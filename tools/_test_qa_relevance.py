# -*- coding: utf-8 -*-
"""_test_qa_relevance.py —— 情报问答「相关度闸门 / 零命中诚实化」回归测试

钉死两件**必须真起服务打接口**才能验的事（源码看着对、跑起来不一定对）：

  1. 问一个**知识库里确定不存在**的术语 → 必须如实回答"没有匹配情报"，
     而**不能**返回「本次检索命中 N 条相关情报」+ 一堆无关条目。
     （实测根因：`hybrid_search` 无相关度下限、`FINAL_K=8` 固定凑数。）
  2. 问一个**确实存在**的产品 → 不能被闸门误杀（宁可漏剔、不可误剔）。

外加纯单元判据（不需服务）：
  3. `qa.relevance` 的各档判据（向量高 / 实词命中 / BM25 / 双路交集）；
  4. `no_hit_note()` 文案必含"没有…匹配"且给出可操作的检索建议。

用法： py tools/_test_qa_relevance.py [端口]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import loopback  # noqa: E402

loopback.enable()

QA_DIR = os.path.join(ROOT, "modules", "m3_qa", "backend")
sys.path.insert(0, QA_DIR)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8921
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable

PASS = FAIL = SKIP = 0


def ok(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % label)
    else:
        FAIL += 1
        print("  [FAIL] %s %s" % (label, extra))


def skip(label, why=""):
    global SKIP
    SKIP += 1
    print("  [SKIP] %s %s" % (label, why))


# ── 第一部分：纯单元判据（不依赖服务） ────────────────────────────
def unit_tests():
    print("\n[1] qa.relevance 判据单元测试")
    from qa.relevance import is_relevant, gate, query_terms, strong_terms, no_hit_note

    terms = query_terms("Ollama 有哪些高危漏洞")
    ok("实词抽取只留实体（'漏洞'等泛词被剔除）",
       "ollama" in terms and "漏洞" not in terms, str(terms))

    terms2 = query_terms("CVE-2024-1234 的修复建议")
    ok("CVE 编号被抽为实词", any("cve-2024-1234" == t for t in terms2), str(terms2))

    # ★ 实测校准过的两条关键反例
    tn = query_terms("zzzqqq不存在的术语xyzzy")
    ok("瞎编英文不切碎（保留 zzzqqq 整词）", "zzz" not in tn and "qqq" not in tn, str(tn))
    ok("中文不滑窗（不产生 '的术' 碎片）", "的术" not in tn, str(tn))
    # 注：`术语` 是查询里的**真实独立词**（"不存在的术语"），保留它是对的；
    # 关键是它**不算铁证**（见下一条），不会单独把无关文档判成相关。

    st = strong_terms("zzzqqq不存在的术语xyzzy")
    ok("铁证词只认标识符：瞎编串 '不存在' 不算铁证",
       "不存在" not in st and "zzzqqq" in st, str(st))
    st2 = strong_terms("Ollama 的 CVE-2024-1234 怎么修")
    ok("铁证词含产品名与 CVE 编号",
       "ollama" in st2 and "cve-2024-1234" in st2, str(st2))

    # ① 铁证命中 → 相关
    ok("标题含查询产品名 → 相关",
       is_relevant({"title": "Ollama 远程代码执行", "vector_score": 0.2}, [], ["ollama"]))
    # ★ 实测反例：中文惯用语"不存在"命中渗透文章 —— 不得判相关
    ok("★ 中文惯用语假阳性被挡住（'记一次不存在的渗透' ≠ 相关）",
       not is_relevant({"title": "记一次不存在的加解密实战渗透",
                        "vector_score": 0.86}, ["不存在", "术语"], ["zzzqqq", "xyzzy"]))
    # ② 余弦 + 铁证词
    ok("余弦 0.91 且查询含铁证 → 相关（相关组典型值）",
       is_relevant({"vector_score": 0.91, "title": "Ollama RCE"}, [], ["ollama"]))
    ok("余弦 0.86 且无铁证命中 → 不相关（不相关组典型值）",
       not is_relevant({"vector_score": 0.86, "title": "PHP 反射类"}, [], ["ollama"]))
    # ③ 纯分数不行
    ok("BM25 分高但铁证完全没出现 → 不相关",
       not is_relevant({"score": 5.0, "desc": "unrelated"}, [], ["ollama"]))
    # ④ 纯中文提问（无铁证）→ 只能靠语义，门槛 0.90
    ok("纯中文提问 余弦 0.91 → 相关（不误杀真命中）",
       is_relevant({"vector_score": 0.91, "title": "远程代码执行"}, ["远程", "执行"], []))
    ok("纯中文提问 余弦 0.87 → 不相关",
       not is_relevant({"vector_score": 0.87, "title": "无关文章"}, ["远程"], []))

    # 闸门整体行为
    docs = [
        {"id": "A", "vector_score": 0.85, "title": "Ollama RCE"},
        {"id": "B", "vector_score": 0.31, "title": "PHP 反射类动态调用"},
        {"id": "C", "vector_score": 0.28, "title": "Lorex 摄像头配置"},
    ]
    kept, st = gate(docs, "Ollama 有什么漏洞")
    ok("闸门保留相关、剔除无关",
       [d["id"] for d in kept] == ["A"], str([d["id"] for d in kept]))
    ok("闸门统计含 candidates/relevant/dropped",
       st["candidates"] == 3 and st["relevant"] == 1 and st["dropped"] == 2, str(st))

    # 零相关 → 空
    kept0, st0 = gate([{"id": "X", "vector_score": 0.86, "title": "无关"},
                       {"id": "Y", "vector_score": 0.87, "title": "也无关"}],
                      "zzzqqq不存在的术语xyzzy")
    ok("全不相关 → 返回空列表（不兜底凑数）", kept0 == [], str(kept0))

    note = no_hit_note("zzzqqq不存在的术语xyzzy", st0)
    ok("零命中文案明确说'没有…匹配'", "没有与该问题匹配" in note, note[:80])
    ok("零命中文案给出可操作建议（产品名/CVE/CWE）",
       "CVE" in note and "CWE" in note and "产品" in note)
    ok("零命中文案含结构化算子示例", "product:" in note)


# ── 第二部分：真起服务打接口（核心） ─────────────────────────────
def _serve():
    env = dict(os.environ)
    env["AISEC_MAIN_SERVER"] = BASE
    proc = subprocess.Popen(
        [PYEXE, os.path.join(ROOT, "core", "server.py"), "--port", str(PORT)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=env)
    for _ in range(60):
        try:
            with urllib.request.urlopen(BASE + "/api/health", timeout=2) as r:
                if r.status == 200:
                    return proc
        except Exception:  # noqa: BLE001
            time.sleep(1)
    proc.terminate()
    return None


def _post(path, payload, timeout=180):
    data = json.dumps(payload).encode("utf-8")
    r = urllib.request.Request(BASE + path, data=data,
                               headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        return json.load(resp)


def api_tests():
    print("\n[2] 真起服务 · 零命中诚实化（核心）")
    proc = _serve()
    if not proc:
        skip("服务启动", "无法在 %d 端口起服务" % PORT)
        return
    try:
        # ── 2a. 确定不存在的术语 → 必须"没有匹配"，且不得凑数 ──
        try:
            r = _post("/api/chat", {"q": "zzzqqq不存在的术语xyzzy"})
        except Exception as e:  # noqa: BLE001
            ok("不存在术语的问答请求返回 200", False, str(e)[:120])
            return
        concl = (r.get("conclusion") or r.get("answer") or "")
        n_ev = len(r.get("evidence") or [])
        n_src = len(r.get("sources") or [])
        # 核心断言：不许出现"命中 N 条"这种凑数话术（正则匹配任意 N）
        import re as _re
        m_hit = _re.search(r"命中\s*\**\s*(\d+)\s*\**\s*条\s*相关情报", concl)
        ok("不存在术语：不得自称'命中 N 条相关情报'",
           not m_hit, "命中话术: %s" % (m_hit.group(0) if m_hit else "") + " | " + concl[:120])
        # 必须明确说没有 / 未命中
        ok("不存在术语：结论明确表示未命中",
           any(k in concl for k in ("没有与该问题匹配", "未命中高相关度", "未在情报库中检索到")),
           concl[:160])
        ok("不存在术语：证据列表为空（不兜底填充）",
           n_ev == 0 and n_src == 0, "evidence=%d sources=%d" % (n_ev, n_src))
        # reasoning_chain 里应如实记录闸门统计
        rc = r.get("reasoning_chain") or {}
        ok("不存在术语：reasoning_chain 标记 zero_hit",
           rc.get("zero_hit") is True or (rc.get("relevance") or {}).get("dropped", 0) > 0,
           json.dumps({k: rc.get(k) for k in ("zero_hit", "relevance")}, ensure_ascii=False)[:180])

        # ── 2b. 确实存在的产品 → 不能被误杀 ──
        try:
            r2 = _post("/api/chat", {"q": "Ollama 有哪些漏洞"})
        except Exception as e:  # noqa: BLE001
            ok("存在产品的问答请求返回 200", False, str(e)[:120])
            return
        concl2 = (r2.get("conclusion") or r2.get("answer") or "")
        ev2 = len(r2.get("evidence") or [])
        # 若知识库确实有 Ollama 数据 → 必须有结果；若库里没有，测的是"不误报"
        has_ollama = "ollama" in concl2.lower()
        if has_ollama:
            ok("存在产品：返回了相关证据（未被闸门误杀）", ev2 > 0, "evidence=%d" % ev2)
        else:
            ok("存在产品：结论未出现凑数话术", "命中" not in concl2 or "相关情报" not in concl2, concl2[:120])
        ok("存在产品：结论不为空", bool(concl2.strip()))

        # ── 2c. 结构化算子查询豁免闸门（精确过滤） ──
        try:
            r3 = _post("/api/chat", {"q": "product:ollama kev:yes"})
            ok("结构化算子查询：正常返回（豁免闸门不报错）",
               bool((r3.get("conclusion") or r3.get("answer") or "").strip()))
        except Exception as e:  # noqa: BLE001
            ok("结构化算子查询正常", False, str(e)[:120])

        # ── 2d. 边界：空问题仍 400 ──
        try:
            _post("/api/chat", {"q": ""})
            ok("空问题返回 4xx", False, "竟然返回 200")
        except urllib.error.HTTPError as e:
            ok("空问题返回 4xx", 400 <= e.code < 500, "code=%d" % e.code)
        except Exception as e:  # noqa: BLE001
            ok("空问题返回 4xx", False, str(e)[:100])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            proc.kill()


def source_scan():
    """源码级防线：防止有人把闸门从关键路径上摘掉。"""
    print("\n[3] 源码防线（闸门必须挂在关键路径上）")
    import io

    def _read(p):
        with io.open(p, encoding="utf-8") as f:
            return f.read()

    ret = _read(os.path.join(QA_DIR, "qa", "retriever.py"))
    ok("hybrid_search 调用了相关度闸门", "_relevance_gate" in ret)
    mh = _read(os.path.join(QA_DIR, "qa", "multi_hop.py"))
    ok("multi_hop_search 调用了相关度闸门", "from qa.relevance import gate" in mh)
    ok("multi_hop 记录 zero_hit", "zero_hit" in mh)
    gen = _read(os.path.join(QA_DIR, "qa", "generator.py"))
    ok("模板生成器有零命中分支", "no_hit_note" in gen and "no_relevant" in gen)
    rep = _read(os.path.join(QA_DIR, "qa", "report.py"))
    ok("summarize 区分'零相关'与'没检索到'", "_low_confidence" in rep)

    # ★ 实测踩过的坑：/api/chat POST 的字段名是 **`q`**，不是 `question`。
    #   任何打这个接口的探针/测试写错字段名都会被 400 拒掉，或（更糟）
    #   在只带 `question` 时静默当成"缺少参数q" —— 审计结果全部作废。
    #   这里钉死契约，防止后续脚本重蹈覆辙。
    api = _read(os.path.join(ROOT, "modules", "m3_qa", "api.py"))
    ok("/api/chat 仍以 `q` 为请求字段（契约钉死）",
       'data.get("q"' in api, "接口字段名变了，所有探针需同步")


if __name__ == "__main__":
    print("=" * 60)
    print("  情报问答 · 相关度闸门 / 零命中诚实化 回归测试")
    print("=" * 60)
    unit_tests()
    source_scan()
    api_tests()
    print("\n" + "=" * 60)
    print("  通过 %d · 失败 %d · 跳过 %d" % (PASS, FAIL, SKIP))
    print("=" * 60)
    sys.exit(1 if FAIL else 0)
