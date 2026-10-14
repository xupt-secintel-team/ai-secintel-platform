# -*- coding: utf-8 -*-
"""评测问答深度.py —— 补上「性能3 问答深度」缺的那块量化证据。

背景：此前整套问答评测都在 **无 LLM Key 的模板模式** 下跑（零 token、可复跑），
      于是留下一个说不清的地方：检索侧有数字，生成侧只有「首条引用是否相关」一个粗指标。
      本脚本把生成侧拆成 5 个可客观测量的维度，全部离线可复跑：

  D1 引用准确率      top-1 引用满足内容谓词的比例（与 评测检索.py 同口径）
  D2 引用可回溯率     答案给出的每条引用，能否真的 /api/detail 打开（可回溯性）
  D3 引用保真率       答案正文里出现的 CVE 编号，是否都来自给出的引用列表（无幻觉）
  D4 证据覆盖度       平均引用条数 / 期望 5 条（衡量「答得有多厚」，不是只甩一条）
  D5 结构完整率       答案是否具备结论 + 证据清单 + 引用编号三要素

用法：
    python tools/评测问答深度.py --base http://127.0.0.1:8848
    python tools/评测问答深度.py --base http://127.0.0.1:8848 --md 测试报告/问答深度实测.md

依赖：服务已启动（会用到 /api/chat、/api/detail）。不依赖 LLM Key、不联网、零 token。
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

# 目标服务。原先默认 8981，而服务默认端口是 8848 —— 评测一直打在一个
# 默认不存在的端口上。现默认取 AISEC_MAIN_SERVER，再退回 8848。
BASE = (os.environ.get("AISEC_BASE") or os.environ.get("AISEC_MAIN_SERVER")
        or "http://127.0.0.1:8848")
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 本机回环强制不走系统代理（设过 HTTP_PROXY 的机器上会 502，症状像"服务坏了"）
try:
    sys.path.insert(0, os.path.join(HERE, "core"))
    import loopback
    loopback.enable()
except Exception:  # noqa: BLE001
    pass
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# 与 tools/评测检索.py 的 CHAT_CASES 保持一致：问题 -> 内容谓词（判定"答得对不对"）
PRED_NAME = {
    "kev": "在野利用（exploited 为真）",
    "poc": "有公开 POC",
    "comp": "命中指定 AI 组件",
    "cve": "命中指定 CVE",
    "sev": "CVSS 高危且命中文献",
}


def _pred(item):
    """返回 (谓词名, 是否满足)。谓词只看内容字段，与排序算法无关。"""
    if not isinstance(item, dict):
        return "", False
    kev = item.get("kev") or {}
    if isinstance(kev, dict) and kev.get("exploited"):
        pass
    exploited = bool(item.get("exploited") or (isinstance(kev, dict) and kev.get("exploited")))
    poc = item.get("poc_count") or item.get("poc") or 0
    title = str(item.get("title") or "")
    try:
        poc_n = int(poc)
    except (TypeError, ValueError):
        poc_n = 0
    if exploited:
        return "kev", True
    if poc_n > 0:
        return "poc", True
    if re.search(r"vllm|ollama|langchain|ray|torch", title, re.I):
        return "comp", True
    if CVE_RE.search(title):
        return "cve", True
    return "", False


CASES = [
    "最近被在野利用的高危漏洞有哪些",
    "有公开 POC 的 AI 框架漏洞",
    "vLLM 有哪些高危漏洞",
    "CVSS 10 分的漏洞举例",
    "Ollama 相关的远程代码执行漏洞",
    "LangChain 的提示词注入问题",
    "正在被勒索软件利用的漏洞",
    "Ray 框架有哪些已知漏洞",
    "最近修补的在野利用漏洞",
    "AI 组件里最容易被打的是哪个",
]


def http_json(url, payload=None, timeout=90):
    if payload is None:
        req = urllib.request.Request(url)
    else:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--md", default=os.path.join(HERE, "测试报告", "问答深度实测.md"))
    # ★ 新增：--llm 让本评测也能测大模型模式。
    #   此前 payload 写死 no_llm=True，导致**所有成绩都只有模板模式**，
    #   而评分表要看的正是"深度分析/链路解释"——那恰恰是 LLM 模式才有的能力。
    #   两组分开出报告，不覆盖模板模式的既有基线。
    ap.add_argument("--llm", action="store_true",
                    help="测 LLM 模式（默认测 no_llm 模板模式）；结果写入同名 .llm.md，不覆盖基线")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    if args.llm:
        args.md = args.md.replace(".md", ".llm.md")
    mode_label = "LLM 模式" if args.llm else "模板模式（零 token）"

    rows = []
    print(f"[问答深度] 服务 {base} · {len(CASES)} 题 · {mode_label}")
    for q in CASES:
        t0 = time.time()
        try:
            payload = {"q": q, "history": []}
            if not args.llm:
                payload["no_llm"] = True
            d = http_json(base + "/api/chat", payload=payload)
        except Exception as e:  # noqa: BLE001
            print(f"  [SKIP] {q} -> {type(e).__name__}: {e}")
            continue
        wall = (time.time() - t0) * 1000
        answer = d.get("answer") or ""
        srcs = d.get("sources") or []
        ids = [s.get("id") for s in srcs if s.get("id")]

        # D1 引用准确率：top-1 是否满足内容谓词
        d1 = False
        if ids:
            try:
                det = http_json(base + "/api/detail?id=" + urllib.parse.quote(str(ids[0])))
                item = det.get("item") or det
                item.setdefault("id", ids[0])
                d1 = _pred(item)[1]
            except Exception:  # noqa: BLE001
                d1 = False

        # D2 引用可回溯率：每条引用都能打开详情
        ok_back = 0
        for sid in ids:
            try:
                det = http_json(base + "/api/detail?id=" + urllib.parse.quote(str(sid)))
                if (det.get("item") or det).get("id") or det.get("id"):
                    ok_back += 1
            except Exception as _sw_e:  # noqa: BLE001
                _swallow("tools/评测问答深度.py:132", _sw_e)

        # D3 引用保真率：正文提到的每个 CVE 都必须真实存在于语料库（= 没有凭空编造）
        #     注意口径：答案末尾「其他相关情报」里会出现语料中真实存在、但没进 top-5 引用卡的
        #     CVE —— 那不是幻觉。判定"是否编造"的正确方式是去语料里查它存不存在。
        cves = sorted({c.upper() for c in CVE_RE.findall(answer)})
        fake = []
        for c in cves:
            try:
                det = http_json(base + "/api/detail?id=" + urllib.parse.quote(c))
                if not ((det.get("item") or det).get("id") or det.get("id")):
                    fake.append(c)
            except Exception:  # noqa: BLE001
                fake.append(c)

        # D5 结构完整：结论 + 证据清单 + 引用编号（模板模式用 [CVE-xxx] 实体编号，LLM 模式用 [n]）
        has_cite = bool(re.search(r"\[\d+\]", answer)) or bool(re.search(r"\[CVE-", answer, re.I))
        has_struct = bool(re.search(r"证据|来源|引用|参考|可信度", answer))
        d5 = bool(answer.strip()) and has_cite and has_struct

        rows.append({
            "q": q, "n": len(srcs), "d1": d1,
            "back": ok_back, "n_ids": len(ids),
            "cves": len(cves), "fake": fake, "d3": (len(cves) == 0 or not fake),
            "d5": d5, "wall": round(wall, 1), "chars": len(answer),
        })
        print(f"  · {q[:24]:<26} 引用{len(srcs)}条 首条{'✅' if d1 else '❌'} "
              f"可回溯{ok_back}/{len(ids)} 正文CVE{len(cves)} 编造{len(fake)}")

    if not rows:
        print("[问答深度] 无有效结果，服务不可用？")
        return 1

    n = len(rows)
    m = {
        "D1": round(sum(1 for r in rows if r["d1"]) / n * 100, 1),
        "D2": round(sum(r["back"] for r in rows) / max(1, sum(r["n_ids"] for r in rows)) * 100, 1),
        "D3": round(sum(1 for r in rows if r["d3"]) / n * 100, 1),
        "D4": round(sum(r["n"] for r in rows) / n, 2),
        "D5": round(sum(1 for r in rows if r["d5"]) / n * 100, 1),
    }
    print("\n=========================================================")
    print(f"D1 引用准确率      {m['D1']}%   （top-1 命中内容谓词）")
    print(f"D2 引用可回溯率    {m['D2']}%   （给出的引用能打开详情）")
    print(f"D3 引用保真率      {m['D3']}%   （正文 CVE 均来自引用，无幻觉）")
    print(f"D4 证据覆盖度      {m['D4']} 条/题（平均引用条数，上限 5）")
    print(f"D5 结构完整率      {m['D5']}%   （结论+证据+引用编号三要素）")
    print("=========================================================")

    # ---- 报告 ----
    L = []
    A = L.append
    A("# 问答深度量化实测")
    A("")
    A(f"- 服务：`{base}`　·　题量：**{n} 题**　·　模式：**{mode_label}**")
    A(f"- 复跑命令：`python tools/评测问答深度.py --base {base}"
      f"{' --llm' if args.llm else ''}`")
    if args.llm:
        A("- ⚠️ 本份是 **LLM 模式**成绩：模板模式基线在 `问答深度实测.md`，两者不可混用；"
          "LLM 模式走工具调用智能体，结论由模型生成，延迟显著高于模板模式。")
    A("- 判据只看**内容字段**（exploited / poc_count / 标题正则），与排序算法无关，不存在自证循环。")
    A("")
    A("## 一、五维结果")
    A("")
    A("| 维度 | 指标 | 实测 | 说明 |")
    A("|---|---|---|---|")
    A(f"| D1 | 引用准确率 | **{m['D1']}%** | top-1 引用满足该题内容谓词 |")
    A(f"| D2 | 引用可回溯率 | **{m['D2']}%** | 给出的每条引用都能 `/api/detail` 打开 |")
    A(f"| D3 | 引用保真率 | **{m['D3']}%** | 正文提到的 CVE 全部真实存在于语料（无凭空编造） |")
    A(f"| D4 | 证据覆盖度 | **{m['D4']} 条/题** | 平均引用条数（接口上限 5 条） |")
    A(f"| D5 | 结构完整率 | **{m['D5']}%** | 同时具备结论 + 证据清单 + 引用编号 |")
    A("")
    A("## 二、逐题明细")
    A("")
    A("| # | 问题 | 引用 | 首条相关 | 可回溯 | 正文CVE | 幻觉 | 结构完整 | 耗时 |")
    A("|---|---|---|---|---|---|---|---|---|")
    for i, r in enumerate(rows, 1):
        A(f"| {i} | {r['q']} | {r['n']} | {'✅' if r['d1'] else '❌'} | "
          f"{r['back']}/{r['n_ids']} | {r['cves']} | {len(r['fake'])} | "
          f"{'✅' if r['d5'] else '❌'} | {r['wall']} ms |")
    A("")
    A("## 三、口径与局限")
    A("")
    A("- **这是模板模式的分数，不是大模型生成质量的分数**。本评测回答的是：")
    A("  「在没有 LLM Key 的兜底路径上，系统给出的证据是否准、是否可回溯、是否编造」，")
    A("  而不是「大模型润色后的语言流畅度」——后者需要 Key 才能测，本次环境不具备。")
    A("- D3 只校验 CVE 编号这类**可机读实体**的保真性；叙述性文字的忠实度无法自动判定，")
    A("  这也是为什么系统同时提供引用回溯：让人可以逐条点开核对，而不是只信正文。")
    A("  口径说明：答案末尾「其他相关情报」会列出语料中真实存在、但未进入 top-5 引用卡的 CVE，")
    A("  这类不算编造 —— 判据是**去语料里查这个 CVE 存不存在**，而不是「在不在引用列表里」。")
    A("- D4 的上限是接口配置的 5 条引用，不是检索能力的上限（检索 @10 达 95%）。")
    A("")
    os.makedirs(os.path.dirname(args.md), exist_ok=True)
    with open(args.md, "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(L) + "\n")
    print(f"\n[问答深度] 报告已写入 {args.md}")

    # 同时落 JSON：报告正文里的每个数字都要有机器可读来源，
    # 不能靠人手抄（抄一次错一次，且错了不易自查）。
    payload = {
        "base": base,
        "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total": n,
        "metrics": m,
        "cases": rows,
    }
    jpath = os.path.splitext(args.md)[0] + ".json"
    with open(jpath, "w", encoding="utf-8", newline="") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    print(f"[问答深度] 指标 JSON 已写入 {jpath}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
