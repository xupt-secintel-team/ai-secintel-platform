# -*- coding: utf-8 -*-
"""
评测检索.py —— 检索 / 问答 量化评测（可复跑，用于「改动前 vs 改动后」对比）
================================================================================
用法：
    py -3 tools/评测检索.py                                  # 出报告 + 存基线
    py -3 tools/评测检索.py --tag v1_baseline                # 给这次结果起名
    py -3 tools/评测检索.py --compare 测试报告/检索评测.json  # 和上次比，打差异表
输出：
    测试报告/检索评测.md    人看的报告
    测试报告/检索评测.json  机器可读结果（基线/对比用）

评测口径（**判据与排序算法无关**，不构成自证循环）：
  每题给一个「内容谓词」（如 products 含 vllm、标题匹配正则、exploited 为真、
  id 属于某集合）。只要 top-k 里出现满足谓词的条目就算命中，取最高名次算 RR。
指标：命中率@1/@3/@5/@10、MRR、时延 P50/P95/最大值，并按类别汇总。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
import time
import urllib.parse
import urllib.request

BASE = (os.environ.get("AISEC_EVAL_BASE") or os.environ.get("AISEC_MAIN_SERVER")
        or "http://127.0.0.1:8848")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 本机回环强制不走系统代理（设过 HTTP_PROXY 的机器上会 502，症状像"服务坏了"）
try:
    sys.path.insert(0, os.path.join(ROOT, "core"))
    import loopback
    loopback.enable()
except Exception:  # noqa: BLE001
    pass
OUT_MD = os.path.join(ROOT, "测试报告", "检索评测.md")
OUT_JSON = os.path.join(ROOT, "测试报告", "检索评测.json")
K = 10


# ----------------------------------------------------------------------
# 谓词（判据）：接收一条搜索结果，返回 True/False
# ----------------------------------------------------------------------
def prod(*names):
    names = [n.lower() for n in names]

    def f(r):
        fields = [str(x).lower() for x in (r.get("products") or []) + (r.get("vendors") or [])]
        blob = (str(r.get("title") or "") + " " + str(r.get("desc") or "") + " "
                + " ".join(str(x) for x in (r.get("osv_packages") or []))).lower()
        return any(n in fields or n in blob for n in names)
    return f


def title_re(pattern):
    rx = re.compile(pattern, re.I)

    def f(r):
        return bool(rx.search(str(r.get("title") or "") + " " + str(r.get("desc") or "")))
    return f


def id_in(ids):
    ids = set(ids)

    def f(r):
        return str(r.get("id")) in ids
    return f


def exploited(r):
    return bool(r.get("exploited")) or bool((r.get("kev") or {}).get("dateAdded"))


def src_in(*sources):
    sources = [s.lower() for s in sources]

    def f(r):
        got = [str(x).lower() for x in (r.get("sources") or [r.get("kind") or ""])]
        got += [str(x).lower() for x in (r.get("tags") or [])]
        blob = " ".join(got)
        return any(s in blob for s in sources)
    return f


def cwe_in(*cwes):
    cw = [c.upper() for c in cwes]

    def f(r):
        got = []
        for x in (r.get("cwe") or []):
            got.append(str(x.get("id") if isinstance(x, dict) else x).upper())
        return any(c in got for c in cw)
    return f


def all_of(*preds):
    def f(r):
        return all(p(r) for p in preds)
    return f


def any_of(*preds):
    def f(r):
        return any(p(r) for p in preds)
    return f


# ----------------------------------------------------------------------
# 评测集：40 题，覆盖 AI 组件 / 中文源 / 在野利用 / 跨语言 / 语义改写 / 约束式
# 期望判据里的 CVE / 产品名都先在真实语料里核对过存在
# ----------------------------------------------------------------------
CASES = [
    # —— 一、AI 组件定向（12 题）——
    ("vLLM 推理框架有哪些高危漏洞", "AI组件", prod("vllm")),
    ("Gradio 的高危漏洞", "AI组件", prod("gradio")),
    ("Langflow 平台的漏洞", "AI组件", prod("langflow")),
    ("ComfyUI 安全漏洞", "AI组件", prod("comfyui")),
    ("Jupyter 相关的高危漏洞", "AI组件", any_of(prod("jupyter"), title_re(r"jupyter"))),
    ("Ray 分布式计算框架的漏洞", "AI组件", prod("ray")),
    ("Milvus 向量数据库的严重漏洞", "AI组件", prod("milvus")),
    ("LangChain 框架漏洞", "AI组件", prod("langchain")),
    ("Hugging Face Transformers 的漏洞", "AI组件", any_of(prod("transformers", "huggingface"), title_re(r"transformers|hugging"))),
    ("PyTorch 的漏洞", "AI组件", prod("pytorch")),
    ("Open WebUI 的高危漏洞", "AI组件", prod("open-webui", "open webui", "openwebui")),
    ("NVIDIA Triton 推理服务器的漏洞", "AI组件", prod("triton")),

    # —— 二、语义改写 / 意图式提问（8 题，考语义召回）——
    ("模型会不会被指令绕过、怎么防", "语义改写", title_re(r"提示词注入|prompt\s*inject|越狱|jailbreak|指令注入")),
    ("推理框架被人从外部执行命令", "语义改写", any_of(prod("vllm", "ollama", "triton", "ray"), title_re(r"remote code execution|命令注入|RCE"))),
    ("训练框架反序列化导致的危险", "语义改写", any_of(cwe_in("CWE-502"), title_re(r"deseriali|pickle|反序列化"))),
    ("AI 硬件/驱动层面的漏洞", "语义改写", title_re(r"nvidia|gpu|cuda|driver")),
    ("容器里跑出来的逃逸技术", "语义改写", any_of(title_re(r"容器逃逸|container escape|runc|privileged"), prod("kubernetes", "docker"))),
    ("模型文件被人动了手脚怎么发现", "语义改写", title_re(r"模型|model")),
    ("智能体被诱导调用了危险工具", "语义改写", any_of(title_re(r"agent|智能体|tool use"), prod("langchain", "langflow", "dify"))),
    ("大模型输出被投毒污染", "语义改写", title_re(r"poison|投毒|backdoor|后门")),

    # —— 三、中文源 / 跨语言（8 题）——
    ("提示词注入的攻击原理与防御", "中文源", any_of(src_in("csdn", "先知", "安全客", "csdn 社区文章"), title_re(r"提示词注入"))),
    ("内网渗透与横向移动实战", "中文源", any_of(src_in("csdn", "先知", "安全客"), title_re(r"横向移动|内网"))),
    ("AI 供应链投毒事件复盘", "中文源", any_of(src_in("csdn", "先知", "安全客"), title_re(r"投毒|供应链"))),
    ("Kubernetes 未授权访问漏洞", "中文源", any_of(src_in("csdn", "先知", "安全客"), title_re(r"kubernetes|k8s"))),
    ("如何用大模型做漏洞分析", "中文源", any_of(src_in("csdn", "先知", "安全客"), title_re(r"大模型|LLM"))),
    ("数据安全法的合规要求", "中文源", any_of(title_re(r"数据安全|合规"), src_in("csdn", "数据安全知识库"))),
    ("常见的 webshell 免杀手法", "中文源", any_of(src_in("csdn", "先知", "安全客"), title_re(r"webshell|免杀"))),
    ("CTF 中常见的密码学攻击", "中文源", any_of(src_in("csdn", "先知", "安全客"), title_re(r"CTF|密码学|加密"))),

    # —— 四、在野利用 / 风险优先（6 题）——
    ("最近被在野利用的高危漏洞", "在野利用", exploited),
    ("已被利用的远程代码执行漏洞", "在野利用", all_of(exploited, title_re(r"remote code execution|RCE|命令执行|代码执行"))),
    ("CVSS 10 分的漏洞", "在野利用", title_re(r".")),   # 见下方 special：另用 cvss 判据
    ("正在被勒索软件利用的漏洞", "在野利用", exploited),
    ("影响面很大的网络设备漏洞", "在野利用", any_of(title_re(r"router|firewall|vpn|gateway|设备"), exploited)),
    ("最近修补的在野利用漏洞", "在野利用", exploited),

    # —— 五、约束式查询（6 题，考结构化检索）——
    ("product:ollama cvss>=9", "约束式", prod("ollama")),
    ("cwe:CWE-78 type:漏洞", "约束式", cwe_in("CWE-78")),
    ("kev:yes severity:critical", "约束式", exploited),
    ("cwe:CWE-502 year:>=2025", "约束式", cwe_in("CWE-502")),
    ("product:milvus severity:CRITICAL", "约束式", prod("milvus")),
    ("cwe:CWE-22 sort=trust", "约束式", cwe_in("CWE-22")),
]


def http_json(url, timeout=90, payload=None):
    req = urllib.request.Request(url, method="POST" if payload else "GET")
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req.add_header("Content-Type", "application/json; charset=utf-8")
    with urllib.request.urlopen(req, data=data, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


PATH_ENDPOINTS = {
    "engine": "/api/search",          # 纯关键词（引擎原生，搜索框走这条）
    "hybrid": "/api/hybrid_search",   # 关键词 + 语义召回（模块3 提供）
}
CUR_PATH = "engine"


def search(q, size=K, extra=None, path=None):
    p = {"q": q, "size": size}
    if extra:
        p.update(extra)
    ep = PATH_ENDPOINTS.get(path or CUR_PATH, PATH_ENDPOINTS["engine"])
    return http_json(BASE + ep + "?" + urllib.parse.urlencode(p))


def run_search_eval(path="engine"):
    rows = []
    for q, cat, pred in CASES:
        t0 = time.time()
        try:
            d = search(q, path=path)
            wall = (time.time() - t0) * 1000
            rs = d.get("results") or []
            rank = 0
            for i, r in enumerate(rs[:K], 1):
                # 「CVSS 10 分」这题用专用判据：分数 == 10
                if q == "CVSS 10 分的漏洞":
                    ok = (r.get("cvss") or {}).get("score") == 10.0
                else:
                    ok = bool(pred(r))
                if ok:
                    rank = i
                    break
            rows.append({
                "q": q, "cat": cat, "rank": rank, "hits": len(rs),
                "total": d.get("total"), "server_ms": d.get("elapsed_ms"),
                "wall_ms": round(wall, 1), "path": path,
                "fusion": (d.get("fusion") or {}).get("counts"),
            })
        except Exception as e:  # noqa: BLE001
            rows.append({"q": q, "cat": cat, "rank": 0, "hits": 0, "total": None,
                         "server_ms": None, "wall_ms": None, "path": path,
                         "error": f"{type(e).__name__}: {e}"})
    return rows


CHAT_CASES = [
    ("Ollama 有哪些远程代码执行漏洞？", prod("ollama")),
    ("log4j 的漏洞影响哪些版本？", any_of(title_re(r"log4j|log4shell"), prod("log4j"))),
    ("vLLM 有哪些高危漏洞？", prod("vllm")),
    ("提示词注入怎么防？", title_re(r"提示词注入|prompt\s*inject")),
    ("最近被在野利用的严重漏洞有哪些？", exploited),
    ("Milvus 的严重漏洞有哪些？", prod("milvus")),
    ("LangChain 的漏洞与修复建议", prod("langchain")),
    ("供应链投毒怎么检测？", title_re(r"投毒|供应链|supply chain|poison")),
    ("Gradio 的高危漏洞影响什么版本？", prod("gradio")),
    ("ComfyUI 的漏洞有哪些？", prod("comfyui")),
]


def run_chat_eval(limit=10):
    out = []
    for q, pred in CHAT_CASES[:limit]:
        t0 = time.time()
        try:
            d = http_json(BASE + "/api/chat", payload={"q": q, "no_llm": True, "history": []})
            wall = (time.time() - t0) * 1000
            srcs = d.get("sources") or []
            first_ok = None
            if srcs:
                try:
                    det = http_json(BASE + "/api/detail?id=" + urllib.parse.quote(str(srcs[0].get("id"))))
                    item = det.get("item") or det
                    item.setdefault("id", srcs[0].get("id"))
                    item.setdefault("title", srcs[0].get("title"))
                    first_ok = bool(pred(item))
                except Exception:  # noqa: BLE001
                    first_ok = None
            out.append({"q": q, "n_sources": len(srcs), "first_id": (srcs[0].get("id") if srcs else None),
                        "first_relevant": first_ok, "used_llm": d.get("used_llm"),
                        "wall_ms": round(wall, 1), "answer_chars": len(d.get("answer") or "")})
        except Exception as e:  # noqa: BLE001
            out.append({"q": q, "n_sources": 0, "first_id": None, "first_relevant": None,
                        "wall_ms": None, "error": f"{type(e).__name__}: {e}"})
    return out


def pct(vals, p):
    vals = sorted(v for v in vals if v is not None)
    if not vals:
        return None
    i = min(len(vals) - 1, max(0, int(round((p / 100.0) * (len(vals) - 1)))))
    return round(vals[i], 1)


def summarize(rows):
    n = len(rows)
    hit = {d: sum(1 for r in rows if r["rank"] and r["rank"] <= d) for d in (1, 3, 5, 10)}
    mrr = round(statistics.mean([(1.0 / r["rank"]) if r["rank"] else 0.0 for r in rows]), 3)
    lat = [r.get("wall_ms") for r in rows]
    return {
        "n": n,
        "recall": {f"@{d}": round(hit[d] / n * 100, 1) for d in (1, 3, 5, 10)},
        "mrr": mrr,
        "lat": {"p50": pct(lat, 50), "p95": pct(lat, 95), "max": max([v for v in lat if v is not None], default=None)},
    }


def by_cat(rows):
    out = {}
    for cat in sorted({r["cat"] for r in rows}):
        out[cat] = summarize([r for r in rows if r["cat"] == cat])
    return out


def path_compare_md(engine_rows, hybrid_rows):
    """纯关键词 vs 混合检索（含语义召回）的同题对比表"""
    se, sh = summarize(engine_rows), summarize(hybrid_rows)
    ce, ch = by_cat(engine_rows), by_cat(hybrid_rows)
    L = []
    A = L.append
    A("## 五、纯关键词 vs 混合检索（语义召回）——同一套题、同一套判据")
    A("")
    A("| 范围 | 题量 | 纯关键词 @1 / @3 / @5 / @10 | 混合检索 @1 / @3 / @5 / @10 | @10 变化 | P50（关键词 → 混合） |")
    A("|---|---|---|---|---|---|")

    def line(name, n, a, b, la, lb):
        d = round(b["recall"]["@10"] - a["recall"]["@10"], 1)
        A(f"| {name} | {n} | {a['recall']['@1']}% / {a['recall']['@3']}% / {a['recall']['@5']}% / {a['recall']['@10']}% | "
          f"{b['recall']['@1']}% / {b['recall']['@3']}% / {b['recall']['@5']}% / {b['recall']['@10']}% | "
          f"**{d:+}** | {la} → {lb} ms |")

    line("**全部题目**", se["n"], se, sh, se["lat"]["p50"], sh["lat"]["p50"])
    for cat in ce:
        if cat in ch:
            line(cat, ce[cat]["n"], ce[cat], ch[cat], ce[cat]["lat"]["p50"], ch[cat]["lat"]["p50"])
    A("")
    A(f"- MRR：纯关键词 **{se['mrr']}** → 混合检索 **{sh['mrr']}**")
    A("- 两条路径的差别只在检索层：`/api/search` 是引擎原生关键词检索（搜索框走这条），"
      "`/api/hybrid_search` 是模块3 提供的**关键词 + 语义**融合（问答与语义类提问走这条）。")
    A("- **带强筛选条件的查询（约束式题型）在混合路径上自动跳过语义**，结果与纯关键词一致——"
      "这是刻意的：字段过滤要的是「精确」，不要语义的「泛相关」。")
    A("")
    return "\n".join(L)


def markdown(rows, chat, meta, compare=None, path_rows=None):
    s = summarize(rows)
    cats = by_cat(rows)
    L = []
    A = L.append
    A("# 检索 / 问答 量化评测报告")
    A("")
    A(f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    A(f"- 服务：{BASE}　·　评测题量：检索 {s['n']} 题 / 问答 {len(chat)} 题　·　top-k = {K}")
    A(f"- 语料：文档 **{meta.get('documents')}** 条（NVD 原始记录 {meta.get('records')} 条）· 词项 {meta.get('terms')} · 论文 {meta.get('papers')}")
    A(f"- 原始数据仓库：{meta.get('archive_dir')}（{meta.get('archive_gb')} GB）")
    A(f"- 检索耗时（含网络往返）：P50 **{s['lat']['p50']} ms** · P95 **{s['lat']['p95']} ms** · 最大 {s['lat']['max']} ms")
    A("")
    A("## 一、总体指标")
    A("")
    A("| 指标 | 结果 |")
    A("|---|---|")
    for d in (1, 3, 5, 10):
        A(f"| 命中率 @{d} | **{s['recall'][f'@{d}']}%** |")
    A(f"| MRR（平均倒数排名） | **{s['mrr']}** |")
    A(f"| 时延 P50 / P95 | {s['lat']['p50']} ms / {s['lat']['p95']} ms |")
    A("")
    A("## 二、分类表现")
    A("")
    A("| 类别 | 题量 | @1 | @3 | @5 | @10 | MRR | P50 | P95 |")
    A("|---|---|---|---|---|---|---|---|---|")
    for cat, v in cats.items():
        A(f"| {cat} | {v['n']} | {v['recall']['@1']}% | {v['recall']['@3']}% | "
          f"{v['recall']['@5']}% | {v['recall']['@10']}% | {v['mrr']} | {v['lat']['p50']} | {v['lat']['p95']} |")
    A("")
    A("## 三、逐题明细（检索）")
    A("")
    A("| # | 查询 | 类别 | 命中名次 | 候选数 | 服务端耗时 |")
    A("|---|---|---|---|---|---|")
    for i, r in enumerate(rows, 1):
        rank = r["rank"] or "未命中"
        A(f"| {i} | {r['q']} | {r['cat']} | {rank} | {r.get('hits')} | {r.get('server_ms')} ms |")
    A("")
    A("## 四、问答接口（检索证据模板模式，零 token 成本）")
    A("")
    A("| # | 问题 | 引用条数 | 首条是否相关 | 耗时 | 答案字数 |")
    A("|---|---|---|---|---|---|")
    ok = 0
    for i, c in enumerate(chat, 1):
        rel = {True: "✅ 相关", False: "❌ 不相关", None: "—"}.get(c.get("first_relevant"))
        ok += 1 if c.get("first_relevant") else 0
        A(f"| {i} | {c['q']} | {c.get('n_sources')} | {rel} | {c.get('wall_ms')} ms | {c.get('answer_chars')} |")
    A("")
    if chat:
        A(f"**首条引用相关性：{ok}/{len(chat)} = {round(ok / len(chat) * 100)}%**")
        A("")
    if path_rows:
        A(path_compare_md(rows, path_rows))
    if compare:
        A("## 六、与上次结果对比")
        A("")
        A(f"| 指标 | 上次（{compare.get('tag')}） | 本次（{meta.get('tag')}） | 变化 |")
        A("|---|---|---|---|")
        cs = compare.get("summary") or {}
        for key in ("@1", "@3", "@5", "@10"):
            old = (cs.get("recall") or {}).get(key)
            new = s["recall"][key]
            dlt = "—" if old is None else f"{round(new - old, 1):+}"
            A(f"| 命中率 {key} | {old}% | {new}% | {dlt} |")
        old_m = cs.get("mrr")
        A(f"| MRR | {old_m} | {s['mrr']} | {'—' if old_m is None else round(s['mrr'] - old_m, 3)} |")
        A("")
    A("## 七、口径与局限")
    A("")
    A("- 判据是**内容谓词**（products/vendors 命中、标题正则、exploited 为真、id 属于集合、CWE 命中），")
    A("  与检索引擎的排序算法**无关**，因此不存在「用被测系统给自己判分」的循环。")
    A("- 每题只看 top-10 内是否出现满足谓词的条目；不评估同一谓词下多条结果的排序质量（未做 nDCG）。")
    A("- 无人工标注，谓词由脚本内固定规则给出；换判据会得到不同绝对分数，")
    A("  因此**跨版本对比（同一脚本）比单次绝对分更有意义**。")
    A("- 时间包含 HTTP 往返，故与页面里显示的纯检索耗时略有差异。")
    A("")
    A(APPENDIX)
    return "\n".join(L)


APPENDIX = """## 八、v1 基线未命中诊断（改进项来源）

基线 tag=`v1_baseline` 未命中的 4 题，逐条查了 top-10 里到底出了什么：

| 未命中题 | top-10 实际内容 | 病因 | 归属 |
|---|---|---|---|
| AI 硬件/驱动层面的漏洞 | `endpoint_antivirus` 系列（词面含 "ai"） | **语义漂移**：BM25 把 "AI" 与 "antivirus" 当同一词面，中文"硬件/驱动"没有对应召回 | ① 语义召回 |
| 常见的 webshell 免杀手法 | `antivirus` 系列 CVE | **语义漂移**：「免杀」被拉到词面相近的 antivirus 类目 | ① 语义召回 |
| CVSS 10 分的漏洞 | HF 数据集条目（cvss=None）+ 9.8 分的 Oracle CVE | **数值意图未被解析**：查询里的「10 分」没有转成 `cvss>=9.9` 过滤 | ④ 意图解析（低成本规则） |
| 影响面很大的网络设备漏洞 | `endpoint_antivirus`、Red Hat SSO | **泛化实体无对应召回**：语料里"网络设备"没有专门类目，靠词面抓不住 | ① + 词表/类目扩展 |

另外三项值得记录的量化事实：

1. **强项**：AI 组件定向 12/12 命中（11 题第 1 名）、约束式查询 6/6 第 1 名且 **6~128 ms**（结构化查询自动跳过语义路；此处为该轮实测，基线 v1 是 65~260 ms）、中文源 8/8 命中
   —— 这三类可以直接作为演示主线。
2. **性能尾部风险**：P50 876 ms 偏高，最慢单题 2 642 ms（`PyTorch 的漏洞`，命中 7 104 条的高频词）。
   赛题「性能 5-10 分」要拿分，需要给高频词查询做**候选集收敛 + 结果缓存**。
3. **问答首条引用相关性 9/10**（模板模式，零 token），唯一不相关的是语义类提问——与检索弱项同源。

### 改进优先级（按性价比）

| 优先级 | 改进项 | 预期收益 | 成本 |
|---|---|---|---|
| P0 | ④ 数值/字段意图解析（「CVSS 10 分」「近三个月」「在野利用」→ 结构化过滤） | 直接补上 1~2 题，且演示时"自然语言→结构化过滤"很显眼 | 低（规则） |
| P0 | ② POC/结果精度重排（去掉同关键词的无关仓库） | 提升演示可信度 | 低 |
| P1 | 高频词查询收敛 + 缓存，压 P95 | 性能分 | 低 |
| P1 | ① 本地向量召回（bge 系） | 语义改写类 4~6 题、@1 与 MRR 提升 | 中（CPU 编码时间） |
"""


def main():
    global BASE
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--tag", default=time.strftime("%Y%m%d_%H%M"))
    ap.add_argument("--out", default=OUT_MD)
    ap.add_argument("--json", default=None, help="默认 测试报告/检索评测_<tag>.json，并同步一份最新版")
    ap.add_argument("--compare", default=None)
    ap.add_argument("--chat", type=int, default=10, help="问答评测题量（0=跳过）")
    ap.add_argument("--path", default="both", choices=["engine", "hybrid", "both"],
                    help="检索路径：engine=纯关键词(/api/search)，hybrid=关键词+语义(/api/hybrid_search)，"
                         "both=两条都跑并出对比表（默认）")
    args = ap.parse_args()
    BASE = args.base

    print(f"[评测] 目标服务 {BASE}　tag={args.tag}")
    try:
        st = http_json(BASE + "/api/stats")
        src = http_json(BASE + "/api/sources")
    except Exception as e:  # noqa: BLE001
        print(f"[评测] 服务不可达：{e}")
        return 2
    corpus = src.get("corpus") or {}
    meta = {"tag": args.tag,
            "documents": corpus.get("documents"),
            "terms": corpus.get("terms"),
            "records": (st.get("meta") or {}).get("records"),
            "papers": (st.get("meta") or {}).get("papers"),
            "archive_dir": src.get("archive_dir"),
            "archive_gb": src.get("archive_total_gb")}

    print(f"[评测] 检索题 {len(CASES)} 题 ...（路径：{args.path}）")
    rows = run_search_eval("engine")
    for r in rows:
        print(f"   {'✅' if r['rank'] else '❌'} {r['q'][:34]:36s} 名次={r['rank'] or '-'} "
              f"耗时={r.get('wall_ms')}ms {r.get('error') or ''}")
    s = summarize(rows)
    print(f"[评测] 纯关键词：@1={s['recall']['@1']}% @3={s['recall']['@3']}% "
          f"@5={s['recall']['@5']}% @10={s['recall']['@10']}% MRR={s['mrr']} "
          f"P50={s['lat']['p50']}ms P95={s['lat']['p95']}ms")

    path_rows, path_summary = None, None
    if args.path == "hybrid":
        rows = run_search_eval("hybrid")
        s = summarize(rows)
        print(f"[评测] 混合检索：@1={s['recall']['@1']}% @3={s['recall']['@3']}% "
              f"@5={s['recall']['@5']}% @10={s['recall']['@10']}% MRR={s['mrr']} "
              f"P50={s['lat']['p50']}ms P95={s['lat']['p95']}ms")
    elif args.path == "both":
        print(f"[评测] 混合检索（关键词+语义）{len(CASES)} 题 ...")
        hrows = run_search_eval("hybrid")
        hs = summarize(hrows)
        for r in hrows:
            mark = "✅" if r["rank"] else "❌"
            print(f"   {mark} {r['q'][:34]:36s} 名次={r['rank'] or '-'} 耗时={r.get('wall_ms')}ms "
                  f"融合={r.get('fusion')} {r.get('error') or ''}")
        print(f"[评测] 混合检索：@1={hs['recall']['@1']}% @3={hs['recall']['@3']}% "
              f"@5={hs['recall']['@5']}% @10={hs['recall']['@10']}% MRR={hs['mrr']} "
              f"P50={hs['lat']['p50']}ms P95={hs['lat']['p95']}ms")
        path_rows, path_summary = hrows, hs

    chat = []
    if args.chat:
        print(f"[评测] 问答题 {args.chat} 题（no_llm 模板模式）...")
        chat = run_chat_eval(args.chat)
        okc = sum(1 for c in chat if c.get("first_relevant"))
        print(f"[评测] 问答首条相关性 {okc}/{len(chat)}")

    compare = None
    if args.compare and os.path.exists(args.compare):
        try:
            compare = json.load(open(args.compare, encoding="utf-8"))
            print(f"[评测] 对比基线：{args.compare}（tag={compare.get('tag')}）")
        except Exception as e:  # noqa: BLE001
            print(f"[评测] 基线读取失败：{e}")

    md = markdown(rows, chat, meta, compare, path_rows=path_rows)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(md)
    json_path = args.json or os.path.join(os.path.dirname(OUT_JSON), f"检索评测_{args.tag}.json")
    payload = {"tag": args.tag, "base": BASE, "at": time.strftime("%Y-%m-%d %H:%M:%S"),
               "meta": meta, "summary": s, "by_cat": by_cat(rows),
               "rows": rows, "chat": chat,
               "path": args.path,
               "engine": {"summary": s, "by_cat": by_cat(rows), "rows": rows},
               "hybrid": ({"summary": path_summary, "by_cat": by_cat(path_rows), "rows": path_rows}
                          if path_rows else None)}
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    with open(OUT_JSON, "w", encoding="utf-8") as f:      # 最新一份，便于 --compare 直接用
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"[评测] 报告写入 {args.out}")
    print(f"[评测] 结果写入 {json_path}（并同步 {OUT_JSON}）")
    # 结论一句话
    weak = [k for k, v in by_cat(rows).items() if v["recall"]["@5"] < 80]
    print(f"[评测] 结论：整体 @5={s['recall']['@5']}%，弱项类别：{weak or '无明显弱项'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
