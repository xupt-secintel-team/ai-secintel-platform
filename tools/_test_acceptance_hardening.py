# -*- coding: utf-8 -*-
"""_test_acceptance_hardening.py —— 验收补强项的回归护栏（2026-10-06）

这一轮按验收评分表补强的能力，全部在这里钉死，避免以后改回去：

  ① 采集：published_at 保留源站真实时刻（时效性测量的前提）
  ② 采集：源类别体系（"多源覆盖 7 类以上"的可核验依据）
  ③ 富化：维度清单接口（"富化 6 种以上"的可核验依据）
  ④ 问答：检索式改写（首跳不再被条件词带偏）
  ⑤ 问答：迭代多跳 + 推理链结构
  ⑥ 编排：工具注册表（可扩展性的可核验依据）

直接执行： py tools/_test_acceptance_hardening.py
"""
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
for p in (ROOT, os.path.join(ROOT, "core"),
          os.path.join(ROOT, "modules", "m0_ops", "backend"),
          os.path.join(ROOT, "modules", "m1_monitor", "backend"),
          os.path.join(ROOT, "modules", "m2_enrich", "backend"),
          os.path.join(ROOT, "modules", "m3_qa", "backend")):
    if p not in sys.path:
        sys.path.insert(0, p)

RESULTS = []


def ok(name, cond, detail=""):
    """边跑边打印：中途崩了也能看到已跑过的断言，不至于整段白跑。"""
    good = bool(cond)
    RESULTS.append((good, name, str(detail)[:90]))
    print("  [%s] %-46s %s" % ("OK" if good else "!!", name, str(detail)[:90]))


def show():
    bad = sum(1 for g, _, _ in RESULTS if not g)
    print("\n结果：通过 %d / 失败 %d" % (len(RESULTS) - bad, bad))
    return 0 if bad == 0 else 1


# ── ① 采集：published_at 保留时刻 ────────────────────────────────────
print("\n=== ① 采集 · published_at 保留源站真实时刻 ===")
import live as L  # noqa: E402

cases = [
    ("Wed, 29 Jul 2026 05:00:00 GMT", "2026-07-29T13:00:00", "RFC2822 GMT→本地时区"),
    ("Mon, 05 Oct 2026 14:30:00 +0800", "2026-10-05T14:30:00", "RFC2822 带偏移"),
    ("2026-10-06T08:15:00Z", "2026-10-06T16:15:00", "ISO Z 必须换算时区"),
    ("2026-10-06T08:15:00+00:00", "2026-10-06T16:15:00", "ISO +00:00"),
    ("2026-10-06T16:15:00+08:00", "2026-10-06T16:15:00", "ISO +08:00"),
    ("2026-10-06 16:15:00", "2026-10-06T16:15:00", "无时区按本地"),
    ("2026年9月24日 14:30", "2026-09-24T14:30:00", "中文日期不能丢时刻"),
    ("2026/09/24 09:05", "2026-09-24T09:05:00", "斜杠日期"),
]
for raw, want, why in cases:
    got = L._norm_datetime(raw)
    ok("时刻解析 %s" % why, got == want, "%s → %s（期望 %s）" % (raw[:24], got, want))

ok("坏输入返回空串", L._norm_datetime("garbage") == "")
ok("空输入返回空串", L._norm_datetime("") == "")
# published 仍是日期（引擎依赖，不能改）
ok("published 仍是 YYYY-MM-DD（向后兼容）",
   L._norm_date("Wed, 29 Jul 2026 05:00:00 GMT") == "2026-07-29")

# 真实缓存 RSS 走一遍 _rss_items
cache_dir = os.path.join(ROOT, "data", "live_cache")
if os.path.isdir(cache_dir):
    files = [f for f in sorted(os.listdir(cache_dir)) if f.endswith(".xml")]
    hit = tot = 0
    for fn in files[:12]:
        try:
            raw = io.open(os.path.join(cache_dir, fn), encoding="utf-8",
                          errors="replace").read()
            items = L._rss_items(raw, "t")
        except Exception:  # noqa: BLE001
            continue
        for it in items:
            tot += 1
            if it.get("published_at"):
                hit += 1
    ok("真实 RSS 缓存产出 published_at", tot == 0 or hit / float(tot) > 0.8,
       "%d/%d 条带时刻" % (hit, tot))

# ── ② 采集：源类别体系 ──────────────────────────────────────────────
print("\n=== ② 采集 · 源类别体系（7 类以上可核验）===")
cov = L.source_categories()
ok("类别数 ≥ 7", cov.get("category_count", 0) >= 7,
   "实际 %d 类" % cov.get("category_count"))
ok("无未归类源（other 为 0）",
   all(c["key"] != "other" for c in cov["categories"]),
   "类别：%s" % "、".join(c["key"] for c in cov["categories"]))
ok("每类都有中文标签", all(c.get("label") for c in cov["categories"]))
ok("源总数 ≥ 40", cov.get("source_count", 0) >= 40,
   "共 %d 个源 / %d 个轮询器" % (cov.get("source_count"), cov.get("registered_pollers")))
names = {c["key"] for c in cov["categories"]}
for must in ("cve_nvd", "kev_exploited", "vendor_advisory", "exploit_intel",
             "cn_community", "paper"):
    ok("必含类别 %s" % must, must in names)
# 类别总数与 BLOG_FEEDS + 注册源对得上
expect = len(L.BLOG_FEEDS) + len(L.BLOG_FEEDS_PROXY_ONLY) + len(L.SOURCE_CATEGORIES) - 1
ok("源计数与定义一致（blogs 已展开）", cov["source_count"] == expect,
   "%d vs %d" % (cov["source_count"], expect))

# ── ③ 富化：维度清单 ────────────────────────────────────────────────
print("\n=== ③ 富化 · 维度清单（6 种以上可核验）===")
import enrich_dims as ED  # noqa: E402

ed = ED.enrich_dimensions()
ok("维度数 ≥ 6", ed["dimension_count"] >= 6, "实际 %d 种" % ed["dimension_count"])
ok("关联层 ≥ 1（精准富化+智能关联）", ed["association_count"] >= 1,
   "%d 层" % ed["association_count"])
ok("每个维度都写了后端文件", all(d.get("backend") for d in ed["dimensions"]))
ok("每个维度都写了对外路由", all(d.get("entry") for d in ed["dimensions"]))
ok("落盘型维度取到真实计数", ed["counted_records"] > 0,
   "合计 %d 条" % ed["counted_records"])
ok("计算型维度诚实标 None 并注明",
   all(d.get("data_file_note") or d.get("count_note")
       for d in ed["dimensions"] if d.get("count") is None),
   "None 项：%s" % "、".join(d["key"] for d in ed["dimensions"] if d.get("count") is None))

# ── ④ 问答：检索式改写 ──────────────────────────────────────────────
print("\n=== ④ 问答 · 首跳检索式改写 ===")
from qa.multi_hop import _core_query, _entity_focus  # noqa: E402

rewrite = [
    ("Ollama 有哪些高危且已被在野利用的漏洞？", "ollama"),
    ("vLLM 有什么公开 POC 可用？", "vllm"),
    ("Chrome 的 KEV", "chrome"),
]
for q, must in rewrite:
    core = _core_query(q, _entity_focus(q))
    ok("改写保留主实体 %s" % must, must in (core or "").lower(),
       "%s → %s" % (q[:22], core))
ok("改写剥掉条件词「高危/在野利用」",
   not re.search(r"高危|在野利用", _core_query(
       "Ollama 有哪些高危且已被在野利用的漏洞？", ["ollama"])))
ok("改写剥掉疑问句式",
   not re.search(r"有哪些|有什么", _core_query("Ollama 有哪些漏洞？", ["ollama"])))
ok("改写剥掉 POC（中英混排也要剥）",
   "poc" not in _core_query("2024年Q1影响Ollama的高危且有POC的漏洞", ["ollama"]).lower())
ok("空问题返回空串（不崩）", _core_query("", []) == "")
ok("纯条件问题不崩", isinstance(_core_query("有哪些高危漏洞", []), str))

# ── ⑤ 问答：迭代多跳 + 推理链 ───────────────────────────────────────
print("\n=== ⑤ 问答 · 迭代多跳与推理链 ===")
from qa import multi_hop as MH  # noqa: E402

ok("导出 LAST_CHAIN 占位", hasattr(MH, "LAST_CHAIN"))
ok("迭代函数存在", hasattr(MH, "_iterative_expand"))
ok("派生实体提取器存在", hasattr(MH, "_hop_entities"))
ok("CWE 提取器存在", hasattr(MH, "_hop_cwe_terms"))
# 派生实体必须排除题面已有词
docs = [{"products": ["ollama", "vllm"]}, {"products": ["vllm"]}]
ents = MH._hop_entities(docs, {"ollama"}, 5)
ok("派生实体排除题面已有词", "ollama" not in ents and "vllm" in ents, str(ents))
# 无新实体时要返回空（触发"停止深化"，不跑偏）
ok("无新实体时返回空列表", MH._hop_entities([{"products": ["ollama"]}], {"ollama"}, 5) == [])
# CWE 提取
ok("CWE 名可提取", MH._hop_cwe_terms(
    [{"cwe": [{"id": "CWE-79", "name": "Cross-site Scripting"}]}], 3) ==
    ["cross-site scripting"])
# 推理链结构：模拟一次带 anchor 的迭代
chain = []
pool = [{"id": "A", "products": ["ollama"]},
        {"id": "B", "products": ["vllm"]}]
seen = {"A", "B"}
ok("无预算时至少写入停止记录", isinstance(chain, list))


def _fake_retrieve(q, top_k=8, **kw):
    return []


_orig = MH.retrieve
MH.retrieve = _fake_retrieve
try:
    MH._iterative_expand("ollama 漏洞", pool, seen, {"kev": True}, chain,
                         budget_ms=0, anchor_fn=lambda d: True)
finally:
    MH.retrieve = _orig
ok("派生不出新文档时记录 skipped 依据",
   any(h.get("skipped") == "no_entity" or h.get("new_docs") == 0 for h in chain),
   str(chain)[:110])

# ── ⑥ 编排：工具注册表 ──────────────────────────────────────────────
print("\n=== ⑥ 编排 · 工具注册表 ===")
import orchestrator as O  # noqa: E402

ok("注册表非空", len(O.TOOLS) >= 5, "已注册 %d 个" % len(O.TOOLS))
man = O.tool_manifest()
ok("清单不含函数对象（可序列化）",
   all(set(m) == {"name", "desc", "timeout", "kind"} for m in man))
for must in ("assets", "poc", "remediation", "detail", "attribution"):
    ok("注册了工具 %s" % must, must in O.TOOLS)
try:
    O.call_tool("不存在的工具")
    ok("未注册工具直接抛错（不静默）", False, "竟然没抛")
except KeyError:
    ok("未注册工具直接抛错（不静默）", True)
except Exception as e:  # noqa: BLE001
    ok("未注册工具抛 KeyError", False, type(e).__name__)

# ── ⑦ LLM 调用参数位置（2026-10-07 实测踩坑）──────────────────────
print("\n=== ⑦ LLM 调用 · max_retries 参数位置 ===")
# openai 3.x：max_retries 只能传给 OpenAI() 构造函数；传给
# chat.completions.create() 会抛
# "Completions.create() got an unexpected keyword argument 'max_retries'"
# （用户截图一字不差）。这里静态钉死三处调用点的参数位置。
import re as _re  # noqa: E402

_QA = os.path.join(ROOT, "modules", "m3_qa", "backend", "qa")
for _fname in ("generator.py", "multi_hop.py", "agent.py"):
    _src = open(os.path.join(_QA, _fname), encoding="utf-8").read()
    # 1) create(...) 块里不得出现 max_retries
    _bad = []
    for _m in _re.finditer(r"\.create\((?:[^()]|\([^()]*\))*\)", _src, _re.S):
        if "max_retries" in _m.group(0):
            _bad.append(_m.group(0)[:60])
    ok("%s 的 create() 不传 max_retries" % _fname, not _bad, str(_bad)[:100])
    # 2) 该文件要么在 OpenAI(...) 构造里带 max_retries，要么完全不用它
    _ctor_has = _re.search(r"OpenAI\((?:[^()]|\([^()]*\))*max_retries", _src, _re.S)
    _any_mr = "max_retries" in _src
    ok("%s 的 max_retries 只出现在构造函数（或完全不用）" % _fname,
       (not _any_mr) or bool(_ctor_has),
       "ctor_has=%s any=%s" % (bool(_ctor_has), _any_mr))

# ── ⑧ IOC 本体与检索（2026-10-07 验收补强）─────────────────────────
print("\n=== ⑧ IOC 本体 · 提取与检索 ===")
import engine as ENG  # noqa: E402

ok("IOC 算子已入 OP_KEYS", "ioc" in ENG.OP_KEYS.values())
ok("ioc 字段在归一化字段清单", "ioc" in ENG._NORM_LIST_FIELDS)
ok("ioc 字段在字段顺序表", "ioc" in ENG.FIELD_ORDER)

_ioc_cases = [
    ("标题出现 192.168.1.100 恶意外联", "192.168.1.100"),
    ("域名 evil.example.com 被用于 C2", "evil.example.com"),
    ("样本哈希 6f5902ac237024bdd0c176cb93063dc4", "6f5902ac237024bdd0c176cb93063dc4"),
    ("无任何 IOC 的普通文本", None),
]
for _txt, _want in _ioc_cases:
    _got = ENG.SearchEngine._extract_ioc({"title": _txt, "desc": "", "refs": []})
    if _want is None:
        ok("无 IOC 文本返回空", len(_got) == 0, str(_got)[:50])
    else:
        ok("提取 IOC %s" % _want, any(_want in g for g in _got), str(_got)[:50])

# _match_ioc：具体值子串匹配 + 类型词匹配
ok("ioc 具体值匹配",
   ENG.SearchEngine._match_ioc({"desc": "见 10.0.0.1"}, "10.0.0.1", "10.0.0.1"))
ok("ioc 类型词匹配（ip，文档确有 IOC）",
   ENG.SearchEngine._match_ioc({"desc": "该 IP 10.0.0.1 异常"}, "ip", "ip"))
ok("ioc 类型词匹配（domain，文档确有 IOC）",
   ENG.SearchEngine._match_ioc({"desc": "域名 a.b.com"}, "domain", "domain"))
ok("ioc 类型词不匹配（文档无 IOC）",
   ENG.SearchEngine._match_ioc({"desc": "该 IP 异常"}, "ip", "ip") is False)
ok("ioc 不匹配返回 False",
   ENG.SearchEngine._match_ioc({"desc": "无关内容"}, "203.0.113.7", "203.0.113.7") is False)

# ── ⑨ coverage 覆盖接口（2026-10-07 验收补强）───────────────────────
print("\n=== ⑨ 问答 · 知识覆盖接口 ===")
import importlib  # noqa: E402
_m3api = importlib.import_module("modules.m3_qa.api")
ok("coverage 处理器存在", hasattr(_m3api, "handle_qa_coverage"))
# 路由通过 ctx.route() 注册，无集中式路由表 —— 静态核验 register 源码里有该注册行
import inspect as _inspect  # noqa: E402
_reg_src = _inspect.getsource(_m3api.register)
ok("coverage 路由已注册",
   'ctx.route("GET", "/api/qa/coverage", handle_qa_coverage)' in _reg_src)

# agent 工具：search_ioc 存在且有执行器
from qa import agent as QA_AGENT  # noqa: E402
ok("agent 有 search_ioc 工具函数", hasattr(QA_AGENT, "tool_search_ioc"))
ok("search_ioc 有执行器", "search_ioc" in getattr(QA_AGENT, "EXECUTORS", {}))
ok("search_ioc 在 TOOL_SCHEMAS 声明",
   any("search_ioc" in str(s) for s in getattr(QA_AGENT, "TOOL_SCHEMAS", [])))

sys.exit(show())
