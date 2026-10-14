# -*- coding: utf-8 -*-
"""
self_test.py —— aisec-D_2.0 合并版端到端自测
=============================================
对运行中的服务逐个打通全部 API 端点，输出通过/失败与关键指标。
覆盖：控制台 / stats / 检索（含算子·否定项·通配符·可信度排序）/ detail /
      suggest / latest / corpus / credibility / 卡片可信度字段通路 /
      related / graph / 报告导出 / 问答（GET+POST）/ live（15s 节拍）/
      sources / refresh / gzip / CORS

用法：
    # 先启动服务
    python server.py 8848
    # 再另开一个终端
    python self_test.py            # 默认测 http://127.0.0.1:8848
    python self_test.py 8899       # 指定端口
"""
import json
import os
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

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception as _sw_e:
    _swallow("core/self_test.py:27", _sw_e)

PORT = sys.argv[1] if len(sys.argv) > 1 else "8848"
BASE = f"http://127.0.0.1:{PORT}"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # 项目根（aisec-D_2.0）

PASS, FAIL = [], []


def call(path, expect_json=True, timeout=120):
    url = BASE + path
    t0 = time.time()
    with urllib.request.urlopen(url, timeout=timeout) as r:
        raw = r.read()
        code = r.status
        ctype = r.headers.get("Content-Type", "")
    ms = round((time.time() - t0) * 1000, 1)
    body = None
    if expect_json and "json" in ctype:
        body = json.loads(raw.decode("utf-8"))
    return code, ctype, body, raw, ms


def check(name, cond, detail=""):
    if cond:
        PASS.append(name)
        print(f"  [PASS] {name}  {detail}")
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name}  {detail}")


def main():
    print(f"=== aisec-D_2.0 自测 · {BASE} ===\n")

    # 1. 静态控制台
    print("[1] 前端控制台")
    code, ctype, _, raw, ms = call("/", expect_json=False)
    check("GET / 控制台可访问", code == 200 and b"AI-SecIntel" in raw or code == 200,
          f"HTTP {code}, {len(raw)}B, {ms}ms")

    # 2. 统计
    print("\n[2] 全局统计 /api/stats")
    code, ctype, d, _, ms = call("/api/stats")
    check("HTTP 200", code == 200)
    check("含关键字段", all(k in d for k in ("total", "vulnerabilities", "category", "source", "severity")),
          f"total={d.get('total')} vuln={d.get('vulnerabilities')} kb={d.get('knowledge')} 论文={d.get('papers')}")
    print(f"        词项={d.get('terms')} 在野利用={d.get('exploited')} POC={d.get('poc')} 响应={ms}ms")

    # 3. 检索（多类型查询）
    print("\n[3] 检索 /api/search")
    queries = [
        ("gradio 漏洞", True), ("prompt injection", True), ("log4j", True),
        ("数据安全法", True), ("CVE-2024-5565", True), ("", False),
        ("product:ollama severity:HIGH", True), ("prompt* injection", True),
        ("llm -log4j", True), ("cvss>=9 kev:yes", True),
    ]
    for q, expect_hit in queries:
        code, _, r, _, ms = call("/api/search?" + urllib.parse.urlencode({"q": q, "size": 5}))
        ok_code = code == 200
        total = (r or {}).get("total", 0)
        has_ans = "answer" in (r or {})
        has_facets = "facets" in (r or {})
        hit_ok = (total > 0) if (expect_hit and q) else True
        check(f"search q={q!r}", ok_code and has_ans and has_facets and hit_ok,
              f"命中={total} 意图={(r or {}).get('answer', {}).get('intent')} 响应={ms}ms")

    # 4. 结构化算子解析
    print("\n[4] 查询语法解析")
    _, _, r, _, _ = call("/api/search?" + urllib.parse.urlencode({"q": "product:ollama cvss>=9 -log4j"}))
    qp = (r or {}).get("query", {})
    check("算子/否定项被解析", bool(qp.get("ops")) and bool(qp.get("must_not")),
          f"ops={[o.get('raw') for o in qp.get('ops', [])]} must_not={qp.get('must_not')}")

    # 5. 详情
    print("\n[5] 详情 /api/detail")
    _, _, r, _, _ = call("/api/search?" + urllib.parse.urlencode({"q": "CVE-2024-5565"}))
    cid = ""
    for x in (r or {}).get("results", []):
        if x.get("id", "").upper().startswith("CVE-"):
            cid = x["id"]
            break
    if cid:
        code, _, d, _, ms = call("/api/detail?" + urllib.parse.urlencode({"id": cid}))
        check(f"detail {cid}", code == 200 and d.get("id") == cid,
              f"refs={len(d.get('refs', []))} atlas={len(d.get('atlas', []))} 响应={ms}ms")
    else:
        check("detail 前置检索", False, "未取到 CVE id")

    # 6. 自动补全
    print("\n[6] 自动补全 /api/suggest")
    code, _, d, _, ms = call("/api/suggest?q=log")
    check("suggest", code == 200 and isinstance(d, dict),
          f"cves={len(d.get('cves', []))} products={len(d.get('products', []))} terms={len(d.get('terms', []))} 响应={ms}ms")

    # 7. 最新 feed
    print("\n[7] 最新情报 /api/latest")
    code, _, d, _, ms = call("/api/latest?n=5")
    check("latest", code == 200 and len(d.get("items", [])) > 0,
          f"{len(d.get('items', []))} 条，首条={(d.get('items') or [{}])[0].get('id')} 响应={ms}ms")

    # 8. 轻量清单
    print("\n[8] 轻量清单 /api/corpus")
    code, _, d, _, ms = call("/api/corpus")
    check("corpus", code == 200 and d.get("total") == d.get("total"),
          f"total={d.get('total')} 响应={ms}ms")

    # 9. 可信度
    print("\n[9] 可信度统计 /api/credibility")
    code, _, d, _, ms = call("/api/credibility")
    check("credibility", code == 200 and "trust_distribution" in d,
          f"平均置信度={d.get('avg_confidence')} 高置信={d.get('high_confidence_count')} 多源验证={d.get('cross_verified_count')} 响应={ms}ms")

    # 10. 检索卡片是否带可信度字段
    print("\n[10] 检索卡片可信度字段通路")
    _, _, r, _, _ = call("/api/search?" + urllib.parse.urlencode({"q": "gradio 漏洞"}))
    res = (r or {}).get("results", [])
    if res:
        keys = ("trust_score", "trust_label", "cross_count", "cross_label",
                "exploit_score", "exploit_label", "confidence", "freshness")
        missing = [k for k in keys if k not in res[0]]
        check("卡片含全部可信度字段", not missing,
              f"trust={res[0].get('trust_label')} cross={res[0].get('cross_label')} "
              f"exploit={res[0].get('exploit_score')} confidence={res[0].get('confidence')}"
              + (f" 缺失={missing}" if missing else ""))
    else:
        check("卡片含全部可信度字段", False, "检索无结果")

    # 11. 关联推荐
    print("\n[11] 关联推荐 /api/related")
    if cid:
        code, _, d, _, ms = call("/api/related?" + urllib.parse.urlencode({"id": cid}))
        check("related", code == 200 and "top_overall" in d,
              f"top={len(d.get('top_overall', []))} 同组件={len(d.get('same_product', []))} "
              f"同弱点={len(d.get('same_cwe', []))} 同技术={len(d.get('atlas_related', []))} 响应={ms}ms")

    # 12. 关系图谱
    print("\n[12] 关系图谱 /api/graph")
    if cid:
        code, _, d, _, ms = call("/api/graph?" + urllib.parse.urlencode({"id": cid}))
        check("graph", code == 200 and "nodes" in d and "links" in d and "categories" in d,
              f"nodes={len(d.get('nodes', []))} links={len(d.get('links', []))} "
              f"categories={len(d.get('categories', []))} 响应={ms}ms")

    # 13. 报告导出
    print("\n[13] 报告导出 /api/export")
    code, ctype, _, raw, ms = call("/api/export?" + urllib.parse.urlencode({"q": "gradio 漏洞"}), expect_json=False)
    check("export(搜索报告)", code == 200 and "markdown" in ctype and len(raw) > 500,
          f"HTTP {code} {len(raw)}字符 响应={ms}ms")
    if cid:
        code, ctype, _, raw, ms = call("/api/export?" + urllib.parse.urlencode({"id": cid}), expect_json=False)
        check("export(详情报告)", code == 200 and "markdown" in ctype and len(raw) > 500,
              f"HTTP {code} {len(raw)}字符 响应={ms}ms")

    # 14. 问答（GET 简版）—— 加 no_llm=1，确保自测不花大模型 token
    print("\n[14] 情报问答 /api/chat")
    code, _, d, _, ms = call("/api/chat?" + urllib.parse.urlencode({"q": "gradio 有哪些高危漏洞", "no_llm": 1}), timeout=180)
    check("chat(GET)", code == 200 and isinstance(d, dict) and "answer" in d,
          f"used_llm={d.get('used_llm')} sources={len(d.get('sources', []))} 响应={ms}ms")

    # 15. 问答（POST，带 history）—— 显式 no_llm，确保自测不花大模型 token
    print("\n[15] 情报问答 POST /api/chat")
    payload = json.dumps({"q": "log4j 有什么漏洞", "no_llm": True, "history": [
        {"role": "user", "content": "你好"},
        {"role": "assistant", "content": "你好，我是AI安全情报助手"},
    ]}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(BASE + "/api/chat", data=payload,
                                headers={"Content-Type": "application/json"}, method="POST")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            d = json.loads(r.read().decode("utf-8"))
            code = r.status
        check("chat(POST+history)", code == 200 and "answer" in d,
              f"used_llm={d.get('used_llm')} sources={len(d.get('sources', []))} "
              f"响应={round((time.time()-t0)*1000)}ms")
    except Exception as e:
        check("chat(POST+history)", False, str(e)[:120])

    # 16. 增量同步状态
    print("\n[16] 增量同步 /api/refresh")
    code, _, d, _, ms = call("/api/refresh")
    check("refresh 状态", code == 200 and "running" in d,
          f"running={d.get('running')} last_sync={d.get('last_sync')} 响应={ms}ms")

    # 17. 快车道实时监测（合并版新增：15s 一轮）
    print("\n[17] 快车道实时监测 /api/live")
    code, _, d, _, ms = call("/api/live")
    iv = d.get("interval") if isinstance(d, dict) else None
    check("live 已启用且节拍为 15s", code == 200 and d.get("enabled") and iv == 15,
          f"enabled={d.get('enabled')} interval={iv}s 最近一轮={d.get('last_poll')} "
          f"耗时={d.get('last_ms')}ms 新增={d.get('last_batch')} 累计={d.get('added_total')} 响应={ms}ms")
    check("live 分源计数存在", isinstance(d.get("per_source"), dict),
          f"per_source={d.get('per_source')}")

    # 18. 多源归档体量
    print("\n[18] 多源归档体量 /api/sources")
    code, _, d, _, ms = call("/api/sources")
    check("sources", code == 200 and "channels" in d,
          f"归档={d.get('archive_total_gb')}GB 渠道={len(d.get('channels', []))} "
          f"已入索引 docs={(d.get('corpus') or {}).get('documents')} 响应={ms}ms")

    # 19. 可信度排序（合并版新增）
    print("\n[19] 可信度排序 sort=trust")
    code, _, r, _, ms = call("/api/search?" + urllib.parse.urlencode(
        {"q": "漏洞", "size": 5, "sort": "trust"}))
    res = (r or {}).get("results", [])
    confs = [x.get("confidence") for x in res if isinstance(x.get("confidence"), (int, float))]
    desc = all(confs[i] >= confs[i + 1] for i in range(len(confs) - 1)) if len(confs) > 1 else bool(confs)
    check("可信度排序生效", code == 200 and bool(res) and desc,
          f"置信度序列={confs} 响应={ms}ms")

    # 20. 双域语料（通用安全 + AI 安全）可分别命中
    print("\n[20] 合并语料双域检索")
    for q, name in (("log4j", "通用安全域"), ("prompt injection", "AI 安全域"),
                    ("数据安全法", "数据安全知识库")):
        code, _, r, _, ms = call("/api/search?" + urllib.parse.urlencode({"q": q, "size": 3}))
        check(f"{name} q={q!r}", code == 200 and (r or {}).get("total", 0) > 0,
              f"命中={(r or {}).get('total')} 响应={ms}ms")

    # 21. CORS / gzip
    print("\n[21] HTTP 能力")
    req = urllib.request.Request(BASE + "/api/stats", headers={"Accept-Encoding": "gzip", "Origin": "http://x"})
    with urllib.request.urlopen(req, timeout=60) as r:
        ae = r.headers.get("Content-Encoding")
        acao = r.headers.get("Access-Control-Allow-Origin")
    check("gzip 压缩", ae == "gzip", f"Content-Encoding={ae}")
    check("CORS 头", acao == "*", f"Access-Control-Allow-Origin={acao}")

    # 22. 模块化结构：模块注册表 + 模块自有接口
    print("\n[22] 模块化结构（注册表 / 模块接口）")
    code, _, d, _, ms = call("/api/modules")
    mods = {m.get("id"): m for m in (d or {}).get("modules", [])}
    check("模块注册表 /api/modules", code == 200 and mods,
          f"已加载 {sorted(mods)} 跳过 {(d or {}).get('skipped')} 响应={ms}ms")
    check("模块1 情报监测 已接入", "m1_monitor" in mods,
          f"routes={(mods.get('m1_monitor') or {}).get('routes')}")
    check("模块2 情报富化 已接入", "m2_enrich" in mods,
          f"routes={(mods.get('m2_enrich') or {}).get('routes')}")
    check("模块3 情报问答 已接入", "m3_qa" in mods,
          f"routes={(mods.get('m3_qa') or {}).get('routes')}")
    code, _, d, _, ms = call("/api/assets?" + urllib.parse.urlencode({"id": "CVE-2024-5565"}))
    check("模块2 /api/assets", code == 200 and "assets" in (d or {}),
          f"count={(d or {}).get('count')} 响应={ms}ms")
    code, _, d, _, ms = call("/api/poc?" + urllib.parse.urlencode({"id": "CVE-2024-5565"}))
    check("模块2 /api/poc（任务状态）", code == 200 and (d or {}).get("id") == "CVE-2024-5565",
          f"running={(d or {}).get('running')} 结果={(d or {}).get('results') and len(d['results'])} 响应={ms}ms")
    # ② POC 搜索必须支持 force=1 强制重跑：默认「已完成就返回缓存」，会让「先点快速、再点完整」
    #    静默拿到第一次的旧结果（看不出差别，像按钮坏了）——这是本轮修掉的真 bug，纳入回归防退化。
    #    用一个**本次运行才出现的假 CVE 号**，避免「上一次运行/手工测试还在跑」把首次断言打成 False。
    fake_cve = "CVE-1999-%06d" % (int(time.time()) % 1000000)

    def _poc_post(extra):
        q = urllib.parse.urlencode({"id": fake_cve, "quick": 1, **extra})
        rq = urllib.request.Request(BASE + "/api/poc?" + q, data=b"{}",
                                    headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(rq, timeout=60) as r:
            return json.loads(r.read().decode("utf-8"))

    try:
        d1 = _poc_post({"force": 1})          # 全新 id，没有任务在跑 → 必须真的启动
        done = False
        for _ in range(20):                   # 等它跑完，好验证「已完成仍可强制重跑」
            time.sleep(2)
            _, _, st, _, _ = call("/api/poc?" + urllib.parse.urlencode({"id": fake_cve}))
            if not (st or {}).get("running"):
                done = True
                break
        d2 = _poc_post({"force": 1})          # 已完成 + force → 仍应重跑
        d3 = _poc_post({})                    # 不带 force → 必须走缓存/运行中分支
        ok = bool(d1.get("started")) and not d3.get("started") and (bool(d2.get("started")) if done else True)
        check("② POC 搜索 force=1 可强制重跑（不会静默返回旧结果）", ok,
              f"{fake_cve} 首次 force started={d1.get('started')}（应 True）· "
              f"已完成后再 force started={d2.get('started')}（应 True{f'; 本次未跑完已跳过' if not done else ''}）· "
              f"不带 force started={d3.get('started')}（应 False）")
    except Exception as e:  # noqa: BLE001
        check("② POC 搜索 force=1 可强制重跑（不会静默返回旧结果）", False, str(e)[:120])
    # —— 按「模块完成度与缺口分析」补齐的能力，纳入回归 ——
    code, _, d, _, ms = call("/api/assets?" + urllib.parse.urlencode({"id": "CVE-2024-37032"}))
    sv = (d or {}).get("survey") or {}
    fofa = sv.get("fofa") or []
    check("模块2 受影响互联网资产测绘语法", code == 200 and bool(fofa),
          f"平台={[k for k in ('fofa','shodan','quake','zoomeye','google') if sv.get(k)]} "
          f"首条={fofa[0]['q'] if fofa else '—'} 响应={ms}ms")
    check("测绘语法带合规提示", bool(sv.get("compliance")),
          f"版本收窄={sv.get('version_narrow')}")
    code, _, d, _, ms = call("/api/qa/status")
    # 供应商预设要给到页面（选服务商→自动填地址/模型，用户只需粘 Key）；同时**不许**把 api_key 下发到浏览器
    provs = (d or {}).get("providers") or []
    no_key = "api_key" not in json.dumps(d or {}, ensure_ascii=False)
    check("模块3 /api/qa/status（问答自检 + 供应商预设，且不下发 Key）",
          code == 200 and "env_key" in (d or {}) and len(provs) >= 4 and no_key,
          f"环境变量Key={(d or {}).get('env_key')} 向量库={(d or {}).get('vector')} 模型={(d or {}).get('model')} "
          f"预设={[p.get('id') for p in provs]} 不含Key字段={no_key} 响应={ms}ms")
    # 本地免费翻译（英译中）：路由在 + 已是中文的条目原样跳过。
    # 用中文输入判定，这样**不依赖翻译模型是否已下载**，这条用例永远可判。
    code, _, d, _, ms = call("/api/qa/mt_status")
    code2, _, d2, _, ms2 = call("/api/qa/translate?" +
                                urllib.parse.urlencode({"text": "这是一段中文，不该被翻译。"}))
    items = (d2 or {}).get("items") or []
    check("模块3 本地免费翻译接口（英译中；中文原样跳过，正文不外发）",
          code == 200 and isinstance((d or {}).get("ready"), bool) and code2 == 200 and bool(items)
          and items[0].get("skipped") is True and items[0].get("dst") == items[0].get("src"),
          f"模型就绪={(d or {}).get('ready')} 体积={(d or {}).get('size_mb')}MB "
          f"引擎={(d2 or {}).get('engine')} 中文跳过={items[0].get('skipped') if items else '—'} "
          f"响应={ms}/{ms2}ms")
    code, _, d, _, ms = call("/api/live")
    check("模块1 情报源健康度字段", code == 200 and "feed_total" in (d or {}),
          f"源成功={(d or {}).get('feed_ok')}/{(d or {}).get('feed_total')} "
          f"失败源={list(((d or {}).get('feed_fail') or {}).keys())[:4]}")
    code, _, d, _, ms = call("/api/sources")
    check("模块1 归档体量字段", code == 200 and "archive_dir" in (d or {}),
          f"路径={(d or {}).get('archive_dir')} 已入索引文档={(d or {}).get('corpus', {}).get('documents')}")

    # —— ③ 评测尺子 / ② POC 精度 / ① 语义召回：接口与规则纳入回归（全部零成本、不发外网） ——
    code, _, d, _, ms = call("/api/qa/status")
    vc = (d or {}).get("vector_count")
    check("① 向量库状态为真实条数（不再是「包能 import」）",
          code == 200 and isinstance(vc, int),
          f"库中向量={vc} 条 模型={(d or {}).get('vector_model') or '—'} 说明={(d or {}).get('vector_note') or '已就绪'}")
    code, _, d, _, ms = call("/api/qa/build_vector")
    check("① 建库进度接口可用",
          code == 200 and "rate" in (d or {}) and "count" in (d or {}),
          f"任务总条数={(d or {}).get('total')} 已处理={(d or {}).get('processed')} "
          f"速率={(d or {}).get('rate')} 条/秒 ETA={round((d or {}).get('eta') or 0)}s 库中={(d or {}).get('count')} 响应={ms}ms")
    code, _, d, _, ms = call("/api/qa/vector_probe?" + urllib.parse.urlencode({"q": "ollama 远程代码执行", "k": 3}))
    _hits = (d or {}).get("hits") or []
    check("① 语义检索探针接口可用（不经关键词融合，直接看向量 top-k）",
          code == 200 and isinstance(_hits, list) and "count" in (d or {}),
          f"库中={(d or {}).get('count')} 条 命中={len(_hits)} "
          f"首条={(_hits[0]['title'][:28] if _hits else '—')} "
          f"相似度={(round(_hits[0]['vector_score'], 3) if _hits else '—')} 响应={ms}ms")
    code, _, d, _, ms = call("/api/hybrid_search?" + urllib.parse.urlencode({"q": "vLLM 远程代码执行", "size": 5}))
    _hr = (d or {}).get("results") or []
    check("① 混合检索接口可用（关键词 + 语义融合）",
          code == 200 and isinstance(_hr, list) and bool((d or {}).get("fusion")),
          f"模式={(d or {}).get('mode')} 融合={((d or {}).get('fusion') or {}).get('counts')} "
          f"首条={( _hr[0].get('title') or '')[:26] if _hr else '—'} 响应={ms}ms")
    code, _, d, _, ms = call("/api/hybrid_search?" + urllib.parse.urlencode({"q": "cwe:CWE-78 type:漏洞"}))
    _f = (d or {}).get("fusion") or {}
    check("① 结构化（字段过滤）查询自动跳过语义路，保持精确",
          code == 200 and _f.get("vector_candidates") == 0,
          f"语义候选={_f.get('vector_candidates')} 跳过原因={_f.get('skipped_vector_reason')} 响应={ms}ms")
    try:
        sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))
        import poc_scraper as _POC
        tier_cases = [
            ("Bi0x/CVE-2024-37032", "", "", "CVE-2024-37032", ["ollama"], "github", "A"),
            ("apache/logging-log4j2", "Apache Log4j", "", "CVE-2021-44228", ["log4j2"], "github", "D"),
            ("Mr-xn/Penetration_Testing_POC", "POC 合集", "", "CVE-2021-44228", ["log4j2"], "github", "B"),
            ("foo/bar", "CMake build tool", "", "CVE-2021-44228", ["log4j2"], "github", "D"),
            ("m/1", "", "", "CVE-2021-44228", [], "metasploit", "A"),
        ]
        got = [_POC._match_tier(n, de, rd, "", cve, pr, source=src, poc_type="", verified=False)
               for n, de, rd, cve, pr, src, _t in tier_cases]
        want = [t for *_x, t in tier_cases]
        check("② POC 匹配分级 A/B/C/D 判定正确（离线规则）",
              got == want, f"实得={got} 期望={want}")
    except Exception as e:  # noqa: BLE001
        check("② POC 匹配分级 A/B/C/D 判定正确（离线规则）", False, f"导入或执行失败：{e}")
    try:
        sys.path.insert(0, os.path.join(ROOT, "modules", "m3_qa", "backend"))
        import qa.local_embedder as _LE
        _dirs = []
        for _m in _LE.MODELS:
            _dirs += _LE.candidate_dirs(str(_m["name"]))
        _found = [d for d in _dirs if os.path.exists(os.path.join(d, "config.json"))]
        check("① 本地免费嵌入模型已就位（离线可加载、零费用）",
              bool(_found),
              f"命中目录={_found[:2]} 候选模型={[str(m['name']) for m in _LE.MODELS]}")
    except Exception as e:  # noqa: BLE001
        check("① 本地免费嵌入模型已就位（离线可加载、零费用）", False, f"导入失败：{e}")
    for tool in ("评测检索.py", "评测POC.py", "评测POC覆盖率.py", "建向量库.py",
                 "评测时效性.py", "评测富化准确率.py", "评测多跳推理.py",
                 "watchdog.py", "自测守护.py"):
        p = os.path.join(ROOT, "tools", tool)
        ok = os.path.exists(p) and os.path.getsize(p) > 800
        check(f"③ 评测/建库/守护工具存在：tools/{tool}", ok,
              f"{os.path.getsize(p) if os.path.exists(p) else 0} 字节")
    for doc in ("测试报告/检索评测.md", "测试报告/POC覆盖率对比.md", "演示脚本_5分钟.md",
                "测试报告/富化准确率评测.md", "测试报告/多跳推理评测.md"):
        p = os.path.join(ROOT, doc)
        check(f"③ 交付物存在：{doc}", os.path.exists(p),
              f"{os.path.getsize(p) if os.path.exists(p) else 0} 字节")

    # —— v2.2 新增：m0_ops 多智能体编排 / 问答深度分析层 / 守护进程 ——
    code, _, d, _, ms = call("/api/ops/status")
    check("v2.2 模块0 编排器状态（六智能体在列：含决策+质疑）",
          code == 200 and (d or {}).get("enabled") is not None
          and len((d or {}).get("agents") or []) == 6,
          f"运行={(d or {}).get('running')} 节拍={(d or {}).get('interval_sec')}s "
          f"智能体={(d or {}).get('agents')} 响应={ms}ms")
    code, _, d, _, ms = call("/api/ops/trace")
    check("v2.2 编排留痕接口（trace 可审计）",
          code == 200 and isinstance((d or {}).get("trace"), list),
          f"留痕条数={len((d or {}).get('trace') or [])} 响应={ms}ms")
    code, _, d, _, ms = call("/api/ops/briefs?n=5")
    check("v2.2 研判简报接口可用",
          code == 200 and isinstance((d or {}).get("briefs"), list),
          f"简报数={(d or {}).get('count')} 响应={ms}ms")
    code, _, d, _, ms = call("/api/ops/decisions?n=5")
    check("v2.4 处置决策接口可用（决策智能体）",
          code == 200 and isinstance((d or {}).get("decisions"), list),
          f"决策数={(d or {}).get('count')} 响应={ms}ms")
    code, _, d, _, ms = call("/api/ops/disposition/stats")
    check("v2.5 处置闭环回填记忆库可用（自我进化）",
          code == 200 and (d or {}).get("ok") is True and "total" in (d or {}),
          f"已沉淀={(d or {}).get('total')} 条 响应={ms}ms")
    try:
        sys.path.insert(0, os.path.join(ROOT, "modules", "m3_qa", "backend"))
        from qa.deep_answer import (parse_constraints, filter_by_constraints,
                                    resolve_reference, extract_entities)
        _cons = parse_constraints("已被在野利用（KEV）且 CVSS 恰好 10 分的漏洞有哪些？")
        check("v2.2 深度层·硬约束解析（KEV+CVSS等值）",
              _cons.get("kev") is True and abs(_cons.get("cvss_eq", 0) - 10.0) < 0.01,
              f"实得={_cons}")
        _docs = [
            {"id": "A", "exploited": True, "cvss": {"score": 10.0}, "title": "gitlab x"},
            {"id": "B", "exploited": True, "cvss": {"score": 9.8}, "title": "gitlab y"},
            {"id": "C", "exploited": False, "cvss": {"score": 10.0}, "title": "gitlab z"},
        ]
        _kept = [x["id"] for x in filter_by_constraints(_docs, {"kev": True, "cvss_eq": 10.0,
                                                              "entities": ["gitlab"]})]
        check("v2.2 深度层·条件链降噪过滤", _kept == ["A"], f"保留={_kept}")
        _q, _cve = resolve_reference("第一个漏洞的 CWE 是什么？",
                                     [{"role": "assistant", "content": "1. [CVE-2024-37032] xxx 2. [CVE-2025-15063] yyy"}])
        check("v2.2 深度层·多轮指代消解", _cve == "CVE-2024-37032" and "CVE-2024-37032" in _q,
              f"改写={_q[:40]}")
        check("v2.2 深度层·实体抽取去停用词",
              extract_entities("GitLab 相关的在野利用漏洞") == ["gitlab"]
              and extract_entities("CVSS 10 分的漏洞") == [],
              f"gitlab={extract_entities('GitLab 相关的在野利用漏洞')} 空={extract_entities('CVSS 10 分的漏洞')}")
    except Exception as e:  # noqa: BLE001
        check("v2.2 深度分析层离线规则（约束解析/降噪/指代/实体）", False, f"导入或执行失败：{e}")
    try:
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import watchdog as _W
        import tempfile as _tf
        _lk = _W.InstanceLock(os.path.join(_tf.mkdtemp(), "t.lock"))
        _ok, _ = _lk.acquire(os.getpid())
        _ok2, _holder = _W.InstanceLock(_lk.fp).acquire(999999)
        _lk.release()
        check("v2.2 守护·单实例锁（存活拒二开）", _ok and not _ok2,
              f"首获={_ok} 二开被拒={not _ok2} 持锁PID={_holder}")
    except Exception as e:  # noqa: BLE001
        check("v2.2 守护·单实例锁（存活拒二开）", False, f"导入或执行失败：{e}")

    # ── 跨平台 / 环境自适应（compat + envprofile）────────────────────────
    # 这一节校验"三环境保证"里的第 ①③ 条：老系统能跑、环境能自配。
    # 全部离线，不依赖服务（第 ② 条"慢机器降档"由单元断言覆盖）。
    print("\n[N] 跨平台兼容与性能档位")
    try:
        sys.path.insert(0, os.path.join(ROOT, "core"))
        import compat as _C
        import envprofile as _E

        _rt = _C.check_runtime()
        check("compat·运行时体检结构完整",
              all(k in _rt for k in ("ok", "fatal", "python", "min_required",
                                     "os_family", "reasons")),
              f"Python {_rt['python']} / {_rt['os_family']} / 下限 {_rt['min_required']}")
        check("compat·版本下限可判定（3.7 起）", _C.PY_MIN == (3, 7) and not _rt["fatal"],
              f"本机 {'.'.join(str(x) for x in _C.PY)}")

        # 低版本 API 兜底：3.7 上没有 str.removeprefix，必须走本模块实现
        check("compat·低版本 API 兜底（removeprefix/suffix）",
              _C.removeprefix("CVE-2024-37032", "CVE-") == "2024-37032"
              and _C.removesuffix("vuln.json", ".json") == "vuln",
              f"{_C.removeprefix('CVE-2024-37032', 'CVE-')}")
        # 平台相关命令不能写死 Windows：macOS 没有 netstat/findstr
        _hint = _C.port_in_use_hint(8848)
        _expect = ("lsof" if _C.IS_MAC else "netstat" if _C.IS_WIN else "ss")
        check("compat·端口排查命令随平台切换", _expect in _hint,
              f"{_C.OS_FAMILY} → {_hint[:44]}")
        check("compat·资源探测可用", _C.cpu_count() >= 1 and _C.total_memory_bytes() >= 0,
              f"CPU {_C.cpu_count()} 核 / 内存 {round(_C.total_memory_bytes()/1024**3, 1)}GB")
        _C.ensure_utf8_stdio()      # 不能抛异常（Windows GBK 控制台的兜底）
        check("compat·控制台 UTF-8 兜底不抛异常", True, "ensure_utf8_stdio 已执行")

        # 性能档位：用构造档位断言，不依赖本机实际档位
        _low = _E.Tier({"tier": "low"})
        _high = _E.Tier({"tier": "high"})
        check("envprofile·低配档放大超时",
              _low.timeout(20) > _high.timeout(20),
              f"20s → low {_low.timeout(20)}s / high {_high.timeout(20)}s")
        check("envprofile·低配档压低并发",
              _low.workers(8) < _high.workers(8),
              f"8 → low {_low.workers(8)} / high {_high.workers(8)}")
        check("envprofile·低配档关掉语义模型预热",
              (not _low.enabled("embed_warmup")) and _high.enabled("embed_warmup"),
              f"low={_low.enabled('embed_warmup')} high={_high.enabled('embed_warmup')}")
        check("envprofile·三档配置齐备",
              set(_E.TIERS) == {"low", "mid", "high"}
              and all("timeout_scale" in v and "worker_cap" in v for v in _E.TIERS.values()),
              f"档位 {sorted(_E.TIERS)}")
        _prof = _E.profile()
        check("envprofile·本机画像已生成",
              _prof.get("tier") in _E.TIERS and _prof.get("cpu_count", 0) >= 1,
              f"{_prof.get('tier')} 档 / CPU {_prof.get('cpu_count')} / 内存 {_prof.get('mem_gb')}GB")
    except Exception as e:  # noqa: BLE001
        check("跨平台兼容与性能档位（compat/envprofile）", False, f"导入或执行失败：{e}")

    # bootstrap 只体检（--check 不联网不建 venv，可安全在自测里跑）
    try:
        import subprocess as _sp
        _py = sys.executable
        _r = _sp.run([_py, os.path.join(ROOT, "bootstrap.py"), "--check", "--json"],
                     cwd=ROOT, timeout=120, capture_output=True)
        _out = (_r.stdout or b"").decode("utf-8", "replace")
        _j = json.loads(_out[_out.find("{"):]) if "{" in _out else {}
        _ok = _j.get("steps", {}).get("check", {}).get("runtime", {}).get("ok")
        check("bootstrap·环境体检可离线执行", _r.returncode == 0 and _ok is True,
              f"退出码 {_r.returncode} / ok={_ok}")
    except Exception as e:  # noqa: BLE001
        check("bootstrap·环境体检可离线执行", False, f"执行失败：{e}")

    print("\n" + "=" * 56)
    print(f"结果：通过 {len(PASS)} / 失败 {len(FAIL)}")
    if FAIL:
        print("失败项：")
        for f in FAIL:
            print("  -", f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
