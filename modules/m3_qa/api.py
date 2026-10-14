# -*- coding: utf-8 -*-
"""
api.py —— 模块3「情报问答」后端入口
============================================================
负责人：成员C
职责：安全版 ChatGPT 对话 —— RAG 生成答案、跨文档推理、多跳检索、来源可回溯。

本模块对外接口（启动时自动注册进主体，无需改 core/server.py）：
    GET  /api/chat?q=问题            简版问答（无历史）
    POST /api/chat                   JSON: {q, history, base_url, api_key, model}
    GET  /api/qa/status              自检：Key/向量库/供应商预设（不下发任何 Key）
    GET|POST /api/qa/translate       本地免费翻译（英译中）{"texts":[...]}；零 token、正文不外发
    GET|POST /api/qa/mt_status       翻译模型状态（前端据此决定「译」按钮可用或提示下载）
    GET|POST /api/qa/mt_download     下载本地翻译模型（约 300 MB，一次性，免费）

实现全部在 backend/qa/ 包里（retriever / multi_hop / generator / vector_store / translator）。
问答会通过 HTTP 回访主体（AISEC_MAIN_SERVER，由 core/server.py 自动设为实际端口）
以复用检索 / 详情 / 图谱能力，因此**不需要**把检索引擎重复实现一遍。
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time

# 回访地址：主体启动时会 setdefault，写死只作为兜底
os.environ.setdefault("AISEC_MAIN_SERVER", "http://127.0.0.1:8848")


def _qa_chat():
    """惰性导入：qa 包缺失或依赖不全时，接口返回可读的错误而不是整站崩溃"""
    from qa import chat as qa_chat
    return _with_qa_log(qa_chat)


# --------------------------------------------------------------------------
# 问答台账（data/qa_log.jsonl）
# --------------------------------------------------------------------------
# 此前问答只在内存里走一圈就丢，"今天被问了几次 / 命中率如何 / 慢在哪"根本查不到，
# 每日报告里 m3 那一栏只能写 0。这里在**唯一出口**（_qa_chat 返回的函数）包一层，
# GET / POST 两个入口、以及将来任何新入口都自动被覆盖 —— 分散到各 handler 里
# 记，迟早会漏一处。
_QA_LOG_MAX_BYTES = 8 * 1024 * 1024      # 超过就轮转，避免问答日志无限长
_QA_LOG_KEEP = 5                          # 保留世代数
_QA_LOG_LOCK = threading.Lock()
_QA_LOG_CAP = 2000                        # 单次最多记多少字符，防止超长问题撑爆行


def _qa_log_path():
    """数据目录必须走 core/paths.DATA_DIR —— 它才是权威口径（认 AISEC_DATA_DIR
    与 config.json 的 data_dir）。自己按 __file__ 上溯拼一个会在模块被换位置 /
    配了自定义数据目录时写到别处，日报那边就永远读到 0 条。"""
    try:
        core = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), "core")
        if os.path.isdir(core) and core not in sys.path:
            sys.path.insert(0, core)
        import paths
        return os.path.join(paths.DATA_DIR, "qa_log.jsonl")
    except Exception:  # noqa: BLE001
        return os.path.abspath(os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "..", "data", "qa_log.jsonl"))


def _rotate_qa_log(fp):
    """超量轮转。写日志绝不能把主服务搞挂 —— 任何异常都在这里吞掉。"""
    try:
        for i in range(_QA_LOG_KEEP - 1, 0, -1):
            src, dst = "%s.%d" % (fp, i), "%s.%d" % (fp, i + 1)
            if os.path.exists(src):
                try:
                    os.replace(src, dst)
                except OSError:
                    pass
        os.replace(fp, fp + ".1")
    except Exception:  # noqa: BLE001
        pass


def _log_qa(question, ms, result=None, error=None):
    """写一条问答台账。任何失败静默 —— 台账是辅助功能，不能影响主流程。"""
    try:
        fp = _qa_log_path()
        d = os.path.dirname(fp)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        srcs = 0
        used_llm = False
        if isinstance(result, dict):
            s = result.get("sources")
            srcs = len(s) if isinstance(s, list) else 0
            used_llm = bool(result.get("used_llm"))
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "q": str(question or "")[:_QA_LOG_CAP],
               "ms": int(ms or 0), "sources": srcs, "used_llm": used_llm,
               "error": str(error)[:200] if error else ""}
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        with _QA_LOG_LOCK:
            try:
                if os.path.exists(fp) and os.path.getsize(fp) > _QA_LOG_MAX_BYTES:
                    _rotate_qa_log(fp)
            except OSError:
                pass
            with open(fp, "a", encoding="utf-8", newline="\n") as f:
                f.write(line)
    except Exception:  # noqa: BLE001
        pass


def _with_qa_log(fn):
    def wrapper(*a, **kw):
        t0 = time.time()
        try:
            r = fn(*a, **kw)
        except Exception as e:  # noqa: BLE001 —— 原样抛出给上层处理，只补记台账
            _log_qa(kw.get("question") or (a[0] if a else ""),
                    (time.time() - t0) * 1000, None, e)
            raise
        _log_qa(kw.get("question") or (a[0] if a else ""),
                (time.time() - t0) * 1000, r, None)
        return r
    wrapper.__name__ = getattr(fn, "__name__", "qa_chat")
    wrapper.__doc__ = getattr(fn, "__doc__", "")
    return wrapper


def _safe_int(v, default=0):
    """POST body 里的数值容错：{"limit":"abc"} 也要能退到默认值，不能抛 500"""
    try:
        return int(str(v).strip()) if str(v).strip() else default
    except (TypeError, ValueError):
        return default


def env_llm_config():
    """环境变量提供默认大模型配置（**不要在代码里写 Key**）。

    优先级：页面「模型设置」（随请求传来） > 环境变量 > qa/config.py 默认。
    演示/部署时在启动脚本里设一次即可，所有人都不用再手填：
        set AISEC_LLM_API_KEY=sk-xxxx
        set AISEC_LLM_BASE_URL=https://api.deepseek.com
        set AISEC_LLM_MODEL=deepseek-chat
    （也兼容 DEEPSEEK_API_KEY / DEEPSEEK_BASE_URL / DEEPSEEK_MODEL）
    """
    def pick(*names):
        for n in names:
            v = (os.environ.get(n) or "").strip()
            if v:
                return v
        return ""
    cfg = {}
    key = pick("AISEC_LLM_API_KEY", "DEEPSEEK_API_KEY")
    base = pick("AISEC_LLM_BASE_URL", "DEEPSEEK_BASE_URL")
    model = pick("AISEC_LLM_MODEL", "DEEPSEEK_MODEL")
    if key:
        cfg["api_key"] = key
    if base:
        cfg["base_url"] = base.rstrip("/")
    if model:
        cfg["model"] = model
    return cfg


def handle_qa_status(req):
    """问答模块自检：服务端有没有配好 Key、向量库是否可用、回访地址是否正确。

    前端「情报问答」面板启动时调用：配了就显示「服务端已配置」，不用再手填 Key。
    向量库这里报的是**真实入库条数**（不是「包能 import」），避免看着可以、其实没索引。
    """
    env = env_llm_config()
    out = {
        "env_key": bool(env.get("api_key")),
        "model": env.get("model") or "deepseek-chat",
        "base_url": env.get("base_url") or "https://api.deepseek.com",
        "main_server": os.environ.get("AISEC_MAIN_SERVER", ""),
        "qa_package": True,
        "vector": False,
        "vector_count": 0,
        "vector_model": "",
        "vector_note": "",
    }
    # LLM Key 自检提示（2026-10-08 实测补）：常见误解是「secrets.env 文件在 = 已配好」。
    # 实测确认：文件里 `AISEC_LLM_API_KEY=` 后面为空时，服务只能走模板模式；
    # 而界面只显示「未配置」，用户分不清是"没填"还是"填了没读到"。这里把两种情况
    # 分开说清楚，避免"我明明配了"的无效排查。
    out["env_key_hint"] = ""
    # —— 降级状态显式化（v2.2）——
    # 此前只有 env_key 一个布尔：前端据此显示「未配置」，但**说不出降级后行为变了什么**，
    # 用户以为系统坏了。degraded/reason 让 UI 能直接讲清「现在是模板模式」。
    out["degraded"] = not bool(env.get("api_key"))
    out["degraded_reason"] = (
        "" if env.get("api_key") else
        "未配置大模型 Key —— 本次回答由「检索证据模板」生成，"
        "不含大模型自主编排/推理，Tool-Calling Agent 未生效"
    )
    if not env.get("api_key"):
        try:
            _root = os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))))
            _fp = os.path.join(_root, "secrets.env")
            _filled = False
            if os.path.exists(_fp):
                with open(_fp, encoding="utf-8", errors="replace") as _f:
                    for _ln in _f:
                        _ln = _ln.strip().lstrip("\ufeff")
                        if _ln.startswith("AISEC_LLM_API_KEY="):
                            _filled = bool(_ln.split("=", 1)[1].strip())
                            break
            out["env_key_hint"] = (
                "secrets.env 里 AISEC_LLM_API_KEY 已填、但当前服务进程未读到（重启服务生效）"
                if _filled else
                "secrets.env 里 AISEC_LLM_API_KEY 为空 —— 填好并重启服务即可启用 LLM 模式")
        except Exception:  # noqa: BLE001
            out["env_key_hint"] = "未配置 LLM Key，当前为模板模式"
    try:
        from qa.vector_store import vector_store
        out["vector_count"] = vector_store.count()
        out["vector"] = out["vector_count"] > 0
        out["vector_model"] = vector_store.info().get("embedder", {}).get("model", "") \
            or vector_store.info().get("model", "")
        if out["vector_count"] == 0:
            out["vector_note"] = ("向量库为空（检索走关键词+多跳，功能正常）；"
                                 "建库：POST /api/qa/build_vector")
    except Exception as e:  # noqa: BLE001
        out["vector_note"] = f"向量库不可用（不影响关键词+多跳检索）: {str(e)[:80]}"
    try:
        _qa_chat()
    except Exception as e:  # noqa: BLE001
        out["qa_package"] = False
        out["note"] = f"qa 包不可用: {str(e)[:80]}"
    # 供应商预设：给页面「模型设置」的下拉用 —— 选了就自动填好 base_url/model，用户只需粘 Key。
    # 数据直接来自 qa/config.py 的 LLM_PROVIDERS（单一来源，不会与后端漂移）；api_key 一律不下发。
    labels = {"deepseek": "DeepSeek", "doubao": "豆包 / 火山方舟",
              "qwen": "通义千问（百炼）", "openai": "OpenAI",
              "custom": "自定义（OpenAI 兼容）"}
    out["providers"] = []
    try:
        from qa import config as qa_config
        for pid, p in (getattr(qa_config, "LLM_PROVIDERS", {}) or {}).items():
            out["providers"].append({
                "id": pid, "label": labels.get(pid, pid),
                "base_url": (p.get("base_url") or "").rstrip("/"),
                "model": p.get("model") or "",
            })
    except Exception as e:  # noqa: BLE001
        out["providers_note"] = f"预设不可用: {str(e)[:80]}"
    return req.json(out)


def handle_qa_coverage(req):
    """GET /api/qa/coverage —— 知识覆盖范围（数据源 → 规模 → 最后同步时间）。

    验收框架要求「数据源清单 + 覆盖矩阵 + 更新频率」是可查询的证据，而不是
    藏在代码常量里。这里把各数据源的真实规模与最后同步时间一次性暴露出来，
    评审/前端都能直接看「现在覆盖了多少、多久没更新了」。
    """
    import time as _t
    try:
        import paths as _paths
        import engine as _engine
    except Exception as e:  # noqa: BLE001
        return req.json({"error": f"核心模块不可用: {str(e)[:120]}"}, 500)

    def _stat(relpath):
        """返回 {path, size, mtime, count} —— 文件不存在则 count=0。"""
        fp = os.path.join(_paths.DATA_DIR, relpath)
        try:
            st = os.stat(fp)
            return {"path": relpath, "bytes": st.st_size,
                    "mtime": _t.strftime("%Y-%m-%dT%H:%M:%S", _t.localtime(st.st_mtime))}
        except OSError:
            return {"path": relpath, "bytes": 0, "mtime": ""}

    # 语料库规模（真实读 corpus.json 顶层计数）
    corpus = {"records": 0, "knowledge": 0, "papers": 0, "kev_total": 0,
              "osv_index": 0, "atlas_techniques": 0}
    try:
        import json as _json
        with open(_paths.CORPUS_FP, encoding="utf-8") as f:
            _d = _json.load(f)
        _m = _d.get("meta", {}) if isinstance(_d, dict) else {}
        corpus["records"] = len(_d.get("records", [])) if isinstance(_d, dict) else 0
        corpus["knowledge"] = len(_d.get("knowledge", [])) if isinstance(_d, dict) else 0
        corpus["papers"] = len(_d.get("papers", [])) if isinstance(_d, dict) else 0
        corpus["kev_total"] = _m.get("kev_total", 0)
        corpus["osv_index"] = _m.get("osv_index", 0)
        _atlas = _d.get("atlas", {}) if isinstance(_d, dict) else {}
        corpus["atlas_techniques"] = (_atlas.get("technique_count", 0)
                                      if isinstance(_atlas, dict) else 0)
    except Exception as e:  # noqa: BLE001
        corpus["error"] = str(e)[:80]

    # 各数据源文件规模 + 最后同步时间
    sources = {
        "CVE/NVD": _stat("nvd_cache.json"),
        "KEV 在野利用": _stat("kev_cache.json"),
        "OSV 开源漏洞": _stat("osv_cache.json"),
        "实时流（快车道）": _stat("live_feed.jsonl"),
        "学术论文": _stat("papers.json"),
        "内部知识库": _stat("corpus.json"),
        "资产库（CMDB）": _stat("cmdb_scans.json"),
        "资产扫描": _stat("asset_scans.json"),
        "POC 情报": _stat("poc_results.json"),
        "缓解/补丁缓存": _stat("remediation_cache.json"),
    }
    for _k in list(sources):
        _v = sources[_k]
        if _v["bytes"] == 0 and _k not in ("实时流（快车道）", "内部知识库"):
            continue  # 未接入/空的数据源不报，避免刷屏
        sources[_k] = {**_v, "size_kb": round(_v["bytes"] / 1024, 1)}

    # 实时性口径（来自 live.py 的真实常量，而非口头承诺）
    refresh = {}
    try:
        from qa import config as _cfg
        refresh["live_poll_sec"] = getattr(_cfg, "FAST_INTERVAL", 15)
    except Exception:  # noqa: BLE001
        refresh["live_poll_sec"] = 15
    # monitor.last_sync（真实最后同步时间）
    last_sync = ""
    try:
        import json as _json
        with open(os.path.join(_paths.DATA_DIR, "monitor_state.json"), encoding="utf-8") as f:
            _ms = _json.load(f)
        last_sync = _ms.get("last_sync", "") if isinstance(_ms, dict) else ""
    except Exception:  # noqa: BLE001
        pass

    return req.json({
        "corpus": corpus,
        "sources": sources,
        "refresh": refresh,
        "last_sync": last_sync,
        "ioc_supported": "ioc" in getattr(_engine, "OP_KEYS", {}).values(),
        "generated_at": _t.strftime("%Y-%m-%dT%H:%M:%S"),
    })


# ----------------------------------------------------------------------
# 向量库建库（① 全量语义召回）
# ----------------------------------------------------------------------
VEC_JOB = {"running": False, "done": False, "total": 0, "processed": 0,
           "indexed": 0, "skipped": 0, "error": None, "started_at": "",
           "elapsed": 0.0, "rate": 0.0, "eta": 0.0, "model": "", "dim": 0,
           "note": ""}
VEC_LOCK = threading.Lock()
VEC_THREAD = None


def _vec_build_worker(engine, limit, batch, reset):
    """后台线程：把引擎里的语料分批编码写入 Chroma（断点续跑，可反复调用）"""
    import time as _t
    t0 = _t.time()
    try:
        from qa.vector_store import vector_store
        if reset:
            vector_store.reset()
        docs = list(getattr(engine, "docs", []) or [])
        if limit and limit > 0:
            docs = docs[:limit]
        with VEC_LOCK:
            VEC_JOB.update(total=len(docs), note=f"语料 {len(docs)} 条，模型加载中…")
        # 预热模型（加载耗时单独提示，避免用户以为卡住）
        from qa.local_embedder import local_embedder
        local_embedder.ensure()
        with VEC_LOCK:
            VEC_JOB.update(model=local_embedder.model_name, dim=local_embedder.dim,
                           note=f"编码中（{local_embedder.model_name}，{local_embedder.dim} 维）")

        def _prog(done, total):
            dl = _t.time() - t0
            rate = done / dl if dl > 0 else 0
            left = (total - done) / rate if rate > 0 else 0
            with VEC_LOCK:
                VEC_JOB.update(processed=done, elapsed=round(dl, 1),
                               rate=round(rate, 1), eta=round(left, 1))

        res = vector_store.build_index(docs, batch_size=batch, progress=_prog,
                                       capacity_hint=len(getattr(engine, "docs", []) or []))
        with VEC_LOCK:
            VEC_JOB.update(running=False, done=True, error=res.get("error"),
                           indexed=res.get("indexed", 0), skipped=res.get("skipped", 0),
                           elapsed=round(_t.time() - t0, 1),
                           note=f"完成：本次写入 {res.get('indexed', 0)} 条，"
                                f"库中 {res.get('total', 0)} 条")
        print(f"[m3] 向量库建库完成：{res}")
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        with VEC_LOCK:
            VEC_JOB.update(running=False, done=True, error=str(e),
                           elapsed=round(_t.time() - t0, 1))


def handle_build_vector(req):
    """GET 看进度 / POST 开始建库。

    POST body（都可省略）：{"limit": 0, "batch": 64, "reset": false}
      limit：只索引前 N 条（先小样验证用）；0/缺省=全部语料
      batch：编码批次，CPU 上 32~64 比较稳
      reset：true 先清空重建（换模型时必须）
    """
    global VEC_THREAD
    from qa.vector_store import vector_store  # noqa: F401  （提前暴露导入错误）
    if req.method == "GET":
        with VEC_LOCK:
            out = dict(VEC_JOB)
        try:
            out["count"] = vector_store.count()
            out["embedder"] = vector_store.info().get("embedder", {})
        except Exception as e:  # noqa: BLE001
            out["count"] = 0
            out["error"] = out.get("error") or str(e)
        return req.json(out)

    body = {}
    try:
        if req.body:
            body = json.loads(req.body.decode("utf-8"))
    except Exception:  # noqa: BLE001
        body = {}
    if VEC_THREAD is not None and VEC_THREAD.is_alive():
        return req.json({"error": "已有建库任务在跑", **dict(VEC_JOB)}, 409)
    limit = _safe_int(body.get("limit"), 0)
    batch = _safe_int(body.get("batch"), 64)
    reset = bool(body.get("reset"))
    with VEC_LOCK:
        VEC_JOB.update(running=True, done=False, total=0, processed=0, indexed=0,
                       skipped=0, error=None, elapsed=0.0, rate=0.0, eta=0.0,
                       started_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
                       note="已受理，正在准备…")
    VEC_THREAD = threading.Thread(target=_vec_build_worker,
                                  args=(req.engine, limit, batch, reset), daemon=True)
    VEC_THREAD.start()
    return req.json({"started": True, "limit": limit, "batch": batch, "reset": reset,
                     "hint": "GET /api/qa/build_vector 查进度"}, 202)


def handle_chat_get(req):
    """兼容 GET 简版：?q=问题  （POST 版本支持 history / 自定义 LLM 配置）

    加 &no_llm=1 可强制「只用检索证据模板」（自测 / 离线演示 / 不想花 token）。
    """
    question = req.q("q")
    if not question:
        return req.json({"error": "缺少参数q"}, 400)
    no_llm = (req.q("no_llm") or "").lower() in ("1", "true", "yes", "on")
    # ★ 2026-10-08 实测补 —— GET 与 POST 的 LLM 配置必须一致：
    #   原 GET 分支传 `llm_config=None`，于是 generate() 落回 qa/config.py 的
    #   默认配置（**不含 api_key**）→ **GET 路径永远走模板模式**，
    #   哪怕服务端/secrets.env 已配好 Key。这直接造成「1007 条问答日志里
    #   只有 6 条 used_llm=true」——那 6 条全是 POST（且是页面手填 Key）。
    #   现在 GET 也读 env_llm_config()；`no_llm=1` 仍可显式强制模板。
    llm_config = dict(env_llm_config())
    if no_llm:
        llm_config["disable_llm"] = True
    llm_config = {k: v for k, v in llm_config.items() if v} or None
    try:
        return req.json(_qa_chat()(question, llm_config=llm_config))
    except ImportError as e:
        return req.json({"error": f"问答模块不可用（缺少 qa 包或其依赖）: {e}",
                         "answer": "问答模块未就绪", "sources": [], "used_llm": False}, 500)
    except Exception as e:  # noqa: BLE001
        return req.json({"error": f"问答服务异常: {e}",
                         "answer": "系统暂时繁忙，请稍后再试",
                         "sources": [], "used_llm": False}, 500)


def handle_chat_post(req):
    body = req.body
    try:
        data = json.loads(body.decode("utf-8")) if body else {}
    except Exception:  # noqa: BLE001
        return req.json({"error": "请求体不是合法JSON"}, 400)
    question = data.get("q", "")
    if not question:
        return req.json({"error": "缺少参数q"}, 400)
    history = data.get("history", [])
    # 合并顺序：环境变量（服务端统一配置） ← 被 ← 请求里的页面设置覆盖
    llm_config = dict(env_llm_config())
    llm_config.update({k: v for k, v in {
        "base_url": data.get("base_url"),
        "api_key": data.get("api_key"),
        "model": data.get("model"),
    }.items() if v})
    llm_config = {k: v for k, v in llm_config.items() if v}
    # 显式要求「只用检索证据模板」：自测/离线演示/不想花 token 时用（no_llm: true）
    if data.get("no_llm") is True:
        llm_config["disable_llm"] = True
    try:
        qa_chat = _qa_chat()
    except ImportError as e:
        return req.json({"error": f"问答模块不可用（缺少 qa 包或其依赖）: {e}",
                         "answer": "问答模块未就绪", "sources": [], "used_llm": False}, 500)
    try:
        result = qa_chat(question, history=history,
                         llm_config=llm_config if llm_config else None)
        return req.json(result)
    except Exception as e:  # noqa: BLE001
        return req.json({"error": f"问答服务异常: {str(e)}",
                         "answer": "系统暂时繁忙，请稍后再试",
                         "sources": [], "used_llm": False}, 500)


# ----------------------------------------------------------------------
# 流式问答（SSE）—— 2026-10-08 针对「大模型生成 55.6s 才整段返回」实测改造
# ----------------------------------------------------------------------
# 根因：Agent 收敛轮一次性生成 ~2000 token（非流式），deepseek 输出速度
# ~30-40 tok/s → 光生成就 50-60s，且 Agent 路径此前不受 QA_BUDGET 约束。
# 服务端已把 Agent 改成「规划轮 + 终局流式生成」两段式；本端点把
# stage/token 事件以 text/event-stream 逐帧推给前端，用户从「黑盒干等
# 55s」变成「~10s 内看见答案逐字生成、全程可见阶段进度」。
#
# SSE 帧协议：
#   event: stage   data: {"stage":"plan|tool|generate|finalize","msg":"..."}
#   event: token   data: {"t":"片段"}     —— 终局生成的逐字输出
#   event: done    data: {完整结果 JSON}  —— 与 POST /api/chat 同构
#   event: error   data: {"error":"..."}
# ----------------------------------------------------------------------

def _sse_frame(event: str, obj) -> bytes:
    return ("event: %s\ndata: %s\n\n" % (event, json.dumps(obj, ensure_ascii=False))).encode("utf-8")


def handle_chat_stream(req):
    """POST /api/chat/stream —— SSE 流式问答。请求体与 POST /api/chat 完全一致。

    无 Key / no_llm 时直接走模板路径，不流式（模板是毫秒级，流式没意义）。
    任何异常都以 error 帧收尾——前端把已收到的 token 拼起来展示，不白等。
    """
    h = req.h
    try:
        data = json.loads(req.body.decode("utf-8")) if req.body else {}
    except Exception:  # noqa: BLE001
        data = {}
    question = data.get("q", "")
    history = data.get("history", [])

    # ── SSE 响应头：不带 Content-Length，显式 Connection: close ──
    try:
        h.send_response(200)
        h.send_header("Content-Type", "text/event-stream; charset=utf-8")
        h.send_header("Cache-Control", "no-store")
        h.send_header("Connection", "close")
        h.send_header("Access-Control-Allow-Origin", "*")
        h.send_header("X-Accel-Buffering", "no")   # 若前面有反代也不缓冲
        h.end_headers()
        h.close_connection = True                   # HTTP/1.1 keep-alive 必须显式关
    except (ConnectionError, BrokenPipeError):
        return

    def _push(event, obj):
        try:
            h.wfile.write(_sse_frame(event, obj))
            h.wfile.flush()
        except (ConnectionError, BrokenPipeError, OSError):
            raise                       # 客户端断开：让上层停止生成
        except Exception as e:  # noqa: BLE001
            raise ConnectionError(f"sse write failed: {e}")

    if not str(question or "").strip():
        _push("error", {"error": "缺少参数q"})
        return

    llm_config = dict(env_llm_config())
    llm_config.update({k: v for k, v in {
        "base_url": data.get("base_url"),
        "api_key": data.get("api_key"),
        "model": data.get("model"),
    }.items() if v})
    llm_config = {k: v for k, v in llm_config.items() if v}
    if data.get("no_llm") is True:
        llm_config["disable_llm"] = True

    def _on_event(kind, payload):
        if kind in ("stage", "token"):
            _push(kind, payload)

    try:
        qa_chat = _qa_chat()
        result = qa_chat(question, history=history,
                         llm_config=llm_config if llm_config else None,
                         on_event=_on_event)
        _push("done", result)
    except (ConnectionError, BrokenPipeError):
        # 客户端提前关页面：正常结束，服务端日志不刷屏
        return
    except ImportError as e:
        _push("error", {"error": f"问答模块不可用（缺少 qa 包或其依赖）: {e}"})
    except Exception as e:  # noqa: BLE001
        try:
            _push("error", {"error": f"问答服务异常: {str(e)[:300]}"})
        except Exception:  # noqa: BLE001
            pass


def handle_vector_probe(req):
    """只看向量检索命中什么（调试/验收用）：证明「语义召回真的在工作」。

    GET /api/qa/vector_probe?q=有东西能被远程打穿的AI框架&k=5
    返回向量库自己的 top-k 与相似度（不经过 BM25 融合），与 /api/search 对比即可看出语义召回补了什么。
    """
    q = req.q("q") or ""
    k = max(1, min(req.q_int("k", 5), 60))
    if not q:
        return req.json({"error": "缺少参数q"}, 400)
    try:
        from qa.vector_store import vector_store
        hits = vector_store.search(q, k)
        return req.json({"q": q, "k": k, "count": vector_store.count(),
                         "model": vector_store.info().get("embedder", {}).get("model", ""),
                         "hits": [{"id": h.get("id"), "title": (h.get("title") or "")[:120],
                                   "vector_score": h.get("vector_score"),
                                   "severity": (h.get("cvss") or {}).get("severity"),
                                   "published": h.get("published")} for h in hits]})
    except Exception as e:  # noqa: BLE001
        return req.json({"error": f"向量检索失败: {e}", "q": q, "hits": []}, 500)


def handle_hybrid_search(req):
    """**混合检索**（关键词 + 语义）——模块3 对外提供，核心引擎不用改。

    GET /api/hybrid_search?q=vLLM远程代码执行&size=12
    返回：融合同排后的结果 + 融合元信息（两路候选数、权重、各来源条数、是否跳过语义）。
    与 /api/search 的区别：这里多了**语义召回**这一路，用于口语化/语义改写提问；
    带强筛选（severity=/category=/cvss_min= …）时自动只走引擎精确路径（结论与纯关键词一致）。
    """
    q = req.q("q") or ""
    if not q:
        return req.json({"error": "缺少参数q"}, 400)
    size = max(1, min(req.q_int("size", 12), 60))
    filters = {
        "severity": [s for s in (req.q("severity") or "").split(",") if s],
        "category": [s for s in (req.q("category") or "").split(",") if s],
        "source": [s for s in (req.q("source") or "").split(",") if s],
        "scope": [s for s in (req.q("scope") or "").split(",") if s],
        "exploited_only": req.q("exploited") == "1",
        "poc_only": req.q("poc") == "1",
        "cvss_min": req.q_float("cvss_min") or None,
        "year_from": req.q_int("year_from") or None,
        "year_to": req.q_int("year_to") or None,
    }
    try:
        from qa.retriever import hybrid_search
        # no_boost=1：关掉「强标记→结构化算子」增强，用于同口径 A/B 评测
        no_boost = str(req.q("no_boost") or "").lower() in ("1", "true", "yes", "on")
        out = hybrid_search(q, size, filters, skip_boost=no_boost)
        out["q"] = q
        return req.json(out)
    except Exception as e:  # noqa: BLE001
        return req.json({"error": f"混合检索失败: {e}", "q": q, "results": []}, 500)


# ---------------- 本地免费翻译（英文情报 → 中文；零 token、正文不外发） ----------------
MT_LOCK = threading.Lock()
MT_THREAD = None
MT_JOB = {"running": False, "done": False, "ok": None, "size_mb": 0, "seconds": 0,
          "error": None, "note": "", "percent": 0}


def _mt_download_worker():
    global MT_THREAD
    # 关键：这里是 daemon 线程，download() 一旦抛异常线程就会静默死掉，
    # MT_JOB 永远停在 running=True —— 前端表现为「一直在下载中」且没有任何报错，
    # 用户只能猜。所以整个下载过程必须兜住异常并把原因写回 MT_JOB。
    try:
        from qa.translator import translator
    except Exception as e:  # noqa: BLE001
        with MT_LOCK:
            MT_JOB.update(running=False, done=True, ok=False,
                          error=f"翻译模块导入失败：{type(e).__name__}: {e}",
                          note="下载失败（模块导入异常）")
        MT_THREAD = None
        return

    with MT_LOCK:
        MT_JOB.update(note="下载中（约 300 MB，ModelScope 直连镜像；中断后重跑会续传）")

    def _prog(stage, pct):
        with MT_LOCK:
            MT_JOB.update(note=f"下载中 {stage}（{pct}%）", percent=pct)

    try:
        r = translator.download(_prog)
    except Exception as e:  # noqa: BLE001
        with MT_LOCK:
            MT_JOB.update(running=False, done=True, ok=False, percent=100,
                          error=f"{type(e).__name__}: {e}",
                          note="下载失败（后台任务异常，见 error 字段）")
        MT_THREAD = None
        return

    with MT_LOCK:
        MT_JOB.update(running=False, done=True, ok=bool(r.get("ok")),
                      size_mb=r.get("size_mb") or 0, seconds=r.get("seconds") or 0,
                      error=r.get("error"), percent=100,
                      note="下载完成，翻译已可用（免费、本地）" if r.get("ok") else "下载失败")
    MT_THREAD = None


def handle_mt_status(req):
    """GET /api/qa/mt_status —— 本地翻译模型状态。

    前端拿它决定「译」按钮是「可用」还是「提示下载」：ready=false 时不该静默失败。
    """
    from qa.translator import translator
    with MT_LOCK:
        job = dict(MT_JOB)
    return req.json({**translator.status(), "job": job})


def handle_mt_download(req):
    """POST /api/qa/mt_download —— 下载本地翻译模型（一次性，免费，不花钱）。

    GET 等价于看状态；已经在下载时返回 409，不会重复下。
    """
    global MT_THREAD
    from qa.translator import translator
    if req.method == "GET":
        with MT_LOCK:
            job = dict(MT_JOB)
        return req.json({**translator.status(), "job": job})
    if MT_THREAD is not None and MT_THREAD.is_alive():
        with MT_LOCK:
            return req.json({"error": "已有下载任务在跑", **dict(MT_JOB)}, 409)
    with MT_LOCK:
        MT_JOB.update(running=True, done=False, ok=None, size_mb=0, seconds=0,
                      error=None, note="已受理，正在准备…")
    MT_THREAD = threading.Thread(target=_mt_download_worker, daemon=True)
    MT_THREAD.start()
    return req.json({"started": True, "hint": "GET /api/qa/mt_status 或 /api/qa/mt_download 查进度"}, 202)


def handle_translate(req):
    """POST /api/qa/translate  {"texts": ["...", "..."]} → {items:[{src,dst,skipped}], engine, ms}

    本地 MarianMT 英译中：零 token、零外部请求、离线可用；**正文不出本机**。
    单条上限 2000 字符、单次最多 50 条（防误用）；已是中文/太短/纯符号的条目原样返回并标 skipped。
    GET 形式：/api/qa/translate?text=...（便于 curl 手测）
    """
    if req.method == "GET":
        q = req.q("text")
        texts = [q] if q else []
    else:
        try:
            body = json.loads(req.body.decode("utf-8")) if req.body else {}
        except Exception:  # noqa: BLE001
            return req.json({"error": "请求体不是合法JSON"}, 400)
        texts = body.get("texts") or ([body.get("text")] if body.get("text") else [])
    texts = [str(t) for t in (texts or [])][:50]
    if not texts:
        return req.json({"error": "缺少 texts（数组）或 text（单条）"}, 400)
    from qa.translator import translator
    return req.json(translator.translate(texts))


def handle_agent_tools(req):
    """GET /api/qa/agent/tools —— 智能体登记了哪些工具可用（名字/参数/是否有执行器）。

    这是「Agent 架构」对外可验证的证据**：不是嘴上说有 Tool Calling，
    而是把工具注册表原样暴露出来，谁都能数。评测脚本 `评测/量化评测.py` 的 C1 也读它。
    """
    try:
        from qa.agent import tools_manifest, MAX_CALLS, MAX_ROUNDS
        tools = tools_manifest()
        return req.json({
            "count": len(tools),
            "all_have_executor": all(t["has_executor"] for t in tools),
            "max_calls_per_question": MAX_CALLS,
            "max_rounds": MAX_ROUNDS,
            "tools": tools,
        })
    except Exception as e:  # noqa: BLE001
        return req.json({"error": f"工具注册表不可用: {str(e)[:120]}", "count": 0, "tools": []}, 500)


def handle_agent_trace(req):
    """GET /api/qa/agent/trace —— 最近一次智能体问答的工具调用链路（留痕）。

    用于答辩现场证明"它真的自主调了工具"：返回 trace 里每一步的工具名、参数、成败与耗时。
    """
    try:
        # 注意：留痕实现就在 qa/agent.py 里（record_trace/last_traces），
        # 曾经写成 from qa.agent_trace_ring import —— 那个模块不存在，
        # 导致本接口每次都 500，答辩要用的"工具调用链路"反而取不到。
        from qa.agent import last_traces
        return req.json({"traces": last_traces()})
    except Exception as e:  # noqa: BLE001
        return req.json({"error": f"trace 不可用: {str(e)[:120]}", "traces": []}, 500)


def register(ctx):
    ctx.route("GET", "/api/chat", handle_chat_get)
    ctx.route("POST", "/api/chat", handle_chat_post)
    # 流式问答（SSE）：前端逐字渲染，首字时间从 55s 量级降到 ~10s 内
    ctx.route("POST", "/api/chat/stream", handle_chat_stream)
    ctx.route("GET", "/api/qa/status", handle_qa_status)
    ctx.route("GET", "/api/qa/coverage", handle_qa_coverage)
    ctx.route("GET", "/api/qa/build_vector", handle_build_vector)
    ctx.route("POST", "/api/qa/build_vector", handle_build_vector)
    ctx.route("GET", "/api/qa/vector_probe", handle_vector_probe)
    ctx.route("GET", "/api/hybrid_search", handle_hybrid_search)
    # 本地免费翻译（英文情报 → 中文）：不花 token、正文不外发、离线可用
    ctx.route("GET", "/api/qa/translate", handle_translate)
    ctx.route("POST", "/api/qa/translate", handle_translate)
    ctx.route("GET", "/api/qa/mt_status", handle_mt_status)
    ctx.route("GET", "/api/qa/mt_download", handle_mt_download)
    ctx.route("POST", "/api/qa/mt_download", handle_mt_download)
    # 智能体工具编排：Tool-Calling Agent（实现在 qa/agent.py）
    ctx.route("GET", "/api/qa/agent/tools", handle_agent_tools)
    ctx.route("GET", "/api/qa/agent/trace", handle_agent_trace)
    # 语义索引自动增量补建：把"要不要手动补一次索引"这件事也自动化掉
    ctx.on_start(start)


# ---------------- 语义索引自动增量补建（自动化最后一块拼图） ----------------
# 以前：实时监测往语料里加新文档，索引要人手工点一次「建索引」才会补上，
# 忘了补 → 新情报只能被关键词检索到、语义召回不到，是个静默的功能缺口。
# 现在：模块启动后起一个守护线程，按配置周期自动补建（只处理未编码的新文档），
# 周期由 config.json 的 vector_auto_sync_hours 控制（默认 6 小时，0 = 关闭）。
AUTO_SYNC_THREAD = None


def _auto_sync_worker(hours: float, engine):
    """守护线程：每 hours 小时补建一次语义索引（复用 POST /api/qa/build_vector 的 worker，
    已编码的文档自动跳过，只补新增，断点续跑）。"""
    global VEC_THREAD
    import time as _t
    # 先给服务 90 秒冷启动时间，别一上来就跟启动线程抢 CPU
    _t.sleep(90)
    while True:
        try:
            if VEC_THREAD is not None and VEC_THREAD.is_alive():
                print("[m3_qa] 语义索引自动补建：已有任务在跑，本轮跳过", flush=True)
            else:
                from qa.vector_store import vector_store
                before = vector_store.count()
                print(f"[m3_qa] 语义索引自动补建：开始（当前 {before} 条）", flush=True)
                VEC_THREAD = threading.Thread(target=_vec_build_worker,
                                              args=(engine, 0, 64, False),
                                              daemon=True, name="qa-autosync-build")
                VEC_THREAD.start()
                VEC_THREAD.join(timeout=max(30, int(hours * 3600 * 0.5)))
                print(f"[m3_qa] 语义索引自动补建：本轮结束（{before} → {vector_store.count()} 条）", flush=True)
        except Exception as e:  # noqa: BLE001
            # 模型没下好 / 依赖缺 / 被中断 —— 下一轮再试，绝不影响主服务
            print(f"[m3_qa] 语义索引自动补建失败（下一周期重试，不影响问答）：{str(e)[:120]}", flush=True)
        _t.sleep(max(1.0, hours) * 3600)


def start(core):
    """模块启动钩子：注册自动补建线程（关掉只需把周期设为 0）。"""
    global AUTO_SYNC_THREAD
    cfg = (getattr(core, "config", None) or {}) or {}
    hours = float(cfg.get("vector_auto_sync_hours") or 6)
    if hours <= 0:
        print("[m3_qa] 语义索引自动补建：已关闭（config.json 的 vector_auto_sync_hours=0）", flush=True)
        return
    try:
        engine = core.get_engine()
    except Exception:  # noqa: BLE001
        engine = None
    AUTO_SYNC_THREAD = threading.Thread(target=_auto_sync_worker, args=(hours, engine),
                                        daemon=True, name="qa-autosync")
    AUTO_SYNC_THREAD.start()
    print(f"[m3_qa] 语义索引自动补建：开启，每 {hours} 小时补一次新增文档（断点续跑）", flush=True)
