# -*- coding: utf-8 -*-
"""
server.py —— HTTP 宿主 + 路由注册（AI-SecIntel 主体 core）
============================================================
本文件只负责“主体”该管的事；模块相关的东西一律由 modules/<id>/api.py 自己注册，
所以以后再也不用把三个人的 server.py 手工融合。

  【主体自带接口】
  GET  /                     控制台前端
  GET  /api/stats            语料与维度统计
  GET  /api/search           自然语言检索（结果 + 意图解析 + 分面 + 答复卡）
  GET  /api/detail?id=       单条情报全量富化详情
  GET  /api/suggest?q=       检索建议（组件 / CVE号 / 术语 / 中文词）
  GET  /api/corpus           轻量清单（前端离线筛选用）
  GET  /api/latest?n=        最新情报 feed
  GET  /api/related?id=      相关情报推荐
  GET  /api/graph?id=        情报关系图谱
  GET  /api/credibility      全局可信度 / 交叉验证 / 可利用性统计
  GET  /api/export?q=|id=    导出 Markdown 报告
  GET  /modules/<id>/<file>  模块自有前端资源（自动服务）

  【由模块注册进来的接口】见各模块 module.json 的 routes 字段
  /api/live /api/sources /api/refresh   —— m1_monitor 情报监测
  /api/assets /api/poc                  —— m2_enrich  情报富化
  /api/chat                             —— m3_qa      情报问答

启动： python core/server.py [port] [--auto-refresh 小时] [--fast-interval 秒]
                                [--no-live] [--no-modules]
      （macOS/Linux 用 python3；Windows 也可用 py -3）

跨平台：2012 年后的 Windows 7+/macOS/Linux 均可运行（最低 Python 3.6）。
        慢机器由 core/envprofile.py 自动降档（降并发 / 延超时 / 关预热）。

性能设计（沿用合并版）：HTTP/1.1 keep-alive · gzip · 静态 ETag/304 ·
/api/stats 结果缓存 · 引擎热切换不中断检索。
"""

import gzip
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.parse
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# 项目根目录也进 sys.path：modules/ 是 namespace package（无 __init__.py），
# 只有根目录在 path 里时 `from modules.m3_qa.api import ...` 这类导入才成立。
# 此前只加 core/，导致 llm_status() 的 `from modules.m3_qa.api import` 在服务
# 进程里永远 ModuleNotFoundError、LLM Key 已填却读不到（2026-10-08 实测定位）。
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
# 索引缓存落盘节流（秒）：271MB 的 pickle，轻量同步 5 分钟一轮不必每轮都重写。
_IDXCACHE_SAVE_GAP = 1200
_LAST_IDXCACHE_SAVE = [0.0]

import paths                                                  # noqa: E402
try:                       # 版本/平台兼容 + 性能档位（见 core/compat.py、core/envprofile.py）
    import compat as _compat
except Exception:          # pragma: no cover
    from core import compat as _compat                        # type: ignore
try:
    import envprofile as _envp
    T = _envp.T
except Exception:          # pragma: no cover
    _envp, T = None, None
from registry import Registry, Request                        # noqa: E402
from engine import SearchEngine, PHRASE_TERMS, AI_PRODUCTS, canonical_url  # noqa: E402
import credibility as CR          # noqa: E402  —— 可信度 / 交叉验证 / 可利用性
import graph_data as GD           # noqa: E402  —— 相关情报 / 关系图谱
import report_export as RPT       # noqa: E402  —— Markdown 报告导出
import metrics                    # noqa: E402  —— 基础设施指标 / 阈值告警 / /api/metrics
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

HERE = paths.CORE_DIR
WEB = paths.WEB_DIR
CORPUS = paths.CORPUS_FP
CONFIG = paths.load_config()

MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
        ".svg": "image/svg+xml", ".ico": "image/x-icon"}

# 单次 POST 请求体上限（2026-10-06）。
# 定这个数的依据：CMDB 全量 .db 上百 MB 是真实场景，必须能传；但也不能不设限——
# 没有上限时 rfile.read(length) 会把整个 body 读进内存，再由 API 层切片复制，
# 峰值内存是文件体积的 2~3 倍。688MB 的库实测直接把连接打到重置，
# 浏览器只看到 "Failed to fetch"。2GB 留足余量，同时挡住误传的巨型包。
MAX_BODY = 2048 * 1024 * 1024
# ★ 大包直传白名单（2026-10-08 晚）：项目成分扫描要支持单包 ≤10GB 的项目 zip。
#   这些路由的 handler 用 req.iter_body() 边收边落盘（磁盘只写一次，峰值内存 =
#   一个 chunk），不会把 body 读进内存，所以可以放开；其余路由维持 2GB 阀门
#   ——那个阀门防的是「rfile.read 进内存」的旧模式，流式路由不在其射程内。
LARGE_BODY_PATHS = {"/api/project_scan"}
LARGE_BODY = (10 * 1024 + 64) * 1024 * 1024      # 10GB + 64MB 余量（容纳表单开销）
def _int_param(qs, key, default, lo=None, hi=None):
    """取整数查询参数：非法值（abc / 空 / null）一律退回默认值，不抛异常。

    URL 是用户可改的（深链接 ?size=0 / ?page=abc / ?n=xx），旧的裸 int()/float()
    会把这类请求打成 500 —— 2026-09-28 修复：size=0、cvss_min=abc、latest?n=abc 均曾 500。
    """
    try:
        raw = (qs.get(key) or [None])[0]
        v = int(str(raw).strip()) if str(raw).strip() else default
    except (ValueError, TypeError, IndexError):
        v = default
    if lo is not None:
        v = max(v, lo)
    if hi is not None:
        v = min(v, hi)
    return v


def _float_param(qs, key, default=None):
    """同上，浮点版本（cvss_min 这类可选项：非法值视为「不过滤」）。"""
    try:
        raw = (qs.get(key) or [None])[0]
        s = str(raw).strip()
        return float(s) if s else default
    except (ValueError, TypeError, IndexError):
        return default


DEFAULT_PORT = 8848


def _coerce_port(v, default=DEFAULT_PORT):
    """把 config["port"] 变成一个能用的端口号。

    ★ 2026-10-07 别人机器上实测：那份 config.json 的 port 字段里存的不是
      8848，而是**一段中文说明**（"控制台端口，但可启动时用命令行覆盖：py -3
      core/server.py 8899"）—— 显然是手工编辑时把 config.json 里其它字段的
      说明文字复制进了 port。
      原先这里是 `int(config.get("port") or 8848)`，直接抛
      ValueError: invalid literal for int()，**服务一行日志都打不出来就崩**，
      用户只看到双击窗口闪一下就没了。
      现在非法值一律回落默认端口并明确提示 —— 配置写错不该让服务起不来。
    """
    if v is None or (isinstance(v, str) and not v.strip()):
        return default
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        print("[!] config.json 的 port 字段不是数字（%r），已回落到默认端口 %d。"
              "请把 port 改成 1024~65535 之间的整数。" % (v, default))
        return default
    if not (1024 <= n <= 65535):
        print("[!] config.json 的 port=%d 超出 1024~65535，已回落到 %d。"
              % (n, default))
        return default
    return n


def _cfg_num(key, default, cast=float, lo=None, hi=None):
    """从 config 取一个数值字段，非法值回落到 default。

    ★ 和 _coerce_port 同一个理由：config.json 是**给人手工编辑**的，
      很容易把说明文字误填进数值字段（实测 port 就这样被别人填成了一段
      中文说明）。原先 int()/float() 直接抛异常，服务一行日志都来不及打
      就崩掉，表现为"双击窗口闪一下就没了"—— 极难定位。
      端口以外的字段同样处理：auto_refresh_hours / fast_interval /
      auto_refresh_sec 都被填过文字的话，症状一样。
    """
    raw = CONFIG.get(key)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return default
    try:
        n = cast(str(raw).strip())
    except (TypeError, ValueError):
        print("[!] config.json 的 %s 字段不是数字（%r），已按 %s 处理。"
              % (key, raw, default))
        return default
    if lo is not None and n < lo:
        print("[!] config.json 的 %s=%s 小于下限 %s，已按 %s 处理。"
              % (key, n, lo, default))
        return default
    if hi is not None and n > hi:
        print("[!] config.json 的 %s=%s 大于上限 %s，已按 %s 处理。"
              % (key, n, hi, default))
        return default
    return n


ENGINE = None
LOCK = threading.Lock()
STATS_CACHE = {}          # engine id -> (stats_json_bytes, etag)
STATIC_CACHE = {}         # path -> (mtime, size, etag, body, gzip_body)
REGISTRY = None           # 模块注册中心（main() 里装载）


class CoreCapabilities:
    """模块通过 ``ctx.core`` 拿到的核心能力：引擎、富化、热切换、端口与配置"""

    def __init__(self, config):
        self.config = config
        self.registry = None
        self.port = _coerce_port(config.get("port"))
        self.corpus_path = CORPUS
        self.args = {}

    # ---- 引擎 ----
    def get_engine(self):
        return get_engine()

    def current_engine(self):
        return ENGINE

    def reload_engine(self):
        """重新构建引擎并原子热切换（增量同步完成后调用，检索不中断）"""
        eng = SearchEngine(CORPUS)
        ensure_credibility(eng)
        global ENGINE
        with LOCK:
            ENGINE = eng
        STATS_CACHE.clear()
        SEARCH_CACHE.clear()        # 引擎换了：检索结果/清单/可信度缓存全部作废
        CORPUS_CACHE.clear()
        CRED_CACHE.clear()
        return eng

    def ensure_credibility(self, eng):
        return ensure_credibility(eng)

    def apply_new_docs(self, docs):
        """轻量同步专用：把新增文档增量并入当前引擎，并同步刷新索引缓存。

        为什么不用 reload_engine()：reload 要重新 json.load 267MB 语料 + 重建/加载索引
        （缓存失效时 382s），而 5 分钟一轮的轻量同步通常只多出个位数文档，
        为它们全量重建一次完全不划算，还会把服务拖出卡顿感。
        这里走引擎的 add_documents 增量路径（毫秒级），再把新的索引状态写回
        .idxcache —— 否则每轮写 corpus 都会让缓存键失效，下次启动就要 6 分钟重建。
        """
        eng = ENGINE
        if eng is None or not docs:
            return 0
        # 先追加新文档，再就地覆盖已存在文档（NVD 会改 CVSS/CWE/描述）。
        # add_documents 遇到已存在的 id 会跳过，update_documents 反过来只处理已存在的。
        try:
            n = eng.add_documents(docs) or 0
        except Exception:  # noqa: BLE001 —— 新增都失败了，说明索引状态可疑，退回全量重建
            return -1
        # 更新失败不该连累新增结果：本轮新 CVE 已经进索引了，
        # 少刷新几条 CVSS 最多是数据略旧，6h 全量轮会补正；为此全量重建不划算。
        try:
            u = eng.update_documents(docs) or 0
        except Exception as e:  # noqa: BLE001
            # 写了一半的索引状态比不写更麻烦，返回 -1 让调用方退回全量重建，
            # 同时打日志——静默吞掉的话，偏差要等到 6h 后的全量轮才显形。
            print("[apply_new_docs] update_documents 失败，退回全量重建:",
                  repr(e)[:200], flush=True)
            u = -1
        if u < 0:
            return -1
        if n or u:
            STATS_CACHE.clear()
            SEARCH_CACHE.clear()
            CORPUS_CACHE.clear()
            CRED_CACHE.clear()
            # 内存顺序对齐磁盘顺序（关键）：
            # monitor 落盘前会把 records/knowledge 按 published 倒序排，而引擎里
            # 是「旧记录原序 + 新记录追加末尾」。这个分叉会让 .idxcache 的 id 指纹
            # 和语料对不上 → 下次启动全量重建（实测 360~410s）。
            # 在写盘这一刻把引擎也排成同一顺序，缓存就永远自洽了；
            # 重排 10 万条是 200ms 级，比启动时多花几分钟划算得多。
            try:
                order = eng._disk_order(self.corpus_path)
                if order and not eng.reorder_by(order):
                    print("[apply_new_docs] 内存顺序对齐失败（id 集合不一致），"
                          "转由启动期 _reorder_docs 兜底", flush=True)
            except Exception as e:  # noqa: BLE001 —— 对齐失败不影响本轮正确性
                print("[apply_new_docs] 顺序对齐异常（忽略）:", repr(e)[:160], flush=True)
            # 索引缓存 271MB，5 分钟一轮的轻量同步没必要每次都重写：
            # 节流到 20 分钟一次。代价只是"这段时间里重启要重建索引（约 6 分钟）"，
            # 而服务本身全程可用、检索全程正确——缓存只影响冷启动速度。
            now = time.time()
            if now - _LAST_IDXCACHE_SAVE[0] >= _IDXCACHE_SAVE_GAP:
                try:
                    eng._save_index_cache(self.corpus_path)
                    _LAST_IDXCACHE_SAVE[0] = now
                except Exception as _sw_e:  # noqa: BLE001
                    _swallow("core/server.py:190", _sw_e)
        return (n or 0) + (u or 0)

    def enrich_all(self, docs):
        return CR.enrich_all(docs)

    def clear_stats_cache(self):
        STATS_CACHE.clear()

    def clear_search_cache(self):
        """清空检索 / 语料 / 可信度缓存，使新增文档立即可被检索命中。"""
        STATS_CACHE.clear()
        SEARCH_CACHE.clear()
        CORPUS_CACHE.clear()
        CRED_CACHE.clear()

    def related_index(self, eng):
        return related_index(eng)


CORE = CoreCapabilities(CONFIG)

_START_TS = time.time()            # 服务启动时刻（/api/health 的 uptime 用）


def get_engine():
    global ENGINE
    if ENGINE is None:
        with LOCK:
            if ENGINE is None:
                ENGINE = SearchEngine(CORPUS)
                ensure_credibility(ENGINE)
    return ENGINE


def ensure_credibility(eng):
    """引擎加载后自动挂载可信度字段（已挂载则跳过，不重复计算）"""
    if eng.docs and "trust_score" in eng.docs[0]:
        return
    CR.enrich_all(eng.docs)


def detail_payload(d):
    """详情接口出参：原始记录 + 原文外链 + 判定依据明细（2026-10-12）

    · url           —— 原文页面地址，前端「打开原文」按钮直接用
    · trust_explain —— 「学术支撑」「双源交叉验证」等标签的判定依据，供点击展开

    这两项都**按需计算**（一次只算被打开的这一条），不像 enrich 那样全量挂载
    到 10 万条记录上，因此不占额外内存。解释算不出来也不影响详情本身可用。
    """
    out = dict(d)
    try:
        out["url"] = canonical_url(d)
    except Exception as e:  # noqa: BLE001
        _swallow("core/server.py:/api/detail.url", e)
        out["url"] = ""
    try:
        out["trust_explain"] = CR.explain_record(d)
    except Exception as e:  # noqa: BLE001
        _swallow("core/server.py:/api/detail.explain", e)
        out["trust_explain"] = {}
    return out


# 关系候选倒排缓存：8 万级语料下避免每次打开详情都全库扫描（引擎热切换时自动重建）
_REL_INDEX = {"engine_id": None, "index": None}


def related_index(eng):
    if _REL_INDEX["engine_id"] != id(eng):
        _REL_INDEX["index"] = GD.build_neighbor_index(eng.docs)
        _REL_INDEX["engine_id"] = id(eng)
    return _REL_INDEX["index"]


def get_stats():
    """stats 结果缓存：语料运行期不变"""
    eng = get_engine()
    key = id(eng)
    if key not in STATS_CACHE:
        raw = json.dumps(eng.stats(), ensure_ascii=False).encode("utf-8")
        etag = '"' + hashlib.sha1(raw).hexdigest()[:16] + '"'
        STATS_CACHE[key] = (raw, etag)
    return STATS_CACHE[key]


# ==========================================================================
# 性能：检索结果 / 轻量清单 / 可信度 缓存（2026-09-28）
#   背景：8.8 万条语料下单次检索要 0.6~1.3s，而"翻页来回切、排序来回切、
#   演示重复跑同一条查询"都是同一组参数 —— 缓存后这些场景直接降到毫秒级。
#   失效策略：以 (引擎对象 id, 文档数) 为代际标识 —— 热切换(引擎对象换)或
#   快车道增量入索引(文档数变)都会自动落到新的 key，不会读到过期结果。
# ==========================================================================
SEARCH_CACHE = OrderedDict()      # (gen, 查询串) -> 检索结果 dict
SEARCH_CACHE_MAX = 64             # 约几十条结果，内存可控
CORPUS_CACHE = {}                 # gen -> 已序列化的 /api/corpus 响应（16MB，别每次重建）
CRED_CACHE = {}                   # gen -> 已序列化的 /api/credibility 响应


def _cache_gen():
    eng = get_engine()
    return (id(eng), getattr(eng, "N", len(eng.docs)))


def search_cached(qkey, compute):
    """检索结果 LRU 缓存；命中时把 elapsed_ms 改成真实耗时并标记 cached=True。"""
    gen = _cache_gen()
    key = (gen, qkey)
    hit = SEARCH_CACHE.get(key)
    if hit is not None:
        SEARCH_CACHE.move_to_end(key)
        out = dict(hit)
        out["elapsed_ms"] = 0.0
        out["cached"] = True
        return out
    d = compute()
    SEARCH_CACHE[key] = d
    SEARCH_CACHE.move_to_end(key)
    while len(SEARCH_CACHE) > SEARCH_CACHE_MAX:
        SEARCH_CACHE.popitem(last=False)
    out = dict(d)
    out["cached"] = False
    return out


def get_corpus_light():
    """/api/corpus：88k 条清单每次重建要 0.3~0.5s 且 16MB，按代际缓存"""
    gen = _cache_gen()
    if gen not in CORPUS_CACHE:
        eng = get_engine()
        light = [{"id": d["id"], "published": d["published"][:10], "score": d["cvss"]["score"],
                  "severity": d["cvss"]["severity"], "category": d["category"],
                  "products": d.get("products", [])[:4], "exploited": bool(d.get("kev"))}
                 for d in eng.docs]
        CORPUS_CACHE[gen] = json.dumps({"total": len(light), "items": light},
                                       ensure_ascii=False).encode("utf-8")
    return CORPUS_CACHE[gen]


def get_credibility():
    """/api/credibility：全库可信度统计（~0.14s），同一代语料只算一次"""
    gen = _cache_gen()
    if gen not in CRED_CACHE:
        eng = get_engine()
        ensure_credibility(eng)
        CRED_CACHE[gen] = json.dumps(CR.credibility_stats(eng.docs),
                                      ensure_ascii=False).encode("utf-8")
    return CRED_CACHE[gen]


def clear_response_caches():
    """引擎热切换后调用：旧代际的结果一律作废"""
    STATS_CACHE.clear()
    SEARCH_CACHE.clear()
    CORPUS_CACHE.clear()
    CRED_CACHE.clear()


# 演示高频查询（与首页示例查询一致）：启动后后台跑一遍进缓存，演示时第一条就是热的
WARM_QUERIES = ["", "ollama 远程代码执行", "提示词注入的修复建议", "已被在野利用的漏洞",
                "vLLM 高危漏洞影响哪些版本", "渗透测试开源工具有哪些"]


def _warmup_sync(t=None):
    """**同步预热**：在端口绑定**之前**执行的重活（嵌入模型 + 向量矩阵）。

    ★ 为什么必须挪到端口之前（实测，2026-10-07）：
      原实现把 `_warmup` 起在**端口已开之后**的后台线程里，而它要花约 47s
      （实测时间线：端口 15.3s 可用 → 模型 41.7s 才加载完 → 46.9s 预热结束）。
      用户在这 30 多秒里一点开页面就问，请求**排队在预热线程后面**，
      首问实测 **31.93s**，而预热结束后再问只要 **2.02s**。
      用户看到的是"问答卡死半分钟"，根本原因却是"预热把请求堵住了"。

      把这段重活挪到端口绑定之前后，用户能点的时候系统**本来就是热的**，
      首问即 2s 级。代价是"控制台已启动"这行字晚出现约 30s ——
      但那是**一段诚实的等待**，比"看起来启好了、一问就卡"好得多。

      可用 AISEC_WARM_SYNC=0 关掉（退回旧的异步预热，慢机器可留给用户自己权衡）。
    """
    import time as _t
    _t0 = _t.time()
    # ① 语义向量模型（约 10s，实测 9.7s）
    _env_embed = os.environ.get("AISEC_WARM_EMBED")
    if _env_embed is not None:
        _warm_embed = _env_embed not in ("0", "false", "False")
    else:
        _warm_embed = t.enabled("embed_warmup", default=True) if t else True
    if _warm_embed:
        try:
            from qa.local_embedder import local_embedder
            if local_embedder.ensure():
                local_embedder.encode(["预热"], kind="query")
                print("  语义向量模型已就绪（%.1fs）" % (_t.time() - _t0), flush=True)
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("core/server.py:warmup_sync-embed", _sw_e)
        # ② 向量矩阵（mmap 118348×384，首问页错误）
        try:
            from qa.vector_store import vector_store
            _r = vector_store.warm()
            if _r.get("ok"):
                print("  向量矩阵已进内存：%d 行（%.1fs）" %
                      (_r.get("rows") or 0, _t.time() - _t0), flush=True)
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("core/server.py:warmup_sync-vector", _sw_e)


def _warmup(port=8848):
    """启动预热（后台线程，失败一律静默，绝不拖慢/阻断启动）。

    8.8 万条语料下，全库分面与答复卡聚合首次计算约 0.6s、常用检索冷启约 0.5~1.2s；
    提前算好并写入结果缓存后，用户打开控制台的第一条检索就是毫秒级（2026-09-28）。

    注意：**重活（模型/向量矩阵）已挪到 `_warmup_sync`，在端口开之前跑完**；
    这里只剩"全库聚合 + 常用检索入缓存"这类轻量且可异步的工作。
    若 `AISEC_WARM_SYNC=0`，本函数仍会兜底做一次模型/矩阵预热（保持旧行为可用）。

    慢机器适配（core/envprofile.py）：预热本身也是负载——
      · 低配档跳过语义模型预热（torch 约 470MB、加载 16s，慢机器上白占资源）
      · 低配档只预热 2 条高频查询（原本 6 条）
      · 预热请求超时按档放大（慢机器 120s 不够，会白跑一轮）
    """
    import urllib.parse
    import urllib.request
    _t = T if T is not None else None
    _sync = os.environ.get("AISEC_WARM_SYNC", "1") not in ("0", "false", "False")
    time.sleep(_t.timeout(6) if _t else 6)          # 等端口真正开始服务
    try:
        eng = get_engine()
        eng._facets_fast(range(eng.N))              # 全库分面缓存
        eng._aggregate(range(eng.N))                # 答复卡聚合缓存
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("core/server.py:343", _sw_e)

    # 语义向量模型 + 向量矩阵：正常情况下已在 `_warmup_sync` 里（端口前）跑完；
    # 只有显式关掉同步预热（AISEC_WARM_SYNC=0）时才在这里兜底。
    if not _sync:
        _warmup_sync(_t)

    base = os.environ.get("AISEC_MAIN_SERVER") or f"http://127.0.0.1:{port}"
    # 显式绕过代理：环境里可能配了 AISEC_PROXY/HTTP_PROXY，回环请求不该走代理
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    # 低配档只预热最高频的前 2 条（预热是"为了让首屏快"，但它本身也要花时间）
    _nq = (_t.value("warm_queries", 6) if _t else 6) or 6
    _to = _t.timeout(120, minimum=120) if _t else 120
    for q in WARM_QUERIES[:max(1, int(_nq))]:
        try:
            opener.open(base + "/api/search?q=" + urllib.parse.quote(q), timeout=_to).read()
        except Exception:  # noqa: BLE001
            break
    print("[warmup] 预热处理完成（全库聚合 + 常用查询已入缓存）", flush=True)


def load_static(full):
    """静态资源缓存（内存 + ETag/304），文件变化时自动失效"""
    try:
        st = os.stat(full)
    except OSError:
        return None
    key = (full, st.st_mtime, st.st_size)
    hit = STATIC_CACHE.get(full)
    if hit and hit[0] == key:
        return hit
    with open(full, "rb") as f:
        body = f.read()
    etag = '"' + hashlib.sha1(body).hexdigest()[:16] + '"'
    gz = gzip.compress(body, 6)
    item = (key, body, gz, etag)
    STATIC_CACHE[full] = item
    return item



class Handler(BaseHTTPRequestHandler):
    server_version = "AISecIntel/2.3"
    core = CORE                        # 模块 handler 通过 req.engine 取引擎
    registry = None                    # 启动时指向 REGISTRY（延迟绑定）
    protocol_version = "HTTP/1.1"          # keep-alive

    def log_message(self, fmt, *args):  # 降噪
        path = getattr(self, "path", "") or ""
        if "/api/" in path:
            sys.stderr.write("[api] %s %s\n" % (self.command, path))

    # ------------------------------------------------------------------
    def _accepts_gzip(self):
        return "gzip" in (self.headers.get("Accept-Encoding") or "")

    def _send(self, code, body, ctype="application/json; charset=utf-8",
              etag=None, cache=None, gz_allowed=True, filename=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        head_gz = False
        if gz_allowed and len(body) > 1024 and self._accepts_gzip():
            body = gzip.compress(body, 6)
            head_gz = True
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if head_gz:
            self.send_header("Content-Encoding", "gzip")
        if etag:
            self.send_header("ETag", etag)
        self.send_header("Cache-Control", cache or "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        if filename:
            # ★ Content-Disposition: attachment 让浏览器直接落盘而不是内联预览。
            #   文件名含中文时必须用 RFC 5987 的 filename*=UTF-8''... 形式，
            #   同时给一个 ASCII 兜底名（老 IE / 部分客户端只认 filename=）。
            safe = str(filename).replace("\\", "_").replace("/", "_").replace('"', "_")
            ascii_name = re.sub(r"[^\x20-\x7e]", "_", safe).strip() or "download"
            self.send_header(
                "Content-Disposition",
                "attachment; filename=\"%s\"; filename*=UTF-8''%s"
                % (ascii_name, urllib.parse.quote(safe)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200, etag=None):
        self._send(code, json.dumps(obj, ensure_ascii=False), etag=etag)

    # ------------------------------------------------------------------
    # 每日报告（AI 安全四方向 + 四模块台账，core/daily_digest.py）
    # ------------------------------------------------------------------
    def _daily_digest(self, path, qs):
        """跨模块聚合的每日报告。放在 core 是因为它同时读四个模块的产物。

        下载分支与 `modules/m1_monitor/api.py` 的日报**共用同一套判据**：
        "查得到"和"能下载"必须一致，否则会出现「列表说没有、点下载却给一份
        现场渲染的空报告」这种自相矛盾 —— 拿到手的是标题写着那天、生成时间
        却是当前时刻的假报告。
        """
        q1 = lambda k, d="": ((qs.get(k) or [d])[0] or d)  # noqa: E731
        try:
            import daily_digest as DG
        except Exception as e:  # noqa: BLE001
            return self._json({"error": "每日报告引擎未就绪：%s" % str(e)[:160]}, 500)

        sub = path[len("/api/daily_digest"):].strip("/")

        # 通知（提醒条）
        if sub == "notifications":
            return self._json(DG.notifications(
                limit=q1("limit", 20) or 20,
                unread_only=q1("unread") in ("1", "true")))
        if sub == "status":
            return self._json(DG.status())

        # ── 分流靠「有没有 module 参数」，不靠 sub 猜 ──
        #   ★ 踩过的坑：sub 对 `/api/daily_digest` 来说是 ""，而
        #     `sub in ("", "/list")` 会把 "" 吃掉，于是详情/下载分支永远进不去
        #     —— 接口不报错，只是**永远返回列表**。zip 更惨：拿到列表 JSON
        #     却标着 application/zip，浏览器存下来解不开。
        #   现在：带 module 或 fmt → 详情/下载；否则 → 列表。
        fmt = (q1("fmt") or "").lower().strip()
        mid_q = (q1("module") or "").strip()
        want_one = bool(mid_q) or bool(fmt) or sub in ("one", "/one")

        # 列表：每天 × 四模块 的格子
        if not want_one and (sub in ("", "/", "list", "/list")):
            days = q1("days") or (DG.RETENTION_DAYS + 5)
            return self._json(DG.list_all(days=days))

        # 详情 / 下载：/api/daily_digest?module=m1_monitor&date=…[&fmt=md|json]
        #            /api/daily_digest?date=…&fmt=zip  （当天四份一次打包）
        if want_one:
            if fmt and fmt not in ("md", "json", "zip"):
                return self._json({"error": "fmt 只支持 md / json / zip"}, 400)
            date = q1("date")
            if date and not DG.valid_date(date):
                return self._json({"error": "date 应为 YYYY-MM-DD"}, 400)
            day = DG.valid_date(date) or DG.target_date()

            # ── zip：把当天四份一次打包（**跨模块**，所以不需要 module 参数）──
            # 与单份下载共用同一套判据：当天一个模块都没有 → 404，
            # 不打一个只有 README 的空包（那正是"看着像样、实则没用"的假交付）。
            if fmt == "zip":
                mid_fmt = (q1("fmts") or "md,json").lower()
                want = tuple(f.strip() for f in mid_fmt.split(",")
                             if f.strip() in ("md", "json")) or ("md", "json")
                payload, included = DG.build_zip(day, want)
                if not payload or not included:
                    return self._json({
                        "ok": False, "error": "该日期没有任何方向报告，无法打包",
                        "date": day, "empty_reason": "no_data",
                    }, 404)
                return self._send(200, payload, "application/zip",
                                  filename="AI安全每日报告_%s.zip" % day,
                                  cache="no-store")

            mid = (q1("module") or "").strip()
            if not mid:
                return self._json({"error": "缺少 module 参数"}, 400)
            # ENTRY_NAME = 四模块 + AI 安全四方向（两者走同一条详情/下载链路）
            if mid not in DG.ENTRY_NAME:
                return self._json({"error": "未知条目 %s，可选：%s"
                                          % (mid, "、".join(DG.ENTRY_NAME))}, 400)
            saved = [f for f in ("md", "json")
                      if os.path.isfile(DG._path(mid, day, f))]
            rep = DG.load(mid, day)
            if rep is None:
                # 没有任何产出 —— 不造占位报告（与 m1 日报同一原则）
                return self._json({
                    "ok": False, "error": "该模块该日没有报告",
                    "module": mid, "date": day,
                    "empty_reason": "no_data",
                    "available_formats": saved,
                }, 404)
            if not fmt:
                rep = dict(rep)
                rep["available_formats"] = saved
                rep["retention_days"] = DG.RETENTION_DAYS
                return self._json(rep)
            # 有报告才允许下载；顺带确保落盘（有数据但还没写文件的补写一次）
            if not saved:
                try:
                    DG.save(rep)
                except Exception as e:  # noqa: BLE001
                    print("[daily_digest] 落盘失败，仍直接下载：%s" % e)
            fp = DG._path(mid, day, fmt)
            if not os.path.isfile(fp):
                payload = (DG.render_markdown(rep).encode("utf-8")
                           if fmt == "md"
                           else json.dumps(rep, ensure_ascii=False, indent=1).encode("utf-8"))
            else:
                with open(fp, "rb") as f:
                    payload = f.read()
            fname = "%s每日报告_%s.%s" % (rep.get("module_name", mid), day, fmt)
            return self._send(200, payload, DG.MIME[fmt], filename=fname,
                              cache="no-store")

        return self._json({"error": "unknown api", "path": path}, 404)

    def _daily_digest_post(self, path, qs, body):
        """POST：生成 / 清理 / 补齐 / 通知已读。"""
        q1 = lambda k, d="": ((qs.get(k) or [d])[0] or d)  # noqa: E731
        try:
            import daily_digest as DG
        except Exception as e:  # noqa: BLE001
            return self._json({"error": "每日报告引擎未就绪：%s" % str(e)[:160]}, 500)
        sub = path[len("/api/daily_digest"):].strip("/")
        try:
            data = json.loads(body.decode("utf-8")) if body else {}
            if not isinstance(data, dict):
                data = {}
        except Exception:  # noqa: BLE001
            data = {}
        try:
            # status 在 GET 侧也提供，这里一并放行 —— 同一个能力两种动词
            # 不该一个通一个 404（实测踩过：前端哪天改成 POST 就静默失败）
            if sub == "status":
                return self._json(DG.status())
            if sub == "generate":
                date = (data.get("date") or "").strip()
                if date and not DG.valid_date(date):
                    return self._json({"ok": False, "error": "日期格式应为 YYYY-MM-DD"}, 400)
                only_missing = bool(data.get("only_missing"))
                r = DG.generate_all(DG.valid_date(date) or None,
                                    only_missing=only_missing,
                                    notify=bool(data.get("notify", True)))
                return self._json(r)
            if sub == "catch_up":
                return self._json(DG.catch_up(days=data.get("days"),
                                              notify=bool(data.get("notify"))))
            if sub == "cleanup":
                return self._json(DG.cleanup(dry_run=bool(data.get("dry_run"))))
            if sub == "notifications/read":
                ids = data.get("ids")
                return self._json(DG.mark_read(ids if isinstance(ids, list) else None))
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            return self._json({"ok": False, "error": str(e)[:200]}, 500)
        return self._json({"error": "unknown api", "path": path}, 404)

    # ------------------------------------------------------------------
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        _t0 = time.time()
        _code = 200
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = urllib.parse.unquote(parsed.path)
            qs = urllib.parse.parse_qs(parsed.query)

            if path.startswith("/api/") or path.startswith("/taxii2/"):
                return self._api(path, qs)
            return self._static(path)
        except BrokenPipeError as _sw_e:
            _code = 499
            _swallow("core/server.py:443", _sw_e)
        except ConnectionError as _sw_e:
            _code = 499
            _swallow("core/server.py:445", _sw_e)
        except Exception as e:  # noqa: BLE001
            _code = 500
            import traceback
            traceback.print_exc()
            self._json({"error": str(e)}, 500)
        finally:
            # 请求耗时/错误采样（喂给 /api/metrics 的 P95 与错误率告警）。
            # 放 finally：客户端提前断开也要计入，否则错误率会被
            # "连上才处理" 的样本稀释掉。
            try:
                metrics.latency.observe(metrics._route_of(getattr(self, "path", "")),
                                         (time.time() - _t0) * 1000.0,
                                         _code >= 500)
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    def _api(self, path, qs):
        # —— /api/metrics：基础设施指标 + 阈值告警（运维监控/评审核验用）——
        #   ?fmt=prometheus 返回 Prometheus 文本格式，可直接被采集器抓。
        # 放在 get_engine() 之前：监控端点绝不能被冷启动的语料加载阻塞
        # （否则监控自己先超时，等于没有监控）。
        if path == "/api/metrics":
            fmt = (qs.get("fmt") or ["json"])[0].lower()
            try:
                if fmt in ("prometheus", "prom", "text"):
                    return self._send(200, metrics.prometheus(),
                                      ctype="text/plain; version=0.0.4; charset=utf-8")
                return self._json(metrics.report())
            except Exception as e:  # noqa: BLE001
                return self._json({"error": str(e)}, 500)

        # —— /api/health：健康检查（容器 healthcheck / 运维监控用）——
        # 刻意放在 get_engine() 之前：冷启动首次加载语料要几十秒，
        # 健康检查不能被引擎加载阻塞，否则容器会被误判不健康而反复重启。
        if path == "/api/health":
            eng_loaded = False
            docs = 0
            try:
                eng = ENGINE
                eng_loaded = eng is not None
                docs = getattr(eng, "N", 0) if eng_loaded else 0
            except Exception:  # noqa: BLE001
                eng_loaded = False
            body = {
                "ok": True,
                "status": "serving",
                "version": self.server_version.split("/")[-1] if self.server_version else "",
                "uptime_sec": round(time.time() - _START_TS, 1),
                "engine_loaded": eng_loaded,
                "docs": docs,
                "threads": threading.active_count(),
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            # 告警并进健康检查：只在 critical 时把 ok 拉低，warn 不影响
            # （磁盘 90% 这种还不该被判死；但要看得到）。
            # 此前 /api/health 无论磁盘满、采集线程死都恒返回 ok —— 假健康。
            try:
                _alerts, lvl = metrics.evaluate()
                body["alert_level"] = lvl
                body["alerts"] = [a["key"] for a in _alerts]
                if lvl == "critical":
                    body["ok"] = False
                    body["status"] = "degraded"
            except Exception:  # noqa: BLE001
                pass
            # —— LLM 能力自证（v2.2）——
            # 刻意**不**因此把 ok 拉低：没有 Key 时服务完全正常，只是回答走模板。
            # 把它算作"不健康"会导致容器 healthcheck 反复重启健康的实例。
            # 但必须 visible：否则"智能体自主决策"在默认部署下名存实亡却看不出来。
            try:
                body["llm"] = llm_status()
            except Exception:  # noqa: BLE001
                pass
            # —— 采集源熔断状态（自愈闭环自证）——
            # 此前"源挂了"只在采集日志里，接口层完全看不到；现在熔断的源、
            # 冷却剩余秒数、有无可用镜像都进健康检查。
            try:
                from core import circuit as _circuit
                _cs = _circuit.breaker().snapshot()
                body["circuit"] = _cs
                _tripped = [k for k, v in _cs.items() if v.get("state") == "tripped"]
                if _tripped:
                    body["sources_tripped"] = _tripped
            except Exception:  # noqa: BLE001
                pass
            return self._json(body)

        # —— 四模块每日报告（core/daily_digest.py）——
        #   跨模块聚合，所以放 core 而不是某个模块的 api.py。
        #   与 /api/metrics 同样放在 get_engine() 之前：日报读的是已落盘的
        #   jsonl / json，不依赖内存引擎，冷启动期间也必须能查。
        if path.startswith("/api/daily_digest"):
            return self._daily_digest(path, qs)

        eng = get_engine()

        if path == "/api/stats":
            raw, etag = get_stats()
            if (self.headers.get("If-None-Match") or "") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self._send(200, raw, etag=etag, cache="public, max-age=60")

        if path == "/api/search":
            q = (qs.get("q") or [""])[0]
            filters = {
                "severity": qs.get("severity", []),
                "category": qs.get("category", []),
                "source": qs.get("source", []),
                "scope": qs.get("scope", []),
                "exploited_only": (qs.get("exploited", ["0"])[0] == "1"),
                "poc_only": (qs.get("poc", ["0"])[0] == "1"),
                "has_paper_only": (qs.get("paper", ["0"])[0] == "1"),
                "cvss_min": _float_param(qs, "cvss_min"),
                "year_from": _int_param(qs, "year_from", None),
                "year_to": _int_param(qs, "year_to", None),
            }
            size = _int_param(qs, "size", 12, lo=1, hi=60)
            page = _int_param(qs, "page", 1, lo=1)
            sort = (qs.get("sort") or ["relevance"])[0]
            expand = (qs.get("expand", ["1"])[0] != "0")
            # 缓存键覆盖全部会影响结果的入参（含多值筛选，按排序后拼接保证稳定）
            def _fkey(name):
                return ",".join(sorted(qs.get(name, [])))
            ckey = "|".join([q, str(size), str(page), sort, "1" if expand else "0",
                             _fkey("severity"), _fkey("category"), _fkey("source"), _fkey("scope"),
                             qs.get("exploited", ["0"])[0], qs.get("poc", ["0"])[0],
                             qs.get("paper", ["0"])[0], (qs.get("cvss_min") or [""])[0],
                             (qs.get("year_from") or [""])[0], (qs.get("year_to") or [""])[0]])
            return self._json(search_cached(
                ckey, lambda: eng.search(q, filters, top_k=size, sort=sort, page=page, expand=expand)))

        if path == "/api/detail":
            cid = (qs.get("id") or [""])[0]
            d = eng.detail(cid)
            if not d:
                return self._json({"error": "not found", "id": cid}, 404)
            return self._json(detail_payload(d))

        if path == "/api/suggest":
            q = (qs.get("q") or [""])[0]
            return self._json(eng.suggest(q))

        if path == "/api/corpus":
            # 供前端/工具做离线筛选的轻量清单（88k 条，按代际缓存，不每次重建）
            return self._send(200, get_corpus_light(),
                              etag='"' + hashlib.sha1(get_corpus_light()).hexdigest()[:16] + '"',
                              cache="public, max-age=60")

        if path == "/api/latest":
            # hi 上限 60→200（2026-09-30）：实时监测面板「展开更多」要看更长的时间轴，
            # 60 条在今天这种更新量下只够覆盖半天。latest() 走的是预排好的 _by_pub_desc
            # 游标，取多少条都是线性切片，200 条实测仍在毫秒级。
            n = _int_param(qs, "n", 14, lo=1, hi=200)
            return self._json(eng.latest(n))

        if path == "/api/related":
            cid = (qs.get("id") or [""])[0]
            ensure_credibility(eng)
            rel = GD.find_related(cid, eng.docs, index=related_index(eng))
            if rel is None:
                return self._json({"error": "not found", "id": cid}, 404)
            return self._json(rel)

        if path == "/api/graph":
            cid = (qs.get("id") or [""])[0]
            d = eng.detail(cid)
            if not d:
                return self._json({"error": "not found", "id": cid}, 404)
            # CTI 知识图谱多跳关联：CVE ↔ 组件 ↔ 资产 ↔ 攻击技术（hops 控制游走深度）
            hops = _int_param(qs, "hops", 2, lo=1, hi=2)
            try:
                idx = related_index(eng)
                return self._json(GD.build_graph_multi(d, eng.docs, index=idx,
                                                       max_hops=hops))
            except Exception as e:  # noqa: BLE001
                # 多跳构建异常时降级为单跳星形图（向后兼容，不影响可用性）
                _swallow("core/server.py:/api/graph", e)
                return self._json(GD.build_graph(d))

        if path == "/api/credibility":
            return self._send(200, get_credibility())

        if path == "/api/export":
            ensure_credibility(eng)
            # 单条详情报告
            if qs.get("id"):
                d = eng.detail(qs["id"][0])
                if not d:
                    return self._json({"error": "not found"}, 404)
                md = RPT.export_detail_report(d)
                fname = qs["id"][0]
            else:
                # 搜索结果报告
                eq = (qs.get("q") or [""])[0]
                size = _int_param(qs, "size", 30, lo=1, hi=60)
                sd = eng.search(eq, {}, top_k=size)
                md = RPT.export_search_report(eq, sd)
                fname = "search"
            payload = md.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Disposition",
                             'attachment; filename="secintel_' + fname + '.md"')
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
            return

        # ------------------------------------------------------------------
        # 模块路由：由 modules/<id>/api.py 在启动时注册，这里统一分发。
        # 模块文件夹没放进来 / 被 config.json 禁用 → 自动 404，主体照常运行。
        if path == "/api/modules":
            # 模块装载情况（前端、运维、核查脚本都用这个确认"模块真的进来了"）
            if REGISTRY is None:
                return self._json({"count": 0, "modules": [], "skipped": {},
                                   "note": "本次启动未加载模块（--no-modules）"})
            mods = [{"id": mid, "name": ctx.name, "owner": ctx.owner,
                     "routes": ctx.manifest.get("routes", []),
                     "web": ctx.manifest.get("web", [])}
                    for mid, ctx in REGISTRY.modules.items()]
            return self._json({"count": len(mods), "modules": mods,
                               "skipped": REGISTRY.skipped})

        try:
            req = Request(self, "GET", path, qs)
            if REGISTRY is not None and REGISTRY.dispatch(req):
                return
        except BrokenPipeError:
            return
        except Exception as e:                                        # noqa: BLE001
            import traceback
            traceback.print_exc()
            return self._json({"error": str(e)}, 500)

        return self._json({"error": "unknown api", "path": path}, 404)

    # ------------------------------------------------------------------
    def do_POST(self):
        req = None
        _pt0 = time.time()
        _pcode = 200
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = urllib.parse.unquote(parsed.path)
            qs = urllib.parse.parse_qs(parsed.query)
            length = int(self.headers.get("Content-Length") or 0)
            # ★ 请求体硬上限（2026-10-06）：超过就明确回 413。
            #   原来没有任何上限，688MB 的 CMDB 全量库会被 `rfile.read(length)`
            #   一次性读进内存，峰值内存是文件体积的 2~3 倍 → 服务端进程直接被
            #   系统或连接重置掉，浏览器侧只能看到 "Failed to fetch"，
            #   连 HTTP 状态码都拿不到，用户完全无从判断是自己库太大还是服务挂了。
            #   有上限后至少能返回一个说人话的 413。
            if length > (LARGE_BODY if path in LARGE_BODY_PATHS else MAX_BODY):
                return self._json({
                    "ok": False,
                    "error": "请求体 %.1f MB 超过单次上限 %d MB；请分批上传或改用"
                             "「库在服务器上？直接填路径」方式指向该文件"
                             % (length / 1048576.0,
                                (LARGE_BODY if path in LARGE_BODY_PATHS else MAX_BODY) // 1048576),
                }, 413)
            # 中等体积以上（>32MB）走零拷贝流式：直接把 socket 交给 handler 边收边切分，
            # 磁盘只写一次（最终那 N 个 .db）。详见 registry.Request.begin_stream 的说明。
            req = Request(self, "POST", path, qs)
            if not req.begin_stream(length, self.rfile):
                req.body = self.rfile.read(length) if length else b""
            # 四模块每日报告的写操作（生成/补齐/清理/通知已读）放 core，
            # 与它的 GET 侧同一处，不要拆到某个模块里。
            if path.startswith("/api/daily_digest"):
                if req.body is None:
                    req.body = b""
                return self._daily_digest_post(path, qs, req.body)
            if REGISTRY is not None and REGISTRY.dispatch(req):
                return
            return self._json({"error": "unknown api", "path": path}, 404)
        except BrokenPipeError as _sw_e:
            _pcode = 499
            _swallow("core/server.py:605", _sw_e)
        except (ConnectionError, ConnectionResetError, ConnectionAbortedError) as _sw_e:
            # ★ do_GET 一直有这层保护，do_POST 原来只有 BrokenPipeError。
            #   大文件上传（几百 MB）分析完写响应时客户端很可能已经超时断开，
            #   抛的是 ConnectionError 系列而不是 BrokenPipeError → 直接冒到
            #   socketserver 层，**一个字节的响应都发不出去**，
            #   浏览器侧表现为 RemoteDisconnected / Failed to fetch，
            #   服务端日志里也看不到 traceback，极难定位。
            _pcode = 499
            _swallow("core/server.py:do_POST.conn", _sw_e)
        except MemoryError as _sw_e:
            # 响应体过大时 json.dumps / gzip 可能撑爆内存，同样要让日志留下痕迹
            _pcode = 500
            _swallow("core/server.py:do_POST.memory", _sw_e)
            try:
                self._json({"ok": False, "error": "报告体积过大，服务端内存不足；"
                                                 "请减少一次上传的数据量或改用路径方式"}, 500)
            except Exception as _sw2:  # noqa: BLE001
                _swallow("core/server.py:do_POST.memory.send", _sw2)
        except Exception as e:                                        # noqa: BLE001
            _pcode = 500
            import traceback
            traceback.print_exc()
            try:
                self._json({"error": str(e)}, 500)
            except Exception as _sw_e:  # noqa: BLE001
                _swallow("core/server.py:612", _sw_e)
        finally:
            # 与 do_GET 同一套耗时/错误采样（上传类接口的 P95 最需要看）
            try:
                metrics.latency.observe(metrics._route_of(getattr(self, "path", "")),
                                         (time.time() - _pt0) * 1000.0,
                                         _pcode >= 500)
            except Exception:  # noqa: BLE001
                pass
            if req is not None:
                try:
                    req.finish_stream()
                except Exception as _sw_e:
                    _swallow("core/server.py:finish_stream", _sw_e)

    # ------------------------------------------------------------------
    def _static_candidates(self, rel):
        """静态资源解析顺序（前端的唯一根是 ``frontend/``）：

        ① ``frontend/<rel>``                 —— 外壳 index.html/styles.css/app.js
                                                与组装好的 /modules/<id>/panel.js
        ② ``frontend/modules/<id>/<file>``   —— 老 URL ``/modules/<id>/web/panel.js`` 映射过来
        ③ ``<项目根>/<rel>``                  —— 模块源目录兜底（没跑 tools/组装前端.py 也不 404）

        返回 [(根, 相对路径], 调用方逐项做越界校验后取第一个真实存在的文件。
        """
        out = [(WEB, rel)]
        if rel.startswith("modules/"):
            parts = rel.split("/")
            if len(parts) >= 3:                      # modules/<id>/web/panel.js → <id> + 文件名
                out.append((os.path.join(WEB, "modules"), parts[1] + "/" + parts[-1]))
            out.append((paths.ROOT, rel))
        return out

    def _resolve_static(self, rel):
        for root, sub in self._static_candidates(rel):
            full = os.path.normpath(os.path.join(root, sub))
            guard = os.path.normpath(root) + os.sep
            if not full.startswith(guard):
                continue                             # 越界（../ 之类）直接跳过
            if os.path.isfile(full):
                return full
        return None

    def _static(self, path):
        """静态资源：只服务 frontend/ 这一个前端根（含组装进来的模块面板）；
        index.html 里的 ``<!--@modules-->`` 会被替换成各模块的前端脚本标签。"""
        if path in ("/", ""):
            path = "/index.html"
        rel = path.lstrip("/")
        if ".." in rel:
            return self._send(403, "forbidden", "text/plain; charset=utf-8", gz_allowed=False)
        full = self._resolve_static(rel)
        if full is None:
            return self._send(404, "not found: " + rel, "text/plain; charset=utf-8", gz_allowed=False)
        ext = os.path.splitext(full)[1].lower()
        item = load_static(full)
        if item is None:
            return self._send(404, "gone", "text/plain; charset=utf-8", gz_allowed=False)
        _key, body, gz, etag = item
        if rel == "index.html" and b"<!--@modules-->" in body:
            body = self._inject_modules(body)
            gz = gzip.compress(body, 6)
            etag = '"' + hashlib.sha1(body).hexdigest()[:16] + '"'
        # ★ HTML 走 no-cache（=「可缓存但每次使用前必须重验证」，配 ETag 命中即 304，开销极小）。
        #   此前 HTML 与 JS/CSS 同为 max-age=600，后果是：改完前端后 10 分钟内
        #   浏览器连新的 index.html 都不来取 —— index.html 里递增的 ?v= 号也跟着失效，
        #   用户必须强制刷新才可能看到改动，白白以为"优化没效果"。
        #   现在：HTML 每次重验证（内容没变就是一次轻量 304），
        #   JS/CSS 继续靠 index.html 里的 ?v= 做长缓存。这是前端缓存的标准分工。
        cache = "no-cache" if ext == ".html" else "public, max-age=600"
        if (self.headers.get("If-None-Match") or "") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", cache)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        ctype = MIME.get(ext, "application/octet-stream")
        gz_ok = ext in (".html", ".js", ".css", ".json", ".svg")
        if gz_ok and self._accepts_gzip():
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(gz)))
            self.send_header("Content-Encoding", "gzip")
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", cache)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(gz)
        else:
            self._send(200, body, ctype, etag=etag, cache=cache, gz_allowed=False)

    def _inject_modules(self, body):
        """把 <!--@modules--> 替换成各模块的 <script>（浏览器按顺序执行，
        模块面板脚本因此可以放心使用主体 app.js 暴露的全局能力）。"""
        scripts, ids = [], []
        if REGISTRY is not None:
            for url, _fp in REGISTRY.web_scripts():
                if url.endswith(".css"):
                    scripts.append(f'<link rel="stylesheet" href="{url}">')
                else:
                    scripts.append(f'<script src="{url}"></script>')
            ids = [{"id": m, "name": c.name, "owner": c.owner}
                   for m, c in REGISTRY.modules.items()]
        boot = ("<script>window.AISEC_MODULES=" +
                json.dumps(ids, ensure_ascii=False) + ";</script>")
        html = body.decode("utf-8").replace("<!--@modules-->", boot + "\n" + "\n".join(scripts))
        return html.encode("utf-8")

    def do_HEAD(self):
        self.do_GET()


def _port_in_use(port, host="127.0.0.1"):
    """端口上是否已有服务在监听。

    为什么不能只靠 bind 报错：Windows 上 SO_REUSEADDR 允许两个进程同时绑定同一端口，
    第二个进程会「假启动成功」，请求仍落到旧实例 —— 于是新的代码改动看起来没生效。
    用 connect 主动探测才是可靠的判据。
    """
    import socket as _socket
    with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, int(port))) == 0


def _load_secrets_env() -> list:
    """兜底加载本机 secrets.env —— 让"直接 python core/server.py"启动也能拿到密钥。

    为什么需要：密钥文件历来靠**启动脚本**注入环境变量
    （启动服务.bat 的 for/findstr、tools/_start_detached.py、compose 的 env_file）。
    一旦有人按文档里那句 `python core/server.py 8848` 直接起服务，这些值就没人注入，
    表现是"明明在 secrets.env 里填了 SMTP / LLM Key，界面却说未配置"——
    这类问题很难自查，因为文件确实是对的。

    用的是 setdefault 语义（已有环境变量优先），所以：
      · 启动脚本注入的值不受影响；
      · 容器里 compose/env_file 的显式配置仍然说了算；
      · 只在"确实没人设过"时才从本机文件补上。

    返回补载的键名列表（**不返回值**，避免密钥进日志）。
    """
    fp = os.path.join(paths.ROOT, "secrets.env")
    if not os.path.exists(fp):
        return []
    loaded: list = []
    try:
        with open(fp, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip().lstrip("\ufeff")
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k and v and not os.environ.get(k):
                    os.environ[k] = v
                    loaded.append(k)
    except Exception as _e:  # noqa: BLE001
        _swallow("core/server.py:_load_secrets_env", _e)
    return loaded


def llm_status() -> dict:
    """大模型（Tool-Calling Agent / LLM 生成）当前**是否真的在跑**，供 /api/health 自证。

    为什么必须有这个：此前「无 AISEC_LLM_API_KEY → 静默降级为模板/规则」是**无声**的。
    接口照常 200、答案照常返回，只是全部来自检索证据模板 —— 从外面完全看不出差别，
    评审/用户只能靠"我觉得回答变差了"来判断。这有两个害处：
      1. 对外宣称「智能体自主决策」时，实际可能是模板在答 —— 能力被高估；
      2. 降级了没人知道，key 填错/没注入也一直不修。

    所以把「enabled / degraded / reason / key 长度」显式写进健康检查。
    注意 `env_key: False` 不是"配错了"，而是**正确行为**：`_load_secrets_env()`
    对空值会跳过（`if k and v`），AISEC_LLM_API_KEY= 空串时不该算"配了"。
    判断依据是**值的长度**，不是"变量存不存在"。
    """
    cfg = {}
    try:
        # 延迟导入：m3_qa 是可选模块，health 不能因它 import 失败而挂掉。
        # 依赖 modules/ 是 namespace package 且项目根目录已进 sys.path（见文件头）。
        from modules.m3_qa.api import env_llm_config
        cfg = env_llm_config() or {}
    except Exception as _e:  # noqa: BLE001
        _swallow("core/server.py:llm_status", _e)
        return {"enabled": False, "degraded": True, "reason": "m3_qa 模块不可用",
                "model": "", "base_url": "", "key_len": 0}

    key = (cfg.get("api_key") or "").strip()
    model = (cfg.get("model") or "").strip()
    base = (cfg.get("base_url") or "").strip()
    enabled = bool(key)
    st = {
        "enabled": enabled,
        "degraded": not enabled,
        "reason": "" if enabled else
                  "未配置 AISEC_LLM_API_KEY —— 问答与简报降级为「检索证据模板」，"
                  "Tool-Calling Agent 自主决策不生效（非故障，属预期降级）",
        "model": model,
        "base_url": base,
        # 只给长度，绝不返回值本身（健康检查是会被日志/监控采集的）
        "key_len": len(key),
        # 建议动作：让运维一眼知道该做什么，而不是只知道"坏了"
        "hint": "" if enabled else
                "在 secrets.env 填 AISEC_LLM_API_KEY=<key>（可选 AISEC_LLM_BASE_URL / "
                "AISEC_LLM_MODEL，默认 deepseek-chat）后重启服务",
    }
    # 有 key 但没配 model/base_url 是常见的半配置态 —— 仍算降级，但要单独说
    if enabled and not model:
        st["degraded"] = True
        st["reason"] = "已配置 Key 但未指定模型，将回落到 qa/config.py 默认模型"
    return st


def main():
    global REGISTRY
    # 兜底补载密钥（已由启动脚本注入时这里是空操作，不打印噪音）
    _sec_loaded = _load_secrets_env()
    if _sec_loaded:
        _compat.safe_print("[secrets] 已从本机 secrets.env 补载 %d 项配置（值不打印）"
                           % len(_sec_loaded))
    # LLM 能力自证：降级要**在启动日志里就说**，不能等到有人问"为什么今天答得这么浅"
    try:
        _ls = llm_status()
        if _ls.get("enabled"):
            _compat.safe_print("[llm] 已启用：模型 %s（智能体自主决策生效）"
                               % (_ls.get("model") or "默认"))
        else:
            _compat.safe_print("[llm] ⚠ 未启用 —— 问答/简报将走「检索证据模板」，"
                               "Tool-Calling Agent 自主决策不生效")
            _compat.safe_print("[llm] ⚠ 原因：%s" % _ls.get("reason"))
            _compat.safe_print("[llm] ⚠ 处理：%s" % _ls.get("hint"))
    except Exception:  # noqa: BLE001
        pass
    args = sys.argv[1:]
    # 提示里的命令必须跟着平台走（Windows 没有 python3，POSIX 没有 py 启动器）
    _PY_HINT = "python" if _compat.IS_WIN else "python3"

    # ── 环境画像 + 性能档位降级（慢机器友好，见 core/envprofile.py）──────
    # 顺序很关键：先按档位补 config.json 里**没有**的键，再从 config 读默认值，
    # 这样"用户显式配置"始终优先，命令行参数又比两者都高。
    if T is not None:
        try:
            T.apply_to_config(CONFIG)
            _compat.safe_print("[env] " + T.describe().replace("\n", "\n       "))
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("core/server.py:main/apply_to_config", _sw_e)

    port = _coerce_port(CONFIG.get("port"))
    auto_hours = _cfg_num("auto_refresh_hours", 0, float, lo=0)
    fast_interval = _cfg_num("fast_interval", 30, int, lo=1, hi=86400)
    no_live = False
    no_modules = False
    force = False
    i = 0
    while i < len(args):
        if args[i].isdigit():
            port = int(args[i])
        elif args[i] == "--auto-refresh" and i + 1 < len(args):
            auto_hours = float(args[i + 1]); i += 1
        elif args[i] == "--fast-interval" and i + 1 < len(args):
            fast_interval = max(30, int(args[i + 1])); i += 1
        elif args[i] == "--no-live":
            no_live = True
        elif args[i] == "--no-modules":
            no_modules = True
        elif args[i] == "--force":
            force = True
        i += 1

    # 端口预检（必须在加载语料之前，快速失败）：
    # Windows 的 SO_REUSEADDR 允许两个进程同时 bind 同一端口，第二个进程会「假启动成功」，
    # 但请求仍然落到旧实例上 —— 表现为「新代码没生效 / 日志对不上 / 诡异崩溃」。
    # 这里直接拒绝启动，除非显式 --force。
    if not force and _port_in_use(port):
        # 排查命令必须跟着当前平台走：Windows 用 netstat/findstr，macOS 用 lsof，
        # Linux 用 ss —— 写死 Windows 命令会让另两个系统的使用者卡在第一步。
        print(f"!! 端口 {port} 上已有服务在监听，本实例不再启动（避免两个实例叠在同一端口）。")
        print(f"   查看占用：{_compat.port_in_use_hint(port)}")
        if _compat.IS_WIN:
            print(f"   停止占用：taskkill /F /PID <PID>")
        else:
            print(f"   停止占用：kill -9 <PID>")
        print(f"   换端口：{_PY_HINT} core/server.py 8899        确实要强制： 加 --force")
        sys.exit(2)

    if not os.path.isfile(CORPUS):
        print(f"!! 未找到语料库 {CORPUS}")
        print(f"   说明：安装包默认不含语料（语料约 274MB + 索引缓存 286MB，单独分发）。")
        print(f"   首次使用请先抓取（需联网，耗时较长）：")
        print(f"       {_PY_HINT} core/fetch_corpus.py")
        print(f"   或把现成的 data/ 目录放到项目根下（需含 data/corpus.json）")
        print(f"   详见 README_安装.md 「四、语料（数据）」")
        sys.exit(1)

    # 问答模块（m3_qa）通过 HTTP 回访本服务；端口可能被改，先行绑定实际端口
    os.environ.setdefault("AISEC_MAIN_SERVER", f"http://127.0.0.1:{port}")
    CORE.port = port
    CORE.args = {"fast_interval": fast_interval, "no_live": no_live,
                 "auto_refresh_hours": auto_hours,
                 # 秒级轻量同步（2026-09-30）：auto_refresh_sec > 0 时，每隔这么多秒
                 # 跑一轮「NVD 单关键词 + KEV 缓存 + CSDN 快抓」，无新增不落盘不重建引擎。
                 "auto_refresh_sec": _cfg_num("auto_refresh_sec", 0, float, lo=0)}

    # 冷启动耗时打印（2026-09-30）：语料 250MB+，命中索引缓存要走「读 pickle」，
    # 没命中要走「解析 json + 全量建索引」，两条路径耗时差一个数量级（60s vs 380s）。
    # 以前这里只有一行提示，卡住时根本看不出是在读缓存还是在重建，排障全靠猜。
    # 慢机器提示：命中索引缓存约 14s，未命中要全量重建（10 万条语料在低配机上 5~8 分钟）。
    # 与其让用户盯着黑窗口以为卡死，不如开跑前就说清楚"要多久、怎么跳过"。
    if T is not None and not os.path.isfile(CORPUS + ".idxcache"):
        try:
            _mb = os.path.getsize(CORPUS) / 1024.0 / 1024.0
            _compat.safe_print(
                "  提示：未发现索引缓存，本次将全量重建索引"
                "（语料 %.0fMB · %s 档，低配机约 5~8 分钟）" % (_mb, T.name))
            _compat.safe_print("        下次启动会命中缓存（秒级）。想跳过：把现成的 "
                               "data/corpus.json.idxcache 一起拷过来。")
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("core/server.py:main/idxcache_hint", _sw_e)

    print("加载语料并构建索引 ...")
    _t_boot = time.time()
    eng = get_engine()
    _dt = time.time() - _t_boot
    _inc = getattr(eng, "_incremental_from_cache", 0) or 0
    _drop = getattr(eng, "_dropped_from_cache", 0) or 0
    if not getattr(eng, "_loaded_from_cache", False):
        _via = "全量重建"
        _why = getattr(eng, "_cache_reject", "") or ""
        if _why:
            print(f"    缓存未复用：{_why}")
    else:
        _parts = ["索引缓存"]
        if _drop:
            _parts.append(f"剔除已删 {_drop} 条")
        if _inc:
            _parts.append(f"尾部增量 {_inc} 条")
        _via = " + ".join(_parts)
    print(f"  索引就绪：{_dt:.1f}s（{_via}）")
    print(f"  文档 {len(eng.docs)} 条 / 词项 {len(eng.df)} 个 / 论文 {len(eng.papers)} 篇")
    print(f"  可信度字段：已挂载 / 交叉验证 {CR.credibility_stats(eng.docs).get('cross_verified_count')} 条")
    print(f"  数据目录：{paths.DATA_DIR}")

    if no_modules:
        print("  --no-modules：只启动主体，不加载任何模块")
    else:
        print("装载模块 ...")
        REGISTRY = Registry(core=CORE, config=CONFIG)
        REGISTRY.load_all()
        CORE.registry = REGISTRY
        print(REGISTRY.summary())
        REGISTRY.start()

    # 四模块每日报告的定时生成 + 缺失补齐 + 出报告后的站内提醒。
    # 放在 REGISTRY.start() 之后：m1 的自动日报线程已经起了，延后起
    # 自己的调度器，两边不会在启动瞬间抢同一个文件。
    # 无论是否加载模块都要起 —— 报告读的是已落盘产物，不依赖模块。
    try:
        import daily_digest as _DG
        _DG.start_scheduler(boot_delay=25)
        print(f"  四模块每日报告：每天 {_DG.DAILY_AT} 自动生成"
              f"（m1/m0/m2/m3 各一份，保留 {_DG.RETENTION_DAYS} 天，缺失自动补齐）",
              flush=True)
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("core/server.py:digest-scheduler", _sw_e)
        print("  四模块每日报告：调度器启动失败（不影响主服务）", flush=True)

    # ── 同步预热（端口绑定之前）：嵌入模型 + 向量矩阵 ──────────────
    # 实测：这两件重活约 30s（模型 ~10s、矩阵页错误 ~11s、其余为首次检索路径）。
    # 放在端口前，用户能点的时候系统就是热的；否则请求排在预热后面，
    # 首问实测 31.93s（详见 _warmup_sync 的注释）。AISEC_WARM_SYNC=0 可关。
    if os.environ.get("AISEC_WARM_SYNC", "1") not in ("0", "false", "False"):
        _warmup_sync(T)

    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    # 监听队列默认只有 5：并发一起来，第 6 个之后的连接在 accept 前就被内核丢弃
    # （客户端表现为 ConnectionRefused/Reset，服务端日志里则是一条
    # ConnectionAbortedError 10053——因为对端早就走了）。e2e 16 路并发实测挂 5~6 个。
    # 控制台是单用户本地服务，128 足够，且它只影响排队、不影响处理能力。
    srv.request_queue_size = 128
    print(f"控制台已启动： http://127.0.0.1:{port}/")
    threading.Thread(target=_warmup, args=(port,), daemon=True, name="warmup").start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()
