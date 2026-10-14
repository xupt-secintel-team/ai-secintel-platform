# -*- coding: utf-8 -*-
"""
api.py —— 模块2「情报富化」后端入口
============================================================
负责人：成员B
职责：给漏洞加料变档案 —— POC / EXP 多源实抓、受影响资产定位（NVD / LLM / CPE 三路）。

本模块对外接口（启动时自动注册进主体，无需改 core/server.py）：
    GET  /api/assets?id=CVE-...   受影响资产定位（三路提取，命中缓存秒出）
    GET  /api/poc?id=CVE-...      POC 搜索任务状态（轮询用）
    POST /api/poc?id=CVE-...&quick=1   POC / EXP 搜索（后台任务）
                                       &force=1 强制重跑（默认已有结果直接返回缓存）

    POST /api/asset_scan          公司互联网资产风险体检（上传 word/txt/excel）
    GET  /api/asset_scan          体检历史列表 / ?id=AS-... 取单次报告 / ?md=1 导出 Markdown

    GET  /api/asset_search        攻击面测绘实查 ?id=CVE-...|?q=语法 &platform=fofa|shodan|quake|zoomeye
    GET  /api/asset_search/status 各平台 Key 配置状态（不含密钥本身）

    GET  /api/subscribe           订阅列表 + 巡检状态
    POST /api/subscribe            新增订阅 {kind,value,min_severity?,ai_min?,kev_only?,webhook?}
    POST /api/subscribe/update     更新订阅（启用/暂停/改条件）
    POST /api/subscribe/delete     删除订阅 {id}
    POST /api/subscribe/check      立即巡检一轮（force 全量回看，seen 去重）
    GET  /api/subscribe/alerts     告警通知流 ?limit=&unread=1&since_id=
    POST /api/subscribe/read       标记已读 {"ids":[..]} 或 {"all":true}

    GET  /api/remediation?id=CVE-...  修复方案生成（LLM/模板双模式，&force=1 重生成 &md=1 导出）

    POST /api/cmdb_scan           连接 CMDB 分析资产风险（rest/inline/file/sqlite 四模式，含优先处置+修复+验收）
                                   file/sqlite 两模式支持浏览器直接拖拽上传多文件（二进制直传，octet-stream + X-Cmdb-Manifest）
    GET  /api/cmdb_scan           历史列表 / ?id=CMDB-... 取单次报告 / ?md=1 导出 Markdown
    GET  /api/cmdb_scan/config    读取 CMDB 连接配置（不下发密钥本身，只报是否已配置）
    GET  /api/cmdb_scan/mail      SMTP 配置状态 + 收件人校验 + 上次发送结果（?to= 预校验）
    POST /api/cmdb_scan/mail      对已生成报告补发邮件 {id,to,mask,attach}

实现全部复用本模块 backend/ 下的 poc_scraper.py / affected_assets.py / asset_scan.py /
asset_search.py / alert_subscribe.py / remediation.py / cmdb_scan.py；
数据（POC 结果、资产缓存、Exploit-DB 清单、体检报告、订阅、修复方案缓存）统一落在 paths.DATA_DIR。
"""
from __future__ import annotations

import base64
import itertools
import json          # ★ 2026-10-08 补：cmdb_scan/port_scan/project_scan 的 handler 都用
                     #   json.loads，此前模块从未 import json —— cmdb 分支一旦真跑必
                     #   NameError（潜伏 bug，本轮接新功能时发现顺手修）。
import os
import re
import sys
import threading
import time

import paths                                   # noqa: F401  —— 数据目录统一从这里取
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass


def apply_env_keys(cfg: dict) -> dict:
    """把环境变量里的 Key 合并进 poc_scraper 配置（**不要在代码里写 Key**）。

        set AISEC_GITHUB_TOKEN=ghp_xxx     —— GitHub 搜索（速率 10/分钟 → 30/分钟）
        set AISEC_LLM_API_KEY=sk-xxx       —— POC 类型二级精判用的 LLM
    """
    def pick(*names):
        for n in names:
            v = (os.environ.get(n) or "").strip()
            if v:
                return v
        return ""
    tok = pick("AISEC_GITHUB_TOKEN", "GITHUB_TOKEN")
    key = pick("AISEC_LLM_API_KEY", "DEEPSEEK_API_KEY")
    base = pick("AISEC_LLM_BASE_URL", "DEEPSEEK_BASE_URL")
    model = pick("AISEC_LLM_MODEL", "DEEPSEEK_MODEL")
    if tok:
        cfg["github_token"] = tok
    if key:
        cfg["deepseek_api_key"] = key
    if base:
        cfg["deepseek_base_url"] = base.rstrip("/")
    if model:
        cfg["deepseek_model"] = model
    return cfg

# ---- 由 registry 在启动时注入 ----
_CORE = None

# ----------------------------------------------------------------------
# POC 搜索后台任务（poc_scraper 接入）
# ----------------------------------------------------------------------
POC_JOBS = {}          # cve_id -> {running, done, quick, results, error, started_at}
POC_LOCK = threading.Lock()


def _run_poc(cve_id, quick):
    """后台执行 POC 搜索（复用 poc_scraper.search_poc，不写新采集逻辑）。

    :param quick: True 跳过 GitHub 慢路径（仅 Exploit-DB/Nuclei/Metasploit/PacketStorm）。
    """
    import poc_scraper as POC
    with POC_LOCK:
        POC_JOBS[cve_id] = {"running": True, "done": False, "quick": quick,
                            "results": [], "error": None,
                            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    try:
        cfg = POC.load_config()
        apply_env_keys(cfg)          # 环境变量里的 GitHub Token / LLM Key 在这里合并
        searchers = POC._default_searchers(cfg)
        if quick:
            searchers = [s for s in searchers
                         if not isinstance(s, POC.GitHubPOCSearcher)]
        rs = POC.search_poc(cve_id, searchers=searchers, config=cfg)
        d = [r.to_dict() for r in rs]
        # ② 精度优化：暴露匹配等级分布，前端/评测都能直接用
        tiers = {}
        for r in d:
            t = r.get("match_tier") or "D"
            tiers[t] = tiers.get(t, 0) + 1
        with POC_LOCK:
            POC_JOBS[cve_id].update(running=False, done=True, results=d, tiers=tiers,
                                    precise=sum(1 for r in d if r.get("match_tier") in ("A", "B")))
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        with POC_LOCK:
            POC_JOBS[cve_id].update(running=False, done=True, error=str(e))


# ======================================================================
# HTTP 处理
# ======================================================================
def handle_assets(req):
    """受影响资产定位：NVD / LLM / CPE 三路提取（同步，命中缓存秒出）"""
    cid = req.q("id")
    d = req.engine.detail(cid)
    if not d:
        return req.json({"error": "not found", "id": cid}, 404)
    import affected_assets as AA  # noqa: E402 —— 懒加载，避免拖慢启动
    desc = (d.get("desc") or "").strip() or (d.get("title") or "").strip()
    assets = AA.extract_affected_assets(cid, desc, record=d)
    hint = ""
    try:
        if not AA.load_config().get("deepseek_api_key") and not (
                os.environ.get("AISEC_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")):
            hint = "未配置 DeepSeek Key，LLM 提取路径已跳过（NVD 结果不受影响）"
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m2_enrich/api.py:113", _sw_e)

    # 受影响互联网资产定位：把「影响什么」翻成「去哪、用什么语法找暴露面」
    # （只生成测绘语法，不发任何请求；合规提示随结果一起返回）
    try:
        import asset_locator as AL  # noqa: E402
        survey = AL.survey(cid, item=d, assets=[a.to_dict() for a in assets])
    except Exception as e:  # noqa: BLE001
        survey = {"error": f"测绘语法生成失败: {str(e)[:120]}"}

    return req.json({"id": cid, "count": len(assets),
                     "assets": [a.to_dict() for a in assets], "hint": hint,
                     "survey": survey})


def handle_poc_get(req):
    cid = req.q("id").strip().upper()
    with POC_LOCK:
        st = dict(POC_JOBS.get(cid, {"running": False, "done": False,
                                     "quick": 0, "results": [], "error": None}))
    return req.json({"id": cid, **st})


def handle_poc_post(req):
    cid = req.q("id").strip().upper()
    if not cid:
        return req.json({"started": False, "error": "empty id"}, 400)
    quick = req.qs.get("quick", ["1"])[0] not in ("0", "false")
    # force=1：强制重跑。默认「已有结果就直接返回缓存」——但那样用户先点「快速搜索」、
    # 配好 GitHub Token 再点「完整搜索」时，第二次会静默拿到第一次的旧结果（实测踩到）。
    force = req.qs.get("force", ["0"])[0] not in ("0", "false", "")
    with POC_LOCK:
        job = POC_JOBS.get(cid)
        if job and job["running"]:
            return req.json({"started": False, "id": cid, **job})     # 正在跑：不重复启动
        if job and job["done"] and not force:
            return req.json({"started": False, "id": cid, **job})     # 已完成：返回缓存
        POC_JOBS[cid] = {"running": True, "done": False, "quick": quick,
                         "results": [], "error": None}
    threading.Thread(target=_run_poc, args=(cid, quick),
                     daemon=True, name="poc").start()
    return req.json({"started": True, "running": True, "id": cid,
                     "quick": quick, "force": force})


# ======================================================================
# 资产风险体检（POST /api/asset_scan）—— 上传 word / txt / excel → 自动风险分析
# ======================================================================
MAX_UPLOAD = 24 * 1024 * 1024          # 单文件上限 24MB（资产清单不会有这么大）


def _multipart_file(body: bytes, ctype: str):
    """从 multipart/form-data 里取出第一个带 filename 的文件。返回 (文件名, 字节)。

    为什么自己解而不用 cgi.FieldStorage：python 3.13 已废弃 cgi 模块，
    且我们只需要「一个文件字段」这一种极简形态，手写反而更可控。
    """
    m = re.search(r'boundary="?([^";,]+)"?', ctype or "")
    if not m:
        return "", b""
    boundary = b"--" + m.group(1).strip().encode("latin-1", "ignore")
    for part in body.split(boundary)[1:]:
        if part.strip() in (b"", b"--"):
            continue
        head, sep, data = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        head_s = head.decode("utf-8", "ignore")
        fn = re.search(r"filename\*\s*=\s*([^;\r\n]+)", head_s)
        if fn:
            raw = fn.group(1).strip().strip('"')
            if "''" in raw:                       # RFC 2231：UTF-8''%E4%B8%AD%E6%96%87
                raw = raw.split("''", 1)[1]
            name = _url_unquote(raw)
        else:
            m2 = re.search(r'filename\s*=\s*"([^"]*)"', head_s) or \
                 re.search(r"filename\s*=\s*([^;\r\n]+)", head_s)
            name = (m2.group(1).strip().strip('"') if m2 else "")
        if not name:
            continue
        data = data.rstrip(b"\r\n")
        if data.endswith(b"--"):
            data = data[:-2].rstrip(b"\r\n")
        return name, data
    return "", b""


def _url_unquote(s: str) -> str:
    import urllib.parse
    try:
        return urllib.parse.unquote(s, encoding="utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        return s


def handle_asset_scan_post(req):
    """接收资产文件 → 解析 → 用模块 1 情报匹配 → 返回风险报告。"""
    import asset_scan as AS                        # 懒加载：不拖慢服务启动

    # 注意：必须用 req.q()（缺省返回 ""）；若手工 dict(req.qs) 再 .get()，
    # 缺键会拿到 None，`None not in ("", "0", "false")` 恒真 → 参数判断全部失效。
    sample = req.q("sample")
    want_md = req.q("md") not in ("", "0", "false")
    filename = req.q("name")
    name, data, text = "", b"", None

    try:
        if sample not in ("", "0", "false"):
            name, text = "示例-某公司互联网资产清单.txt", AS.SAMPLE_ASSETS
        else:
            ctype = (req.h.headers.get("Content-Type") or "").lower()
            if "application/json" in ctype:
                body = req.json_body() or {}
                name = str(body.get("name") or body.get("filename") or "资产清单.txt")
                if body.get("b64"):
                    data = base64.b64decode(body["b64"])
                elif body.get("text"):
                    text = str(body["text"])
                else:
                    return req.json({"ok": False, "error": "缺少文件内容（b64 / text）"}, 400)
            elif "multipart/form-data" in ctype:
                name, data = _multipart_file(req.body, req.h.headers.get("Content-Type") or "")
                if not data:
                    return req.json({"ok": False, "error": "未在表单里找到文件字段"}, 400)
            else:
                name, data = (filename or "资产清单.txt"), req.body
                if not data:
                    return req.json({"ok": False, "error": "请求体为空"}, 400)

        if len(data) > MAX_UPLOAD:
            return req.json({"ok": False,
                             "error": "文件过大（%.1fMB），请拆分后上传（上限 %dMB）"
                                      % (len(data) / 1048576.0, MAX_UPLOAD // 1048576)}, 413)

        rep = AS.build_report(name, data, req.engine, text=text, persist=True)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        return req.json({"ok": False, "error": "体检失败：%s" % str(e)[:200]}, 500)

    if want_md:
        return _md_response(req, AS.report_to_markdown(rep), "资产风险体检报告", rep)
    return req.json({"ok": True, "id": rep["id"], "report": rep})


def handle_asset_scan_get(req):
    """列表 / 单份报告 / Markdown 导出。"""
    import asset_scan as AS
    sid = req.q("id").strip()
    md = req.q("md") not in ("", "0", "false")
    if sid:
        rep = AS.load_report(sid)
        if not rep:
            return req.json({"ok": False, "error": "报告不存在或已被清理", "id": sid}, 404)
        if md:
            return _md_response(req, AS.report_to_markdown(rep), "资产风险体检报告", rep)
        return req.json({"ok": True, "id": sid, "report": rep})
    items = AS.list_scans()
    return req.json({"ok": True, "count": len(items), "items": items})


def handle_asset_scan_clear(req):
    import asset_scan as AS
    n = AS.clear_scans()
    return req.json({"ok": True, "cleared": n})


# ======================================================================
# 攻击面测绘实查（GET /api/asset_search）—— 把测绘语法真正查成数据
# ======================================================================
def handle_asset_search(req):
    """?id=CVE-...（自动选语法）或 ?q=body="..."（用户指定的语法）&platform=fofa|shodan|quake|zoomeye
       &samples=1 &demo=1（强制演示） &limit=100"""
    import asset_search as SR
    platform = (req.q("platform") or "fofa").strip().lower()
    cve = req.q("id").strip().upper()
    q = req.q("q").strip()
    samples = req.q("samples") not in ("0", "false")
    force_demo = req.q("demo") not in ("", "0", "false")
    try:
        limit = min(max(int(req.q("limit") or 100), 1), 200)
    except ValueError:
        limit = 100
    if not cve and not q:
        return req.json({"ok": False,
                         "error": "缺少 id（CVE 编号）或 q（测绘语法），二选一"}, 400)
    if cve:
        return req.json(SR.search_for_cve(cve, req.engine, platform,
                                          samples=samples, limit=limit, q=q,
                                          force_demo=force_demo))
    return req.json(SR.search(platform, q, samples=samples, limit=limit,
                              force_demo=force_demo))


def handle_asset_search_status(req):
    """前端角标：各平台 Key 配置状态（不返回任何密钥本身）。"""
    import asset_search as SR
    return req.json({"ok": True, "platforms": SR.platform_status()})


# ======================================================================
# 漏洞预警订阅与推送（/api/subscribe*）
# ======================================================================
def handle_subscribe_get(req):
    import alert_subscribe as SB
    return req.json({"ok": True, "subs": SB.list_subs(), "status": SB.status()})


def handle_subscribe_post(req):
    import alert_subscribe as SB
    body = req.json_body() or {}
    return req.json(SB.add_sub(body))


def handle_subscribe_update(req):
    import alert_subscribe as SB
    body = req.json_body() or {}
    return req.json(SB.update_sub(body))


def handle_subscribe_delete(req):
    import alert_subscribe as SB
    body = req.json_body() or {}
    return req.json(SB.delete_sub(str(body.get("id") or "")))


def handle_subscribe_check(req):
    import alert_subscribe as SB
    r = SB.match_once(req.engine, force=True)
    return req.json({"ok": True, **r})


def handle_subscribe_alerts(req):
    import alert_subscribe as SB
    try:
        limit = min(max(int(req.q("limit") or 50), 1), 200)
    except ValueError:
        limit = 50
    unread_only = req.q("unread") not in ("", "0", "false")
    items = SB.alerts(since_id=req.q("since_id").strip(), limit=limit,
                      unread_only=unread_only)
    return req.json({"ok": True, "count": len(items), "alerts": items,
                     "status": SB.status()})


def handle_subscribe_read(req):
    import alert_subscribe as SB
    body = req.json_body() or {}
    if body.get("all"):
        n = SB.mark_read(None)
    else:
        ids = body.get("ids")
        n = SB.mark_read([str(x) for x in ids] if isinstance(ids, list) else [])
    return req.json({"ok": True, "marked": n})


# ======================================================================
# 漏洞修复方案生成（GET /api/remediation?id=CVE-...）
# ======================================================================
def handle_remediation(req):
    import remediation as RM
    cid = req.q("id").strip().upper()
    if not cid:
        return req.json({"ok": False, "error": "缺少 id（CVE 编号）"}, 400)
    force = req.q("force") not in ("", "0", "false")
    r = RM.generate(cid, req.engine, force=force)
    if r.get("ok") and req.q("md") not in ("", "0", "false"):
        return _md_response(req, RM.plan_to_markdown(r["plan"]),
                            "修复方案_" + str(cid), r.get("plan"))
    return req.json(r)


# ======================================================================
# 端口测绘（POST /api/port_scan）—— 2026-10-08 新增
# ======================================================================
def handle_port_scan_post(req):
    """POST /api/port_scan  {"host":"www.example.com","ports":"80,443,8000-8010","timeout":1.5}

    仅限授权资产（UI 与报告均带提示）；TCP connect 扫描（nmap -sT 同级）。
    2026-10-08 晚：扫描后自动与本地情报库交叉验证（服务指纹 → CVE），
    ?md=1 下载 CMDB 风格的**工单版**报告（六章制，含 SLA 与验收标准）。
    """
    import port_scan as PS
    try:
        body = json.loads(req.body.decode("utf-8")) if req.body else {}
    except Exception:  # noqa: BLE001
        return req.json({"ok": False, "error": "请求体不是合法 JSON"}, 400)
    host = str(body.get("host") or "").strip()
    if not host:
        return req.json({"ok": False, "error": "缺少 host（域名或 IPv4）"}, 400)
    ports = body.get("ports") or ""
    try:
        timeout = float(body.get("timeout") or 1.5)
    except (TypeError, ValueError):
        timeout = 1.5
    res = PS.scan(host, ports=ports, timeout=timeout)
    if res.get("ok"):
        # ★ 关联失败不阻断扫描结果本身：指纹匹配是增强层，网络/索引异常时
        #   返回无 correlation 字段的结果，前端照常显示端口表。
        try:
            res = PS.correlate(req.engine, res)
        except Exception as e:  # noqa: BLE001
            _swallow("modules/m2_enrich/api.py:port_scan.correlate", e)
            res["correlation_error"] = str(e)[:160]
        PS.save_result(res)
        PS.save_last(res)          # GET ?md=1 从这里出工单报告（不用重新扫）
        if req.q("md") not in ("", "0", "false"):
            return _md_response(req, PS.workorder_markdown(res),
                                "端口测绘工单报告_%s" % res.get("host"), res)
    return req.json(res, 200 if res.get("ok") else 400)


def handle_port_scan_get(req):
    """GET /api/port_scan[?host=xx&limit=20] —— 历史扫描记录；
    GET /api/port_scan?md=1 —— 最近一次扫描的工单版 Markdown 下载（不重扫）。"""
    import port_scan as PS
    if req.q("md") not in ("", "0", "false"):
        last = PS.load_last()
        if not last or not last.get("ok"):
            return req.json({"ok": False,
                             "error": "还没有可导出的扫描结果，请先做一次端口扫描"}, 404)
        return _md_response(req, PS.workorder_markdown(last),
                            "端口测绘工单报告_%s" % last.get("host"), last)
    items = PS.history(host=req.q("host"), limit=req.q_int("limit", 20))
    return req.json({"ok": True, "count": len(items), "items": items})


# ======================================================================
# 项目成分扫描 SCA（POST /api/project_scan）—— 2026-10-08 新增
# ======================================================================
def handle_project_scan_post(req):
    """四种输入（与 asset_scan / cmdb_scan 同风格）：
      ① application/octet-stream + X-Project-Name 头：zip 二进制直传
        （2026-10-08 晚：单包 ≤10GB，iter_body 边收边落盘，字节不进内存）
      ② multipart/form-data：zip 包（小包兼容路径，前端旧版本用）
      ③ JSON {files:[{path, content}]}：文件夹多选（前端只筛清单文件）
      ④ JSON {b64, name}：base64 zip（小包兼容）
    输出报告 JSON；?md=1 直接下载 Markdown（CMDB 风格七章制）。
    """
    import project_scan as PS

    ctype = (req.h.headers.get("Content-Type") or "").lower()

    # ── ① 大包二进制直传（≤10GB）────────────────────────────────
    # 与 cmdb_scan 的 X-Cmdb-Manifest 直传同一思想：10GB 的包走 base64/JSON
    # 会膨胀 1.33 倍且整体进内存，唯一可行形态是「原始字节流 + 落盘」。
    # >32MB 时 core 已 begin_stream()（req.body 为空），统一用 iter_body
    # 1MB 分块写临时文件 —— 两种体积模式同一份代码，不用分支判断。
    if "octet-stream" in ctype:
        name = os.path.basename(str(req.header("X-Project-Name")
                                    or req.q("name") or "project.zip")
                                .replace("\\", "/")) or "project.zip"
        name = re.sub(r'[\\/:*?"<>|]', "_", name)[:80]
        if not name.lower().endswith(".zip"):
            name += ".zip"
        # 落盘目录必须用 tmp_cmdb：_cleanup_sqlite_uploads_async 的安全护栏
        # 只认这个目录（防路径被篡改后误删业务文件）。
        tmp_dir = _init_cleanup_tmpdir()
        try:
            os.makedirs(tmp_dir, exist_ok=True)
        except OSError as e:  # noqa: BLE001
            return req.json({"ok": False,
                             "error": "无法创建临时目录（大包无法落盘）：%s" % str(e)[:120]}, 500)
        dst = os.path.join(tmp_dir, "%s_proj_%s" % (_unique_stamp(), name))
        size = 0
        try:
            with open(dst, "wb") as fh:
                for chunk in req.iter_body(1024 * 1024):
                    size += len(chunk)
                    if size > PS.MAX_ZIP_TOTAL:
                        # 超限即断：不再读 socket，尽快回 413 让浏览器停手
                        fh.close()
                        _cleanup_sqlite_uploads_async([dst])
                        return req.json(
                            {"ok": False,
                             "error": "压缩包超过 %dGB 上限，已中止接收" % (PS.MAX_ZIP_TOTAL // (1024**3))},
                            413)
                    fh.write(chunk)
        except (ConnectionError, BrokenPipeError):
            _cleanup_sqlite_uploads_async([dst])
            raise
        except OSError as e:  # noqa: BLE001
            _cleanup_sqlite_uploads_async([dst])
            return req.json({"ok": False, "error": "临时文件写入失败：%s" % str(e)[:120]}, 500)
        if size == 0:
            _cleanup_sqlite_uploads_async([dst])
            return req.json({"ok": False, "error": "请求体为空（未收到 zip 字节）"}, 400)
        try:
            rep = PS.build_report(name, b"", req.engine, persist=True, path=dst)
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            return req.json({"ok": False, "error": "项目扫描失败：%s" % str(e)[:200]}, 500)
        finally:
            # 大文件删除必须异步（几百 MB~几 GB 的 os.remove 在宿主回收站 shim
            # 下会长时间不返回 —— 见 _hard_unlink 的注释），绝不能阻塞响应。
            _cleanup_sqlite_uploads_async([dst])
        return _project_scan_response(req, rep, PS)

    name, data, files = "", b"", None
    try:
        if "multipart/form-data" in ctype:
            name, data = _multipart_file(req.body, req.h.headers.get("Content-Type") or "")
            if not data:
                return req.json({"ok": False, "error": "未在表单里找到文件字段"}, 400)
            if not name.lower().endswith(".zip"):
                return req.json({"ok": False,
                                 "error": "项目上传请打 zip 包（依赖清单文件 + 目录结构）"}, 400)
        else:
            body = {}
            try:
                body = json.loads(req.body.decode("utf-8")) if req.body else {}
            except Exception:  # noqa: BLE001
                return req.json({"ok": False, "error": "请求体不是合法 JSON"}, 400)
            if body.get("b64"):
                import base64
                name = str(body.get("name") or "project.zip")
                data = base64.b64decode(body["b64"])
            elif isinstance(body.get("files"), list):
                files = body["files"]
                name = str(body.get("name") or "文件夹导入")
            else:
                return req.json({"ok": False,
                                 "error": "缺少项目内容：上传 zip（multipart 或 b64）"
                                          "或 files:[{path,content}]（文件夹多选）"}, 400)
        if data and len(data) > MAX_UPLOAD:
            return req.json({"ok": False,
                             "error": "压缩包过大（%.1fMB），上限 %dMB；大包请改用"
                                      "「二进制直传」（前端已自动使用）"
                                      % (len(data) / 1048576.0, MAX_UPLOAD // 1048576)}, 413)
        rep = PS.build_report(name, data, req.engine, files=files, persist=True)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        return req.json({"ok": False, "error": "项目扫描失败：%s" % str(e)[:200]}, 500)

    return _project_scan_response(req, rep, PS)


def _project_scan_response(req, rep, PS):
    """项目扫描的统一响应出口：JSON 或 ?md=1 下载七章制报告。"""
    if not rep.get("ok"):
        return req.json(rep, 400)
    if req.q("md") not in ("", "0", "false"):
        return _md_response(req, PS.report_to_markdown(rep),
                            "项目成分安全评估报告", rep)
    return req.json(rep)


def handle_project_scan_get(req):
    import project_scan as PS
    sid = req.q("id").strip()
    md = req.q("md") not in ("", "0", "false")
    if sid:
        rep = PS.load_report(sid)
        if not rep:
            return req.json({"ok": False, "error": "报告不存在或已被清理", "id": sid}, 404)
        if md:
            return _md_response(req, PS.report_to_markdown(rep),
                                "项目成分安全评估报告", rep)
        return req.json({"ok": True, "id": sid, "report": rep})
    items = PS.list_scans()
    return req.json({"ok": True, "count": len(items), "items": items})


def handle_project_scan_clear(req):
    import project_scan as PS
    return req.json({"ok": True, "cleared": PS.clear_scans()})


# ======================================================================
# 公司 CMDB 连接 + 资产风险自动分析（POST /api/cmdb_scan）
# ======================================================================
def _cmdb_config() -> dict:
    """读取 CMDB 连接配置：环境变量优先，其次 config.json 的 cmdb 段。
    只用于「自动填充」前端输入，密钥一律不通过 /api/cmdb_scan/config 下发。"""
    def pick(*names):
        for n in names:
            v = (os.environ.get(n) or "").strip()
            if v:
                return v
        return ""
    cfg = {
        "url": pick("AISEC_CMDB_URL"),
        "token_configured": bool(pick("AISEC_CMDB_TOKEN")),
        "auth_type": pick("AISEC_CMDB_AUTH_TYPE") or "bearer",
        "path": pick("AISEC_CMDB_PATH"),
    }
    # config.json 里的 cmdb 段（可选，兜底）
    try:
        jc = (_CORE.config if _CORE else None) or {}
        c = jc.get("cmdb") or {}
        if isinstance(c, dict):
            if not cfg["url"] and c.get("url"):
                cfg["url"] = str(c["url"])
            if not cfg["token_configured"] and c.get("token"):
                cfg["token_configured"] = True
            if c.get("auth_type"):
                cfg["auth_type"] = str(c["auth_type"])
            if c.get("path"):
                cfg["path"] = str(c["path"])
    except Exception as e:  # noqa: BLE001
        _swallow("modules/m2_enrich/api.py:_cmdb_config", e)
    return cfg


def _cmdb_env_token() -> str:
    """取 CMDB 凭证（只用于服务端实际发请求，绝不下发）。"""
    for n in ("AISEC_CMDB_TOKEN",):
        v = (os.environ.get(n) or "").strip()
        if v:
            return v
    try:
        c = ((_CORE.config if _CORE else None) or {}).get("cmdb") or {}
        return str(c.get("token") or "") if isinstance(c, dict) else ""
    except Exception:  # noqa: BLE001
        return ""


def _stage_sqlite_uploads(cfg_files) -> tuple:
    """把上传的 .db 文件落盘到临时目录，返回 (路径列表, 错误信息)。

    为什么必须落盘：SQLite 只能通过文件路径打开，没法像 CSV 那样喂字节流。
    落在 data/tmp_cmdb/ 下（不落 data/ 根目录，避免长期堆积全量 CMDB 库），
    分析结束后由调用方清理。

    文件名做安全处理：只取 basename + 强制 .db 后缀，防目录穿越
    （浏览器传来的 filename 是用户可控的）。
    """
    import shutil
    import time as _t
    try:
        tmp_dir = os.path.join(paths.DATA_DIR, "tmp_cmdb")
        os.makedirs(tmp_dir, exist_ok=True)
    except Exception as e:  # noqa: BLE001
        _swallow("modules/m2_enrich/api.py:_stage_sqlite_uploads.mkdir", e)
        return [], "无法创建临时目录（数据库文件无法落盘）：%s" % str(e)[:120]

    # ★ 与 _stage_sqlite_uploads_stream 共用同一个唯一戳生成器。
    #   原来这里和那里各自算 "%d_%d" % (秒级时间戳, pid)，两个函数撞名就会
    #   Permission denied —— 小库走本函数、大库走流式函数，同一秒内先后上传
    #   就会互相踩（e2e 稳定复现）。毫秒 + 进程内自增序号彻底消除碰撞。
    stamp = _unique_stamp()
    out = []
    for i, f in enumerate(cfg_files):
        name = os.path.basename(str(f.get("filename") or "")).strip().replace("\x00", "")
        name = re.sub(r'[\\/:*?"<>|]', "_", name)[:80] or ("cmdb_%d.db" % i)
        if not name.lower().endswith((".db", ".sqlite", ".sqlite3", ".db3")):
            name += ".db"
        dst = os.path.join(tmp_dir, "%s_%02d_%s" % (stamp, i, name))
        try:
            with open(dst, "wb") as fh:
                fh.write(f.get("data") or b"")
        except Exception as e:  # noqa: BLE001
            _swallow("modules/m2_enrich/api.py:_stage_sqlite_uploads.write", e)
            # ★ 中途失败要把已经落盘的前几个一起删掉（2026-10-06 e2e 抓到）：
            #   否则第 3 个库写失败时，前 2 个会永久留在 data/tmp_cmdb 里 ——
            #   那是用户真实的 CMDB 全量库，攒几轮就是几个 G，且再也无人知道它是谁。
            _cleanup_sqlite_uploads(out)
            return [], "数据库文件写入临时目录失败：%s" % str(e)[:120]
        out.append(dst)

    # 顺手清掉 3 天前的残留（上次异常退出留下的），避免 tmp_cmdb 无限膨胀
    try:
        import time as _t2
        cut = _t2.time() - 3 * 86400
        for fn in os.listdir(tmp_dir):
            fp = os.path.join(tmp_dir, fn)
            try:
                if os.path.isfile(fp) and os.path.getmtime(fp) < cut:
                    os.remove(fp)
            except OSError:
                pass
    except Exception as e:  # noqa: BLE001
        _swallow("modules/m2_enrich/api.py:_stage_sqlite_uploads.gc", e)

    if not out:
        return [], "未收到有效的数据库文件"
    return out, ""


_CLEANUP_TMPDIR = None          # init 时指向 paths.DATA_DIR/tmp_cmdb（跨请求复用）
_CLEANUP_WORKERS = set()        # 在跑的后台清理线程，防止进程退出时被 join 住
_STAMP_SEQ = itertools.count()  # 临时文件名的进程内自增序号，保证同毫秒也不撞名


def _unique_stamp() -> str:
    """生成临时文件名的唯一前缀（毫秒 + 进程内自增序号）。

    ★ 必须唯一到"同一秒内多次上传"这一级。原来两个落盘函数各自算
      "%d_%d" % (秒级时间戳, pid)，同一秒里先后传两个库会算出**完全相同**的
      路径，第二次 open("wb") 直接 Permission denied —— 而上一次的临时文件
      还在后台清理线程里删着，窗口被进一步放大。
      统一走这一个函数，以后新增落盘点不会再漏。
    """
    import time as _t
    return "%d_%03d_%d" % (int(_t.time() * 1000), int((_t.time() % 1) * 1000),
                           next(_STAMP_SEQ, 0) % 1000)


def _init_cleanup_tmpdir() -> str:
    """临时目录只解析一次：_cleanup_sqlite_uploads 在 finally 里被同步调用，
    每次重算 paths.DATA_DIR 会在异常路径上多一次无谓的失败可能。"""
    global _CLEANUP_TMPDIR
    if _CLEANUP_TMPDIR is None:
        try:
            _CLEANUP_TMPDIR = os.path.join(paths.DATA_DIR, "tmp_cmdb")
        except Exception:  # noqa: BLE001
            _CLEANUP_TMPDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp")
    return _CLEANUP_TMPDIR


def _hard_unlink(path: str) -> bool:
    """绕开一切 Python 层包装，直接删文件。返回是否成功。

    ★ 为什么不用 os.remove / os.unlink：
      WorkBuddy 等宿主环境通过 sitecustomize.py 把它们换成 _safe_remove
      （"移入回收站"：fork genie-trash.exe 或调 SHFileOperationW）。
      这条路径在几百 MB 的文件上实测会**长时间不返回**（122MB 的 CMDB 库
      直接把请求线程挂住，浏览器只看到 "Failed to fetch"，服务端零 traceback）。
      os.unlink 在 CPython 里和 os.remove 是同一个对象，换它没有任何用。

      DeleteFileW 是 NTFS 的原生删除：122MB 实测 0.064s，与文件大小基本无关。
      文件被占用时返回 0 + ERROR_SHARING_VIOLATION(32) / ERROR_ACCESS_DENIED(5)，
      这里重试几次即可（占用通常是 sqlite 连接或杀软扫描的短暂窗口）。
    """
    import time as _st
    _abs = os.path.abspath(path)
    if sys.platform == "win32":
        try:
            import ctypes
            _k32 = ctypes.windll.kernel32
            _k32.DeleteFileW.argtypes = [ctypes.c_wchar_p]
            _k32.DeleteFileW.restype = ctypes.c_int
            for _i in range(6):
                if _k32.DeleteFileW(ctypes.c_wchar_p(_abs)):
                    return True
                _err = ctypes.get_last_error()
                if _err in (32, 5):        # SHARING_VIOLATION / ACCESS_DENIED：稍后重试
                    _st.sleep(0.25 * (_i + 1))
                    continue
                break
            # 最后一搏：退回标准库（极端情况下 shim 可能反而能用）
            if os.path.exists(_abs):
                os.remove(_abs)
            return not os.path.exists(_abs)
        except Exception as e:  # noqa: BLE001
            _swallow("modules/m2_enrich/api.py:_hard_unlink.win", e)
    # POSIX：os.unlink 本身是原子的，宿主一般不包装它
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return True
    except Exception as e:  # noqa: BLE001
        _swallow("modules/m2_enrich/api.py:_hard_unlink.unix", e)
        try:
            os.remove(path)
            return True
        except Exception:  # noqa: BLE001
            return False


def _delete_temp_db(path: str) -> None:
    """删掉一个临时 .db。**只允许在后台线程里调用**（见 _cleanup_sqlite_uploads_async）。"""
    try:
        if not (path and os.path.isfile(path)):
            return
        # 兜底：文件不在临时目录内就不删（防止路径被篡改后误删业务文件）
        if os.path.dirname(os.path.abspath(path)) != os.path.abspath(_init_cleanup_tmpdir()):
            return
        _hard_unlink(path)
    except Exception as e:  # noqa: BLE001
        _swallow("modules/m2_enrich/api.py:_delete_temp_db", e)


def _cleanup_sqlite_uploads_async(paths_list) -> None:
    """把临时 .db 丢到后台线程删除，**立刻返回**。

    ★ 这是 2026-10-06 修 688MB 上传 "Failed to fetch" 的关键。
      原来清理在 analyze 的 finally 里同步做，于是顺序是
        analyze(37s) → 删 122MB 临时库(可能永久阻塞) → 写响应
      清理一旦卡住（宿主把 os.remove 换成回收站操作时尤其容易），
      客户端等不到任何字节，socket 被判定为无响应直接断开：
      "RemoteDisconnected: Remote end closed connection without response"。
      服务端日志只有 analyze done，没有 dispatch done，也没有 traceback。

      清理本身是 best-effort 的 housekeeping，没有任何理由让用户等它。
      改成守护线程后：响应立即返回，删除在后台慢慢做；
      就算删除失败也只是磁盘上多一个临时文件，下次启动自检会清。
    """
    import threading
    todo = [p for p in (paths_list or []) if p]
    if not todo:
        return
    for p in todo:                      # 收尾清理：先在后台线程外把明显不该删的挡掉
        try:
            if os.path.dirname(os.path.abspath(p)) == os.path.abspath(_init_cleanup_tmpdir()):
                _CLEANUP_WORKERS.add(p)
        except Exception as e:  # noqa: BLE001
            _swallow("modules/m2_enrich/api.py:_cleanup_sqlite_uploads_async.guard", e)

    def _worker():
        for p in list(_CLEANUP_WORKERS):
            _delete_temp_db(p)
            _CLEANUP_WORKERS.discard(p)

    t = threading.Thread(target=_worker, name="cmdb-tmp-cleanup", daemon=True)
    t.start()


def _cleanup_sqlite_uploads(paths_list) -> None:
    """同步清理（仅供测试与进程退出时使用）。请求路径上一律用异步版。"""
    for p in (paths_list or []):
        _delete_temp_db(p)


def _safe_upload_name(raw, idx, suffixes):
    """上传文件名清洗：只取 basename + 强制合法后缀，防目录穿越（浏览器传的 filename 可控）。"""
    name = os.path.basename(str(raw or "")).strip().replace("\x00", "")
    name = re.sub(r'[\\/:*?"<>|]', "_", name)[:80] or ("cmdb_%d%s" % (idx, suffixes[0]))
    if not name.lower().endswith(tuple(suffixes)):
        name += suffixes[0]
    return name


def _safe_db_name(raw, idx):
    """上传 .db 文件名清洗。"""
    return _safe_upload_name(raw, idx, (".db", ".sqlite", ".sqlite3", ".db3"))


def _stage_sqlite_uploads_stream(req, mfiles) -> tuple:
    """大体积 .db 直传：按清单偏移把流式请求体切分成多个 .db 落盘。

    与 _stage_sqlite_uploads 的区别是**不把请求体读进内存**：
    用 1MB 分块边收边切，峰值内存 = chunk 大小，与 CMDB 库实际体积无关。

    实现要点（单指针状态机，别写成"chunk 跨边界就递归续写"那种绕法——
    第一版就是这么写的，结果只落盘了最后一个文件，前面全丢）：
      buf 里放"还没分配给任何文件"的字节；每轮先补满当前文件，
      补满后打开下一个继续。收尾时必须校验「所有文件都刚好写满」，
      少一个字节都说明上传被截断，要报错回滚而不是把半个 .db 交给 sqlite3
      ——那样用户只会看到 "file is not a database"，完全猜不到是上传断了。
    """
    return _stage_manifest_stream(req, mfiles, _safe_db_name,
                                  ("数据库文件", "库在服务器上？直接填路径"))


def _stage_file_uploads_stream(req, mfiles) -> tuple:
    """大体积 CSV/xlsx 直传：同样按清单切分落盘（2026-10-06）。

    ★ 为什么 file 模式也必须走流式（这是「明明有网却报网络中断」的根因）：
      core/server.py 对超过 32MB 的请求体走 begin_stream()，此时 req.body 是**空的**
      （内容留在 socket 流里）。而 file 模式原先只在内存路径里按清单偏移切 body，
      拿到的是空字节 → 立刻返回 400「文件清单与请求体大小不符」。
      浏览器那边却还在往 socket 写几百 MB，服务端此时已经开始写响应并关闭连接，
      客户端收到的是「连接被中止」(WinError 10053)，XHR 触发 onerror，
      前端只能报「网络中断，请检查连接后重试」——真实原因（清单不匹配）被完全掩盖。

      落盘后由 _file_entries_from_paths 逐个读入、用完即弃，
      峰值内存 = 单个文件大小，而不是全部文件之和。
    """
    return _stage_manifest_stream(req, mfiles, _safe_upload_name_generic,
                                  ("上传文件", "删掉体积最大的几张表后分批上传，或只传漏洞台账+资产表"))


def _safe_upload_name_generic(raw, idx):
    """CSV/xlsx 等表格文件：保留原扩展名，仅清洗目录穿越字符。"""
    name = os.path.basename(str(raw or "")).strip().replace("\x00", "")
    name = re.sub(r'[\\/:*?"<>|]', "_", name)[:80]
    if not name:
        name = "cmdb_%d.xlsx" % idx
    # 必须有能识别类型的扩展名，否则下游 read_upload / _rows_from_bytes 全都跳过
    if not os.path.splitext(name)[1]:
        name += ".xlsx"
    return name


def _stage_manifest_stream(req, mfiles, name_fn, hint) -> tuple:
    """把流式请求体按 X-Cmdb-Manifest 清单切分成多个文件落盘（file / sqlite 共用）。

    返回 (落盘路径列表, 错误信息)。错误信息里带 hint=(对象称呼, 备选方案)，
    用于截断提示 —— 上传几百 MB 时被中断是最常见的失败原因，必须说清怎么补救。
    """
    import time as _t
    CHUNK = 1024 * 1024
    try:
        tmp_dir = os.path.join(paths.DATA_DIR, "tmp_cmdb")
        os.makedirs(tmp_dir, exist_ok=True)
    except Exception as e:  # noqa: BLE001
        _swallow("modules/m2_enrich/api.py:_stage_manifest_stream.mkdir", e)
        return [], "无法创建临时目录（%s无法落盘）：%s" % (hint[0], str(e)[:120])

    # 先把清单解析成 [(路径, 剩余字节数)]，size 非法在这里就报错，不写任何文件
    # 戳必须与 _stage_sqlite_uploads 共用同一生成器，否则多个落盘点同秒上传会撞名
    stamp = _unique_stamp()
    plan = []
    for i, mf in enumerate(mfiles):
        try:
            sz = int(mf.get("size") or 0)
        except (TypeError, ValueError):
            return [], "文件清单第 %d 项 size 非法" % (i + 1)
        if sz < 0:
            return [], "文件清单第 %d 项 size 为负" % (i + 1)
        plan.append([os.path.join(
            tmp_dir, "%s_%02d_%s" % (stamp, i, name_fn(mf.get("filename"), i))), sz])

    out = []
    fh = None
    cur = -1        # 当前正在写的 plan 下标
    try:
        buf = b""
        # ★ 先把第 0 个文件打开：单个 0 字节文件时 iter_body 一个 chunk 都不产出，
        #   下面的循环体一次都进不去，文件就永远不会被创建出来，
        #   最后 os.path.isfile 判成「写入不完整」整单失败。
        cur = 0
        fh = open(plan[0][0], "wb")
        for chunk in req.iter_body(CHUNK):
            buf += chunk
            while True:
                if cur < 0 or plan[cur][1] == 0:
                    # 当前文件已写满（或还没开始）→ 关掉上一个，开下一个
                    if cur + 1 >= len(plan):
                        break                     # 数据比清单还多，剩下的忽略
                    if fh is not None:
                        fh.close()
                        fh = None
                    if cur >= 0:
                        out.append(plan[cur][0])  # 确认上一个真的落盘了
                    cur += 1
                    # ★ 0 字节文件也要真实创建出来：open 一次即建出空文件，
                    #   不能因为「没有数据可写」就跳过 —— 否则 os.path.isfile
                    #   校验会把这一项判成「写入不完整」而整单失败。
                    fh = open(plan[cur][0], "wb")
                    if plan[cur][1] == 0:
                        continue                 # 立刻写满，进入下一轮开下一个
                if not buf:
                    break
                take = min(len(buf), plan[cur][1])
                fh.write(buf[:take])
                plan[cur][1] -= take
                buf = buf[take:]
        if fh is not None:
            fh.close()
            fh = None
        if cur >= 0:
            out.append(plan[cur][0])              # 最后一个文件也要记账

        # 收尾校验：每个声明的文件都必须刚好写满
        short = [(i, n) for i, (_, n) in enumerate(plan) if n > 0]
        if short:
            _cleanup_sqlite_uploads_async([p for p, _ in plan])
            return [], ("上传被中断：%s 还差字节没收到（共声明 %d 个文件）。"
                        "几百 MB 的大文件建议改用「%s」，或分批上传。" % (
                            "、".join("第%d项差%d" % (i + 1, n) for i, n in short[:3]),
                            len(plan), hint[1]))
        missing = [p for p, _ in plan if not os.path.isfile(p)]
        if missing:
            _cleanup_sqlite_uploads_async([p for p, _ in plan])
            return [], "%s写入不完整，请重试" % hint[0]
        return [p for p, _ in plan], ""
    except Exception as e:  # noqa: BLE001
        _swallow("modules/m2_enrich/api.py:_stage_manifest_stream", e)
        # ★ 用 plan 而非 plan[0][0]：清单解析阶段就 return 的路径下 plan 可能为空
        #   （例如首项 size 非法），写 plan[0][0] 会抛 IndexError，
        #   把「清单非法」这个真实原因掩盖成看不懂的 tuple index out of range。
        _cleanup_sqlite_uploads_async([p for p, _ in plan if p])
        return [], "%s写入临时目录失败：%s" % (hint[0], str(e)[:120])
    finally:
        if fh is not None:
            try:
                fh.close()
            except Exception:  # noqa: BLE001
                pass


def _file_entries_from_paths(items):
    """把 [(原始文件名, 落盘路径)] 组装成下游要的 files=[{filename,data}]。

    ★ 用完即弃：整份清单的数据全部读进内存就是「10 个 xlsx 共 374MB」的体积，
      浏览器与服务端都会被拖垮。这里让调用方按需逐个取出，读完一个丢一个。
      返回的对象实现了 __iter__，与普通 list 用法兼容，但不会同时持有全部字节。
    """
    class _LazyFiles:
        """惰性文件序列：按需从磁盘读入，支持「读完一项立刻释放」。

        用法上有两个阶段都要遍历（位置索引 → 逐文件解析），而每个阶段只关心
        当前这一个文件的字节。所以：__iter__ 产出第 i 项之前会先把第 i 项读进来，
        解析完调 release_one() 丢掉它 —— 峰值内存因此是**单个文件**而不是全部之和。
        374MB 的 10 个 xlsx 一次性 list() 进来会直接打爆内存。
        """

        def __init__(self, pairs):
            self._pairs = list(pairs)
            self._cache = {}
            self._cur = None          # 当前 __iter__ 正产出的下标

        def _load(self, i):
            if i not in self._cache:
                name, path = self._pairs[i]
                try:
                    with open(path, "rb") as fh:
                        self._cache[i] = {"filename": name, "data": fh.read()}
                except OSError:
                    self._cache[i] = {"filename": name, "data": b""}
            return self._cache[i]

        def __len__(self):
            return len(self._pairs)

        def __getitem__(self, i):
            if isinstance(i, slice):
                return [self._load(k) for k in range(*i.indices(len(self._pairs)))]
            if i < 0:
                i += len(self._pairs)
            if not 0 <= i < len(self._pairs):
                raise IndexError(i)
            return self._load(i)

        def __iter__(self):
            for i in range(len(self._pairs)):
                self._cur = i
                yield self._load(i)
            self._cur = None

        def release_one(self):
            """丢掉当前项的字节（解析完立刻调用）。非迭代状态下调用是空操作。"""
            if self._cur is not None:
                self._cache.pop(self._cur, None)

        def release(self):
            """释放全部缓存（分析结束后调用，把内存还给系统）。"""
            self._cache.clear()
            self._cur = None

    return _LazyFiles(items)


def _mask_level(req) -> str:
    """Markdown 导出的脱敏级别：?mask=off|basic|strict，非法值退回 off。

    ★ 报告含责任人邮箱 / 内网 IP / 业务系统名，外发前应显式选 basic 或 strict；
      默认 off 是为了不破坏既有交付件与前端契约，但报告会自带保密提示。
    """
    v = (req.q("mask") or "").strip().lower()
    return v if v in ("off", "basic", "strict") else "off"


def _md_filename(kind: str, rep) -> str:
    """Markdown 导出的落盘文件名（含 Content-Disposition 所需的全部信息）。

    ★ 为什么必须有：`req.send(...)` 只有传了 `filename=` 才会写
      `Content-Disposition: attachment`。**不传就等于没要求下载** ——
      浏览器会按 `text/markdown` 内联渲染，用户点「下载」看到的是
      一整页纯文本源码（2026-10-07 用户截图：点按钮跳到一个 Markdown 页面）。
      之前两个 md=1 分支都只设了 ctype、漏了 filename，所以"下载"变成了"跳转预览"。
    ★ 同时这也是**安全属性**：附件下载不会把响应体当页面渲染，避免
      报告里的 `<script>` 之类内容在浏览器里被当作 HTML 执行（XSS 面）。
    """
    rid = str((rep or {}).get("id") or "")
    stamp = rid[-8:] if len(rid) >= 8 else (rid or time.strftime("%Y%m%d"))
    return "%s_%s.md" % (kind, stamp)


def _md_response(req, text_md: str, kind: str, rep) -> object:
    """统一的 Markdown 导出响应：UTF-8 + text/markdown + attachment 文件名。

    单一入口，避免以后再有人只改一处、另一处继续"跳转预览"。
    """
    return req.send(200, str(text_md).encode("utf-8"),
                    ctype="text/markdown; charset=utf-8",
                    filename=_md_filename(kind, rep))


def handle_cmdb_scan_post(req):
    """接收 CMDB 连接参数 / 内联数据 → 分析 → 返回风险报告。"""
    import cmdb_scan as CM
    import json as _json
    import urllib.parse as _up

    # ★ 二进制直传（2026-10-05）：多文件大导出不再走 base64+JSON——10 文件 366MB
    #   base64 后膨胀到 ~490MB，浏览器编码 + 服务端 json.loads 各要十几秒、内存翻三倍。
    #   新协议：文件清单放 X-Cmdb-Manifest 头（URI 编码 JSON），body = 各文件原始
    #   字节按清单顺序拼接。旧 JSON/b64 协议完全兼容保留。
    ctype = (req.header("Content-Type") or "").lower()
    manifest_raw = req.header("X-Cmdb-Manifest") or ""
    if "octet-stream" in ctype and manifest_raw:
        try:
            manifest = _json.loads(_up.unquote(manifest_raw))
        except ValueError:
            return req.json({"ok": False, "error": "X-Cmdb-Manifest 请求头解析失败"}, 400)
        mode = str(manifest.get("mode") or "file").strip().lower()
        if mode not in ("file", "sqlite"):
            return req.json({"ok": False, "error": "二进制直传仅支持「上传文件」或「数据库文件」模式"}, 400)
        mfiles = manifest.get("files") or []
        # ★ 上限提到 40（2026-10-05）：真实 CMDB 全量导出有 20+ 张表（漏洞台账 +
        #   物理机/机房/机柜/中间件…）。原来的 10 会逼着运维分批上传，而分批会把
        #   「机房/机柜表」和「漏洞台账」拆到不同请求里 → 后者查不到位置，
        #   报告的位置列整列变成「未登记」，四要素直接缺一项。20+ 张一次传完反而
        #   是唯一能出完整报告的用法。仍保留上限是为了挡住误传的巨型包。
        MAX_FILES = 40
        if not mfiles:
            return req.json({"ok": False, "error": "文件清单为空"}, 400)
        if len(mfiles) > MAX_FILES:
            return req.json({"ok": False, "error": "文件清单 %d 个，超过单次上限 %d；"
                             "请只上传 CMDB 导出的相关表（漏洞台账 + 资产 + 机房机柜），"
                             "不要把全量业务表一起传" % (len(mfiles), MAX_FILES)}, 400)
        # ★ 大请求体走流式（2026-10-06）：超过 32MB 时 core/server.py 走 begin_stream()，
        #   内容留在 socket 流里、req.body 为空。此时**必须**用 iter_body 边收边切分落盘：
        #     · sqlite 模式 → 切成 .db（下游 sqlite3 只能按路径打开）
        #     · file 模式   → 切成 xlsx/csv（下游吃 bytes，但逐个读入即弃，避免 374MB 全驻留）
        #   原来只有 sqlite 分支走流式，file 模式仍在内存路径里切空 body →
        #   立刻返回 400「文件清单与请求体大小不符」，而浏览器还在写 socket，
        #   连接被服务端关闭 → 前端只看到「网络中断」，真实原因被完全掩盖。
        if hasattr(req, "iter_body") and not req.body and mfiles:
            if mode == "sqlite":
                db_paths, db_err = _stage_sqlite_uploads_stream(req, mfiles)
                if db_err:
                    return req.json({"ok": False, "error": db_err}, 400)
                cfg = {"mode": "sqlite", "paths": db_paths,
                       "tables": str(manifest.get("tables") or "").strip(),
                       "name": str(manifest.get("name") or "").strip(),
                       "_tmp_dbs": db_paths}
            else:
                f_paths, f_err = _stage_file_uploads_stream(req, mfiles)
                if f_err:
                    return req.json({"ok": False, "error": f_err}, 400)
                pairs = [(_safe_upload_name_generic(mf.get("filename"), i), p)
                         for i, (mf, p) in enumerate(zip(mfiles, f_paths))]
                cfg = {"mode": "file",
                       "files": _file_entries_from_paths(pairs),
                       "name": str(manifest.get("name") or "").strip(),
                       "_tmp_dbs": f_paths}
        else:
            body_bytes = req.body or b""
            cfg_files = []
            off = 0
            for mf in mfiles:
                try:
                    size = int(mf.get("size") or 0)
                except (TypeError, ValueError):
                    return req.json({"ok": False, "error": "文件清单 size 非法"}, 400)
                if size < 0 or off + size > len(body_bytes):
                    return req.json({"ok": False, "error": "文件清单与请求体大小不符"}, 400)
                cfg_files.append({"filename": str(mf.get("filename") or "cmdb_assets.xlsx"),
                                  "data": body_bytes[off:off + size]})
                off += size
            if off != len(body_bytes):
                return req.json({"ok": False, "error": "文件清单与请求体大小不符"}, 400)
            if mode == "sqlite":
                # ★ 数据库文件上传（2026-10-06）：.db 是二进制容器，不能像 CSV 那样
                #   在内存里解析，必须先落盘再让 cmdb_scan 用 sqlite3 打开。落临时目录、
                #   分析完即删（不进 data/ 免得长期堆积 CMDB 全量库）。
                db_paths, db_err = _stage_sqlite_uploads(cfg_files)
                if db_err:
                    return req.json({"ok": False, "error": db_err}, 400)
                cfg = {"mode": "sqlite", "paths": db_paths,
                       "tables": str(manifest.get("tables") or "").strip(),
                       "name": str(manifest.get("name") or "").strip(),
                       "_tmp_dbs": db_paths}
            else:
                cfg = {"mode": "file", "files": cfg_files,
                       "name": str(manifest.get("name") or "").strip()}
    else:
        body = {}
        try:
            body = req.json_body() or {}
        except Exception:  # noqa: BLE001
            body = {}
        mode = str(body.get("mode") or "inline").strip().lower()
        cfg = {"mode": mode}

        if mode == "rest":
            # 地址优先用请求里的，凭证优先用环境变量（不在请求里传 Key，也不写进代码）
            cfg["url"] = str(body.get("url") or "").strip()
            cfg["path"] = str(body.get("path") or "").strip()
            cfg["auth_type"] = str(body.get("auth_type") or "bearer").strip()
            cfg["timeout"] = body.get("timeout")
            cfg["page_size"] = body.get("page_size")          # 分页大小（0=不分页，一次拉全量）
            cfg["page_param"] = str(body.get("page_param") or "page").strip()
            cfg["size_param"] = str(body.get("size_param") or "per_page").strip()
            tok = _cmdb_env_token() or str(body.get("token") or "").strip()
            cfg["token"] = tok
            if not cfg["url"]:
                return req.json({"ok": False, "error": "REST 模式需要提供 CMDB 地址（url）"}, 400)
        elif mode == "sqlite":
            # 本地 SQLite 数据库直连：传文件路径 + 可选表名
            cfg["path"] = str(body.get("path") or body.get("db") or "").strip()
            cfg["tables"] = str(body.get("tables") or "").strip()
            if not cfg["path"]:
                return req.json({"ok": False, "error": "SQLite 模式需要提供数据库文件路径（path）"}, 400)
        elif mode == "file":
            # 文件模式：接收 base64（前端读文件后传 b64）
            # 多文件（2026-10-05）：files=[{filename,b64},...] 一次传多个，合并出一份报告；
            # 兼容旧的单文件 b64/filename 写法。
            MAX_FILES = 40        # 与二进制直传一致：20+ 张 CMDB 导表要能一次传完
            files_in = body.get("files")
            if not isinstance(files_in, list) or not files_in:
                legacy_b64 = body.get("b64") or body.get("base64")
                files_in = [{"filename": body.get("filename") or body.get("name"),
                             "b64": legacy_b64}] if legacy_b64 else []
            # ★ 原来超出上限的文件被静默丢弃（files_in[:MAX_FILES]），运维传 21 张
            #   表会以为全传了，实际第 11 张之后根本没进报告。超限必须明确报错。
            if len(files_in) > MAX_FILES:
                return req.json({"ok": False, "error": "文件数 %d 超过单次上限 %d；"
                                 "请只上传 CMDB 导出的相关表（漏洞台账 + 资产 + 机房机柜）"
                                 % (len(files_in), MAX_FILES)}, 400)
            cfg_files = []
            for f in files_in:
                if not isinstance(f, dict):
                    continue
                b64 = f.get("b64") or f.get("base64")
                if not b64:
                    continue
                try:
                    data = base64.b64decode(b64)
                except Exception:  # noqa: BLE001
                    return req.json({"ok": False, "error": "文件内容 base64 解码失败：%s"
                                     % (f.get("filename") or "未命名")}, 400)
                cfg_files.append({"filename": str(f.get("filename") or "cmdb_assets.txt"),
                                  "data": data})
            if not cfg_files:
                return req.json({"ok": False, "error": "文件模式需要提供文件内容（files 数组或 b64）"}, 400)
            cfg["files"] = cfg_files
        else:
            cfg["mode"] = "inline"
            cfg["text"] = str(body.get("text") or "")

        cfg["name"] = str(body.get("name") or "").strip()

    try:
        r = CM.analyze(req.engine, cfg)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        return req.json({"ok": False, "error": "CMDB 分析失败：%s" % str(e)[:200]}, 500)
    finally:
        # ★ 临时 .db 用完即删（成功/失败/异常都删）。报告已经落盘成 JSON，
        #   后续导出 Markdown 走 load_report，不再需要原始库。
        #   必须异步：同步删几百 MB 的库会阻塞响应写出，客户端只看到 Failed to fetch。
        _cleanup_sqlite_uploads_async(cfg.get("_tmp_dbs"))

    if not r.get("ok"):
        return req.json(r, 400)

    # ★ 分析完成后按需发邮件（2026-10-06）：用户可在上传区填收件邮箱勾选"发给我"，
    #   也可在报告页对历史报告补发。收件人与脱敏级别从 query 取，
    #   发送走守护线程 —— SMTP 连不上时最多阻塞 30s，绝不能让用户干等。
    mail_note = _maybe_send_report_mail(req, r["report"])

    if req.q("md") not in ("", "0", "false"):
        return _md_response(req, CM.report_to_markdown(r["report"], _mask_level(req)),
                            "CMDB风险评估报告", r["report"])
    # 落盘失败要透出：否则 POST 200 ok=True，之后 GET?id=... 404，报告"消失"
    out = {"ok": True, "id": r["report"]["id"], "report": r["report"]}
    if r.get("warn_persist"):
        out["warn"] = r["warn_persist"]
    if mail_note:
        out["mail"] = mail_note
    return req.json(out)


def _maybe_send_report_mail(req, report) -> dict:
    """分析/导出后按 query 里的 mail 参数发信。返回给前端的状态（失败不阻断分析）。

    参数（query，避免污染 body 协议）：
        mail   = 收件邮箱（逗号分隔）
        mask   = 脱敏级别 basic(默认外发) / strict
        fmt    = md(默认) / xlsx / both —— 发哪一份
        mail2  = 第二收件人：把"另一份"发给不同的人（如领导看完整版、运维收台账）
    """
    import mailer as ML
    raw = (req.q("mail") or "").strip()
    if not raw:
        return {}
    chk = ML.validate(raw)
    if not chk.get("ok"):
        return {"queued": False, "ok": False, "error": chk.get("error") or "收件人无效"}
    if not ML.configured():
        return {"queued": False, "ok": False, "error": ML.config_status()["hint"]}

    fmt = (req.q("fmt") or "md").strip().lower()
    if fmt not in ("md", "xlsx", "both"):
        fmt = "md"
    mask = _mail_mask(req)
    try:
        import cmdb_scan as CM
        md_text = CM.report_to_markdown(report, mask) if fmt in ("md", "both") else ""
    except Exception as e:  # noqa: BLE001
        return {"queued": False, "ok": False, "error": "报告转 Markdown 失败：%s" % str(e)[:100]}

    xlsx_bytes = None
    if fmt in ("xlsx", "both"):
        import cmdb_ticket_xlsx as TX
        try:
            xlsx_bytes = TX.build_xlsx(report, mask)
        except Exception as e:  # noqa: BLE001
            return {"queued": False, "ok": False,
                    "error": "简略台账生成失败：%s" % str(e)[:120]}
    if fmt == "xlsx":
        import cmdb_ticket_xlsx as TX
        pv = TX.build_rows_preview(report)
        md_text = ("附件为《CMDB 处置简略台账》，共 %d 条工单（严重 %d / 高 %d / 中 %d / 低 %d），"
                   "按责任人、风险等级、三步期限组织，可直接用于派单。\n\n"
                   "完整推导过程与证据链见「七章制 Markdown 版」。"
                   % (pv.get("tickets") or 0,
                      (pv.get("by_severity") or {}).get("R1", 0),
                      (pv.get("by_severity") or {}).get("R2", 0),
                      (pv.get("by_severity") or {}).get("R3", 0),
                      (pv.get("by_severity") or {}).get("R4", 0)))

    ML.clear_last_result()
    ML.send_async(chk["recipients"], report, md_text, mask=mask,
                  attach_md=(fmt in ("md", "both")), xlsx_bytes=xlsx_bytes)

    note = {"queued": True, "ok": True, "to": chk["recipients"],
            "mask": mask, "fmt": fmt,
            "note": "已开始发送，可在「发送状态」里查看结果"}

    # ★ 第二收件人：把另一份发给他。格式互补（一份 md 一份 xlsx），
    #   所以先发的这份用 fmt，另一份自动取反。
    raw2 = (req.q("mail2") or "").strip()
    if raw2:
        chk2 = ML.validate(raw2)
        if chk2.get("ok"):
            other = "xlsx" if fmt != "xlsx" else "md"
            try:
                if other == "xlsx":
                    import cmdb_ticket_xlsx as TX
                    _xb = TX.build_xlsx(report, mask)
                    import cmdb_scan as _CM
                    _md = ("附件为《CMDB 处置简略台账》，可直接用于派单。"
                           "完整推导过程见七章制 Markdown 版。")
                else:
                    import cmdb_scan as _CM
                    _xb = None
                    _md = _CM.report_to_markdown(report, mask)
                ML.send_async(chk2["recipients"], report, _md, mask=mask,
                              attach_md=(other == "md"), xlsx_bytes=_xb)
                note["to2"] = chk2["recipients"]
                note["fmt2"] = other
            except Exception as e:  # noqa: BLE001
                note["warn2"] = "第二份发送失败：%s" % str(e)[:100]
        else:
            note["warn2"] = chk2.get("error") or "第二收件人无效"
    return note


def _mail_mask(req) -> str:
    """邮件脱敏级别。**默认 basic**（外发不能带原文），非法值也退回 basic。"""
    v = (req.q("mask") or "").strip().lower()
    return v if v in ("basic", "strict") else "basic"


def handle_cmdb_scan_get(req):
    """历史列表 / 单份报告 / Markdown 导出。"""
    import cmdb_scan as CM
    sid = req.q("id").strip()
    md = req.q("md") not in ("", "0", "false")
    if sid:
        rep = CM.load_report(sid)
        if not rep:
            return req.json({"ok": False, "error": "报告不存在或已被清理", "id": sid}, 404)
        if md:
            return _md_response(req, CM.report_to_markdown(rep, _mask_level(req)),
                                "CMDB风险评估报告", rep)
        return req.json({"ok": True, "id": sid, "report": rep})
    items = CM.list_scans()
    # 标出详情没落盘成功的条目：否则用户在列表里点进去才发现404
    for it in items:
        if it.get("persist_failed"):
            it["detail_missing"] = True
    return req.json({"ok": True, "count": len(items), "items": items})


def handle_cmdb_config(req):
    """CMDB 连接配置状态（只报是否已配置，绝不下发 token 明文）。"""
    cfg = _cmdb_config()
    return req.json({"ok": True, "url_configured": bool(cfg.get("url")),
                     "url": cfg.get("url") or "",
                     "token_configured": bool(cfg.get("token_configured")),
                     "auth_type": cfg.get("auth_type") or "bearer",
                     "path": cfg.get("path") or ""})


# ======================================================================
# 邮件投递（2026-10-06）
# ======================================================================
def handle_mail_status(req):
    """SMTP 配置状态 + 校验收件人 + 上次发送结果（前端上传区实时提示）。

    GET /api/cmdb_scan/mail?to=a@b.com
    """
    import mailer as ML
    out = dict(ML.config_status())
    to = (req.q("to") or "").strip()
    if to:
        chk = ML.validate(to)
        out["to_check"] = {"ok": bool(chk.get("ok")),
                           "recipients": chk.get("recipients") or [],
                           "rejected": chk.get("rejected") or [],
                           "error": chk.get("error") or ""}
    lr = ML.last_result()
    if lr:
        out["last"] = {"ok": bool(lr.get("ok")), "to": lr.get("to") or [],
                       "error": lr.get("error") or "", "mask": lr.get("mask") or ""}
    return req.json(out)


def handle_mail_send_post(req):
    """对**已生成**的报告补发邮件（历史记录 / 报告详情页用）。

    POST /api/cmdb_scan/mail
      {id, to, mask, attach, fmt}
        fmt = md   → 正文七章制 Markdown（默认）
             xlsx  → 附件为简略版处置台账，正文是简短摘要
             both  → 正文 Markdown + 同时带 .md 与 .xlsx 两个附件
        to  = 收件人。想"两个版本发给不同的人"就调两次、to 各填一组。

    与分析时发信走同一个 mailer，行为一致；这里不会重新分析，所以很快。
    """
    import mailer as ML
    import cmdb_scan as CM
    body = {}
    try:
        body = req.json_body() or {}
    except Exception:  # noqa: BLE001
        body = {}
    if not isinstance(body, dict):
        body = {}

    sid = str(body.get("id") or req.q("id") or "").strip()
    if not sid:
        return req.json({"ok": False, "error": "缺少报告 id"}, 400)
    rep = CM.load_report(sid)
    if not rep:
        return req.json({"ok": False, "error": "报告不存在或已被清理", "id": sid}, 404)

    chk = ML.validate(body.get("to") or req.q("to"))
    if not chk.get("ok"):
        return req.json({"ok": False, "error": chk.get("error") or "收件人无效"}, 400)
    if not ML.configured():
        return req.json({"ok": False, "error": ML.config_status()["hint"]}, 400)

    mask = str(body.get("mask") or "basic").strip().lower()
    if mask not in ("basic", "strict"):
        mask = "basic"
    fmt = str(body.get("fmt") or req.q("fmt") or "md").strip().lower()
    if fmt not in ("md", "xlsx", "both"):
        fmt = "md"
    want_xlsx = fmt in ("xlsx", "both")
    # attach=True 保留兼容旧调用；xlsx/both 形态本身就以附件为主，等价于要附件
    attach = bool(body.get("attach")) or want_xlsx

    try:
        md_text = CM.report_to_markdown(rep, mask) if fmt in ("md", "both") else ""
    except Exception as e:  # noqa: BLE001
        return req.json({"ok": False, "error": "报告转 Markdown 失败：%s" % str(e)[:120]}, 500)

    xlsx_bytes = None
    if want_xlsx:
        import cmdb_ticket_xlsx as TX
        try:
            xlsx_bytes = TX.build_xlsx(rep, mask)
        except Exception as e:  # noqa: BLE001
            return req.json({"ok": False, "error": "简略台账生成失败：%s" % str(e)[:150]}, 500)

    if fmt == "xlsx":
        # 纯台账：正文给一份人话摘要，别让收件人打开附件才知道是什么
        import cmdb_ticket_xlsx as TX
        pv = TX.build_rows_preview(rep)
        md_text = ("附件为《CMDB 处置简略台账》，共 %d 条工单"
                   "（严重 %d / 高 %d / 中 %d / 低 %d），"
                   "按责任人、风险等级、三步期限组织，可直接用于派单。\n\n"
                   "完整推导过程与证据链见「七章制 Markdown 版」。"
                   % (pv.get("tickets") or 0,
                      (pv.get("by_severity") or {}).get("R1", 0),
                      (pv.get("by_severity") or {}).get("R2", 0),
                      (pv.get("by_severity") or {}).get("R3", 0),
                      (pv.get("by_severity") or {}).get("R4", 0)))

    ML.clear_last_result()
    ML.send_async(chk["recipients"], rep, md_text, mask=mask, attach_md=attach,
                  xlsx_bytes=xlsx_bytes)
    return req.json({"ok": True, "queued": True, "id": sid,
                     "to": chk["recipients"], "mask": mask, "attach": attach,
                     "fmt": fmt,
                     "xlsx_bytes": len(xlsx_bytes) if xlsx_bytes else 0,
                     "note": "已开始发送，可在「发送状态」里查看结果"})


# ======================================================================
# 简略版处置台账（2026-10-06）—— 参照客户 SVMS_TKT 模板的精简 Excel
# ======================================================================
def _report_for_export(req, sid: str):
    """按 id 取报告；id 为空时取最近一份。返回 (报告, 错误响应或 None)。"""
    import cmdb_scan as CM
    sid = (sid or "").strip()
    if sid:
        rep = CM.load_report(sid)
        if not rep:
            return None, req.json({"ok": False, "error": "报告不存在或已被清理",
                                   "id": sid}, 404)
        return rep, None
    items = CM.list_scans()
    real = [i for i in items if not i.get("persist_failed")]
    if not real:
        return None, req.json({"ok": False, "error": "还没有可导出的报告，请先做一次分析"}, 404)
    rep = CM.load_report(real[0].get("id"))
    if not rep:
        return None, req.json({"ok": False, "error": "最近一份报告的详情已不可用"}, 404)
    return rep, None


def handle_cmdb_tickets_get(req):
    """下载简略版处置台账 xlsx。

    GET /api/cmdb_scan/tickets?id=CMDB-xxx&mask=off|basic|strict

    ★ 与 ?md=1（七章制 Markdown）**并存不互斥**：两个独立导出入口，
      日常派单用本表，评审归档用 md。用户可任选，也可都要。
    """
    import cmdb_ticket_xlsx as TX
    rep, err = _report_for_export(req, req.q("id"))
    if err:
        return err
    try:
        pv = TX.build_rows_preview(rep)
        if not pv.get("tickets"):
            # 空表下载下来用户只会看到"没内容"，说清原因比给一张空表有用
            return req.json({"ok": False,
                             "error": "这份报告没有可派单的处置工单（分析未命中已知漏洞，"
                                      "或上传的是纯资产表而无漏洞台账）。"
                                      "请确认上传内容含「漏洞台账」表，或改用七章制 Markdown。"},
                            400)
        data = TX.build_xlsx(rep, _mask_level(req))
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        return req.json({"ok": False, "error": "简略台账生成失败：%s" % str(e)[:180]}, 500)
    fname = "CMDB处置简略台账_%s.xlsx" % str(rep.get("id") or time.strftime("%Y%m%d"))[-8:]
    return req.send(200, data, ctype=(
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        filename=fname)


def handle_cmdb_tickets_preview(req):
    """简略台账的统计预览（不生成文件，用于前端提示"共 N 条工单"）。"""
    import cmdb_ticket_xlsx as TX
    rep, err = _report_for_export(req, req.q("id"))
    if err:
        return err
    try:
        pv = TX.build_rows_preview(rep)
    except Exception as e:  # noqa: BLE001
        return req.json({"ok": False, "error": str(e)[:150]}, 500)
    pv["ok"] = True
    pv["id"] = rep.get("id")
    return req.json(pv)


# ======================================================================
# STIX 2.1 / TAXII 2.1 标准导出
# ======================================================================
def handle_stix_bundle(req):
    import stix_export as SX
    sev = req.q("sev").strip().upper() or "LOW"
    kev_only = req.q("kev") not in ("", "0", "false")
    days = req.q("days").strip()
    limit = req.q("limit").strip()
    kw = {"min_sev": sev if sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "LOW",
          "kev_only": kev_only}
    if days:
        try:
            kw["days"] = max(float(days), 0.1)
        except ValueError:
            pass
    try:
        kw["limit"] = min(max(int(limit), 1), 5000) if limit else 2000
    except ValueError:
        pass
    ids = [x for x in (req.q("ids") or "").replace("，", ",").split(",") if x.strip()]
    if ids:
        kw["ids"] = ids
    b = SX.bundle(req.engine.docs, **kw)
    if req.q("md") not in ("", "0", "false"):
        return _md_response(req, SX.export_markdown(b), "STIX情报导出", b)
    fname = "aisec-D_stix_%s.json" % time.strftime("%Y%m%d-%H%M%S")
    return req.json({"ok": True, "filename": fname,
                     "count": len(b.get("objects") or []),
                     "bundle": b})


def _taxii_guard(req):
    import stix_export as SX
    if not SX.check_taxii_auth(req.header("Authorization") or "", req.q("key") or ""):
        req.json(SX.taxii_error(401, "Unauthorized",
                                "缺少或错误的 AISEC_TAXII_KEY 凭证"), 401)
        return False
    return True


def handle_taxii_discovery(req):
    import stix_export as SX
    if not _taxii_guard(req):
        return
    host = req.header("Host") or "127.0.0.1:8848"
    return req.json(SX.taxii_discovery(host=host))


def handle_taxii_root(req):
    import stix_export as SX
    if not _taxii_guard(req):
        return
    return req.json(SX.taxii_root())


def handle_taxii_collections(req):
    import stix_export as SX
    if not _taxii_guard(req):
        return
    return req.json(SX._collections_payload())


def handle_taxii_objects(req):
    import stix_export as SX
    if not _taxii_guard(req):
        return
    # 路由是精确注册的（/taxii2/root/collections/<cid>/objects），cid 直接从 path 取
    parts = [p for p in req.path.split("/") if p]
    cid = parts[3] if len(parts) > 3 else ""
    env = SX.taxii_objects(cid, req.engine.docs,
                           match_id=req.q("match[id]") or req.q("id") or "",
                           added_after=req.q("added_after") or "",
                           limit=req.q("limit") or 2000)
    if env is None:
        return req.json(SX.taxii_error(404, "Not Found",
                                       "集合不存在，可用：%s" % ",".join(SX.COLLECTIONS)), 404)
    return req.json(env)


# ======================================================================
# 漏洞复现环境一键生成（生成器：产出 compose+verify 的 zip，不跑 Docker）
# ======================================================================
def handle_vuln_env_get(req):
    import vuln_env as VE
    cid = req.q("id").strip().upper()
    if not cid:
        return req.json({"ok": False, "error": "缺少 id（CVE 编号）"}, 400)
    doc = _find_doc(req.engine, cid)
    if doc is None:
        return req.json({"ok": False, "error": "语料中找不到 %s" % cid}, 404)
    return req.json(VE.plan(doc))


def handle_vuln_env_post(req):
    import vuln_env as VE
    body = req.json_body() or {}
    cid = str(body.get("id") or "").strip().upper()
    if not cid:
        return req.json({"ok": False, "error": "缺少 id（CVE 编号）"}, 400)
    doc = _find_doc(req.engine, cid)
    if doc is None:
        return req.json({"ok": False, "error": "语料中找不到 %s" % cid}, 404)
    pocs = body.get("poc_urls")
    r = VE.build_zip(doc, poc_urls=[str(x) for x in pocs] if isinstance(pocs, list) else None)
    return req.json(r, 200 if r.get("ok") else 400)


def _find_doc(engine, cid: str):
    for d in getattr(engine, "docs", None) or []:
        if isinstance(d, dict) and str(d.get("id") or "").upper() == cid:
            return d
    return None


def handle_enrich_dimensions(req):
    """GET /api/enrich/dimensions —— 富化维度清单 + 当前真实计数。

    验收「富化维度是否达 6 种以上」用：每维都写明后端文件与对外路由，
    有落盘产物的直接给当前真实条数（不是配置项、不是文档声称）。
    """
    try:
        import enrich_dims
    except Exception as e:  # noqa: BLE001
        return req.json({"ok": False, "error": str(e)[:200]}, 500)
    return req.json(enrich_dims.enrich_dimensions())


def handle_enrich_priority(req):
    """GET /api/enrich/priority?id=<CVE> —— 漏洞优先级四元组（P0-2）。

    返回 cvss / epss / kev / reachability 四键齐全（缺失用 null + missing[]），
    口径与 /api/detail 的 priority 完全一致（同一个 core/priority.build）。
    """
    cid = (req.q("id") or "").strip().upper()
    if not cid:
        return req.json({"ok": False, "error": "缺少 id（CVE 编号）"}, 400)
    doc = _find_doc(req.engine, cid)
    if doc is None:
        return req.json({"ok": False, "error": "语料中找不到 %s" % cid}, 404)
    try:
        try:
            import priority as PR
        except Exception:  # pragma: no cover
            from core import priority as PR  # type: ignore
        return req.json({"ok": True, "id": doc.get("id", cid), "priority": PR.build(doc)})
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        return req.json({"ok": False, "error": str(e)[:200]}, 500)


def handle_epss_refresh(req):
    """POST /api/enrich/epss/refresh —— 批量预热/刷新 EPSS 缓存（P0-2）。

    body（JSON，均可选）：``{"cves": ["CVE-..", ...] | "CVE-..,CVE-..", "limit": 1000}``。
    未给 cves 时默认取 KEV 命中的 CVE（几百条量级，小批量建缓存）。
    刷新后把新值挂回内存文档并清检索缓存，`epss>=N` 与 /api/detail 立即可见。
    无网/失败时降级（status=degraded）且缓存不清空，HTTP 仍 200。
    """
    body = req.json_body() or {}
    cves = body.get("cves")
    if isinstance(cves, str):
        cves = [c.strip() for c in cves.split(",") if c.strip()]
    elif not isinstance(cves, list):
        cves = None
    try:
        limit = int(body.get("limit") or 1000)
    except (TypeError, ValueError):
        limit = 1000
    try:
        import epss as EP
    except Exception as e:  # noqa: BLE001
        return req.json({"ok": False, "error": "epss 模块不可用：%s" % str(e)[:150]}, 500)
    res = EP.refresh(cves=cves, limit=limit)
    # 刷新后回挂内存文档 + 清检索缓存（否则 epss>= 算子与 /api/detail 看不到新值）
    try:
        try:
            import priority as PR
        except Exception:  # pragma: no cover
            from core import priority as PR  # type: ignore
        res["attached"] = PR.attach_epss(req.engine)
        if _CORE is not None:
            try:
                _CORE.clear_search_cache()
            except Exception as _sw_e:  # noqa: BLE001
                _swallow("modules/m2_enrich/api.py:epss_refresh.clear_cache", _sw_e)
    except Exception as _e:  # noqa: BLE001
        _swallow("modules/m2_enrich/api.py:epss_refresh.attach", _e)
    return req.json(res)


def register(ctx):
    global _CORE
    _CORE = ctx.core
    ctx.route("GET", "/api/assets", handle_assets)
    # 富化维度清单（维度数 / 关联层 / 每个维度的当前真实计数）——验收覆盖率用
    ctx.route("GET", "/api/enrich/dimensions", handle_enrich_dimensions)
    # P0-2：优先级四元组 + EPSS 缓存刷新
    ctx.route("GET", "/api/enrich/priority", handle_enrich_priority)
    ctx.route("POST", "/api/enrich/epss/refresh", handle_epss_refresh)
    ctx.route("GET", "/api/poc", handle_poc_get)
    ctx.route("POST", "/api/poc", handle_poc_post)
    ctx.route("POST", "/api/asset_scan", handle_asset_scan_post)
    ctx.route("GET", "/api/asset_scan", handle_asset_scan_get)
    ctx.route("POST", "/api/asset_scan/clear", handle_asset_scan_clear)
    ctx.route("GET", "/api/asset_search", handle_asset_search)
    ctx.route("GET", "/api/asset_search/status", handle_asset_search_status)
    ctx.route("GET", "/api/subscribe", handle_subscribe_get)
    ctx.route("POST", "/api/subscribe", handle_subscribe_post)
    ctx.route("POST", "/api/subscribe/update", handle_subscribe_update)
    ctx.route("POST", "/api/subscribe/delete", handle_subscribe_delete)
    ctx.route("POST", "/api/subscribe/check", handle_subscribe_check)
    ctx.route("GET", "/api/subscribe/alerts", handle_subscribe_alerts)
    ctx.route("POST", "/api/subscribe/read", handle_subscribe_read)
    ctx.route("GET", "/api/remediation", handle_remediation)

    # —— 公司 CMDB 连接 + 资产风险分析 ——
    ctx.route("POST", "/api/cmdb_scan", handle_cmdb_scan_post)
    ctx.route("GET", "/api/cmdb_scan", handle_cmdb_scan_get)
    ctx.route("GET", "/api/cmdb_scan/config", handle_cmdb_config)
    # ★ 邮件（2026-10-06）：状态查询 + 对已生成报告补发。
    #   注意注册顺序：dispatch 是精确匹配（table.get(path)），不存在前缀冲突，
    #   但保持 config/mail 在 cmdb_scan 之后声明，与既有阅读顺序一致。
    ctx.route("GET", "/api/cmdb_scan/mail", handle_mail_status)
    ctx.route("POST", "/api/cmdb_scan/mail", handle_mail_send_post)
    # ★ 简略版处置台账（2026-10-06）：与 ?md=1 的七章制**并存不互斥**，
    #   两个导出入口都保留，用户按用途任选（派单用 xlsx，评审归档用 md）。
    ctx.route("GET", "/api/cmdb_scan/tickets", handle_cmdb_tickets_get)
    ctx.route("GET", "/api/cmdb_scan/tickets/preview", handle_cmdb_tickets_preview)

    # —— STIX / TAXII ——
    ctx.route("GET", "/api/stix", handle_stix_bundle)
    ctx.route("GET", "/taxii2/", handle_taxii_discovery)
    ctx.route("GET", "/taxii2/root/", handle_taxii_root)
    ctx.route("GET", "/taxii2/root/collections/", handle_taxii_collections)
    ctx.route("GET", "/taxii2/root/collections/all/objects/", handle_taxii_objects)
    ctx.route("GET", "/taxii2/root/collections/kev/objects/", handle_taxii_objects)
    ctx.route("GET", "/taxii2/root/collections/critical/objects/", handle_taxii_objects)

    # —— 端口测绘（2026-10-08 新增：授权资产 TCP 探测）——
    ctx.route("POST", "/api/port_scan", handle_port_scan_post)
    ctx.route("GET", "/api/port_scan", handle_port_scan_get)

    # —— 项目成分扫描 SCA（2026-10-08 新增：zip/文件夹 → 依赖 → CVE 报告）——
    ctx.route("POST", "/api/project_scan", handle_project_scan_post)
    ctx.route("GET", "/api/project_scan", handle_project_scan_get)
    ctx.route("POST", "/api/project_scan/clear", handle_project_scan_clear)

    # —— 漏洞复现环境生成 ——
    ctx.route("GET", "/api/vuln_env", handle_vuln_env_get)
    ctx.route("POST", "/api/vuln_env", handle_vuln_env_post)

    def _start(core):
        """启动后台巡检线程（有启用订阅才真正干活；无订阅时空转等待）。"""
        try:
            import alert_subscribe as SB
            SB.start_daemon(core.get_engine)
        except Exception as e:  # noqa: BLE001
            _swallow("modules/m2_enrich/api.py:register.on_start", e)

    ctx.on_start(_start)
