# -*- coding: utf-8 -*-
"""
remediation.py —— 漏洞修复方案生成
============================================================
在漏洞详情页回答「这个洞到底怎么修」：

    input : CVE 编号 + 语料条目（desc / CWE / CPE 版本区间 / KEV / CVSS / 补丁链接）
    output: 结构化修复方案 —— 升级路径 / 配置加固（含代码示例）/ 临时缓解 / 验证方法 / 参考

两条生成路径，互为降级（与问答模块「无 Key 降级」口径一致）：
  1. LLM 模式：复用 DeepSeek 兼容配置（poc_scraper.load_config + 环境变量
     AISEC_LLM_API_KEY / DEEPSEEK_BASE_URL / DEEPSEEK_MODEL），严格 JSON 输出，
     要求结合版本区间给出具体升级目标、可执行的配置/代码级缓解；
  2. 模板模式（无 Key / LLM 失败）：用 NVD 元数据做确定性推导 ——
     CWE→加固动作映射 + CVSS 向量→暴露面收敛 + KEV→处置时限，绝不输出"两行空话"。

结果缓存 data/remediation_cache.json（同 CVE 同输入不重复烧 LLM；force=1 可强制重生成）。
统一入口::

    generate(cve_id, engine, force=False) -> dict
    plan_to_markdown(plan) -> str
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional

import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import paths  # noqa: E402

try:
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

CACHE_PATH = os.path.join(paths.DATA_DIR, "remediation_cache.json")
_LOCK = threading.Lock()

DISCLAIMER = ("方案由系统自动生成，供处置参考；上线前请结合官方公告核对版本号与配置，"
              "并在测试环境验证。")

# CWE → 配置/代码级加固动作（模板模式的核心知识）
_CWE_HARDENING: Dict[str, Dict[str, str]] = {
    "CWE-89":  {"item": "SQL 注入收口", "detail": "所有 SQL 一律参数化/预编译，禁止字符串拼接；ORM 层关闭原生拼接入口。",
                "code": "# 示例（Python）\ncur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n# 反例：f\"SELECT * FROM users WHERE id = {user_id}\""},
    "CWE-78":  {"item": "命令注入收口", "detail": "禁止将用户输入拼进 shell；必须调用时用参数数组形式并白名单校验。",
                "code": "# 示例（Python）\nsubprocess.run([\"convert\", \"in.png\", \"out.png\"], shell=False)\n# 附加：对输入做 ^[A-Za-z0-9._-]+$ 白名单"},
    "CWE-22":  {"item": "路径遍历收口", "detail": "用户输入拼路径前先规范化并强制落在基目录内；拒绝 .. 与绝对路径。",
                "code": "# 示例（Python）\nbase = os.path.realpath(BASE_DIR)\ntarget = os.path.realpath(os.path.join(base, name))\nif not target.startswith(base + os.sep):\n    raise ValueError(\"path traversal\")"},
    "CWE-79":  {"item": "XSS 收口", "detail": "输出按上下文编码；模板默认转义；补充 CSP 响应头收缩脚本来源。",
                "code": "# CSP 示例（nginx）\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self'\";"},
    "CWE-502": {"item": "反序列化收口", "detail": "禁止对不可信数据做原生反序列化（Java 序列化 / Python pickle）；改 JSON 并加类型白名单。", "code": ""},
    "CWE-611": {"item": "XXE 收口", "detail": "XML 解析器禁用外部实体与 DTD。", "code": "# Java 示例\nfactory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);"},
    "CWE-287": {"item": "认证收口", "detail": "修复认证绕过路径；所有管理入口强制鉴权，缺省拒绝。", "code": ""},
    "CWE-862": {"item": "授权收口", "detail": "对象级访问控制：每个接口显式校验“当前用户是否有权访问该对象”，缺省拒绝。", "code": ""},
    "CWE-285": {"item": "授权收口", "detail": "集中化鉴权中间件，禁止散落的 if 判断；管理接口独立网段。", "code": ""},
    "CWE-434": {"item": "文件上传收口", "detail": "类型/扩展名白名单 + 重命名 + 隔离目录 + 禁执行权限。", "code": "# nginx 示例\nlocation ~* ^/uploads/.*\\.(php|jsp|asp)$ { deny all; }"},
    "CWE-200": {"item": "信息暴露收口", "detail": "错误响应最小化：关闭调试输出、隐藏框架指纹、接口不回显敏感字段。", "code": "# nginx 示例\nserver_tokens off;\nproxy_hide_header X-Powered-By;"},
    "CWE-119": {"item": "内存破坏收口", "detail": "对受影响服务启用地址随机化/CFG 等编译期与运行期加固；网络侧收敛可达面。", "code": ""},
    "CWE-639": {"item": "越权收口", "detail": "对象 ID 改不可猜测值并做属主校验，缺省拒绝。", "code": ""},
    "CWE-770": {"item": "资源配额收口", "detail": "对相关接口加限流与并发上限，防资源耗尽。", "code": "# nginx 示例\nlimit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;"},
}

_SEV_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _nz(x: Any) -> str:
    return str(x or "").strip()


# ==========================================================================
# 信号收集：从语料条目提炼修复方案所需输入
# ==========================================================================
def _range_desc(e: dict) -> str:
    """把一条 CPE 版本约束翻译成人话（模板输出用）。"""
    def g(k):
        return _nz(e.get(k))
    parts = []
    if g("start_incl"):
        parts.append("≥ " + g("start_incl"))
    if g("start_excl"):
        parts.append("> " + g("start_excl"))
    if g("end_incl"):
        parts.append("≤ " + g("end_incl"))
    if g("end_excl"):
        parts.append("< " + g("end_excl"))
    ver = g("version")
    rng = "，".join(parts) if parts else ("版本 " + ver if ver and ver != "*" else "全版本")
    return "%s/%s（%s）" % (g("vendor") or "?", g("product") or "?", rng)


def build_signals(record: dict) -> Dict[str, Any]:
    """语料条目 → LLM/模板共用的结构化信号。"""
    d = record or {}
    cvss = d.get("cvss") or {}
    kev = d.get("kev") or {}
    cwes = []
    for c in (d.get("cwe") or []):
        if isinstance(c, dict) and c.get("id"):
            nm = _nz(c.get("name"))
            cwes.append("%s%s" % (c["id"], (" " + nm) if nm else ""))
    cpes = [_range_desc(e) for e in (d.get("cpe") or [])[:8] if isinstance(e, dict)]
    refs = []
    for r in (d.get("patch_links") or []) + (d.get("advisory_links") or []):
        u = _nz(r if isinstance(r, str) else (r or {}).get("url") if isinstance(r, dict) else "")
        if u and u not in refs:
            refs.append(u)
    for r in (d.get("refs") or []):
        u = _nz((r or {}).get("url") if isinstance(r, dict) else r)
        if u and u not in refs and len(refs) < 10:
            refs.append(u)
    return {
        "cve": _nz(d.get("id")),
        "title": _nz(d.get("title"))[:160],
        "desc": _nz(d.get("desc"))[:1200],
        "cwes": cwes[:6],
        "affected": cpes,
        "cvss_score": cvss.get("score"),
        "severity": (_nz(cvss.get("severity")) or "UNKNOWN").upper(),
        "vector": _nz(cvss.get("vector")),
        "kev": bool(kev.get("exploited")),
        "kev_date_added": _nz(kev.get("date_added")),
        "kev_due": _nz(kev.get("due_date")),
        "kev_required_action": _nz(kev.get("required_action"))[:300],
        "official_remediation": [str(x)[:200] for x in (d.get("remediation") or [])[:4]],
        "references": refs[:10],
    }


# ==========================================================================
# LLM 路径
# ==========================================================================
_SYSTEM_PROMPT = (
    "你是资深安全运维与应急响应专家。根据给出的 CVE 信号（描述/CWE/CPE 版本区间/"
    "KEV/CVSS 向量/官方补丁链接），输出可直接执行的中文修复方案，严格 JSON，不要 markdown："
    '{"summary":"三句话以内说清修什么","upgrade":[{"component":"组件(含当前受影响版本区间)",'
    '"target":"具体升级目标版本或判定标准","note":"升级注意点"}],'
    '"config":[{"item":"配置/代码级加固名","detail":"怎么做","code":"可直接粘贴的配置或代码片段，没有则空串"}],'
    '"mitigations":["临时缓解措施"],"verify":["如何验证已修复"],"references":["链接"],'
    '"confidence":"high|medium|low"}'
    "要求：upgrade.target 必须具体（给出版本号或官方公告里的判定条件）；"
    "config 至少给 2 条、能写代码就写代码；结合 KEV 与 CVSS 向量排优先级；不得编造补丁版本号——"
    "不确定就写“以官方公告为准”。"
)

_LLM_SIGNAL_TMPL = """CVE: {cve}
标题: {title}
描述: {desc}
CWE: {cwes}
受影响组件/版本区间: {affected}
CVSS: {score} {severity} {vector}
KEV 在野利用: {kev}（加入 {added}，处置截止 {due}）
官方已有处置提示: {remed}
参考链接: {refs}"""


def _llm_config() -> Dict[str, str]:
    """复用 DeepSeek 兼容配置：poc_scraper 配置 + 环境变量覆盖。"""
    cfg = {"api_key": "", "base_url": "https://api.deepseek.com", "model": "deepseek-chat"}
    try:
        import poc_scraper as PS  # noqa: E402
        pc = PS.load_config() or {}
        cfg["api_key"] = _nz(pc.get("deepseek_api_key"))
        cfg["base_url"] = _nz(pc.get("deepseek_base_url")) or cfg["base_url"]
        cfg["model"] = _nz(pc.get("deepseek_model")) or cfg["model"]
    except Exception as e:  # noqa: BLE001
        _swallow("remediation._llm_config:poc", e)
    for env, k in (("AISEC_LLM_API_KEY", "api_key"), ("DEEPSEEK_API_KEY", "api_key"),
                   ("AISEC_LLM_BASE_URL", "base_url"), ("AISEC_LLM_MODEL", "model")):
        v = _nz(os.environ.get(env))
        if v:
            cfg[k] = v
    cfg["base_url"] = cfg["base_url"].rstrip("/")
    return cfg


def _parse_json_tolerant(text: str) -> Optional[dict]:
    if not text:
        return None
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    raw = m.group(0)
    try:
        return json.loads(raw)
    except ValueError:
        try:
            return json.loads(raw.replace("\n", "\\n"))
        except ValueError:
            return None


def _llm_plan(sig: dict, cfg: dict) -> Optional[dict]:
    try:  # 依赖降级口径与 affected_assets 一致：优先 requests，缺装用 httpcompat
        import requests
    except ImportError:
        import httpcompat as requests  # noqa: F401
    user = _LLM_SIGNAL_TMPL.format(
        cve=sig["cve"], title=sig["title"], desc=sig["desc"] or "（无描述）",
        cwes=", ".join(sig["cwes"]) or "无",
        affected="; ".join(sig["affected"]) or "未提供（按官方公告）",
        score=sig["cvss_score"], severity=sig["severity"], vector=sig["vector"] or "—",
        kev="是" if sig["kev"] else "否", added=sig["kev_date_added"] or "—",
        due=sig["kev_due"] or "—",
        remed=" | ".join(sig["official_remediation"]) or "无",
        refs=" , ".join(sig["references"][:5]) or "无")
    try:
        resp = requests.post(
            cfg["base_url"] + "/chat/completions",
            headers={"Authorization": "Bearer " + cfg["api_key"],
                     "Content-Type": "application/json"},
            json={"model": cfg["model"],
                  "messages": [{"role": "system", "content": _SYSTEM_PROMPT},
                               {"role": "user", "content": user}],
                  "temperature": 0, "max_tokens": 2000,
                  "response_format": {"type": "json_object"}},
            timeout=90,
        )
        if resp.status_code != 200:
            return None
        content = str(resp.json()["choices"][0]["message"]["content"])
    except Exception as e:  # noqa: BLE001
        _swallow("remediation._llm_plan", e)
        return None
    data = _parse_json_tolerant(content)
    if not isinstance(data, dict) or not _nz(data.get("summary")):
        return None
    plan = _normalize(data)
    plan["generated_by"] = "llm"
    plan["confidence"] = _nz(plan.get("confidence")) or "medium"
    return plan


def _normalize(data: dict) -> dict:
    """LLM 输出 → 严格 schema（脏字段丢弃，长度封顶）。"""
    def _strs(v, cap=8):
        out = []
        for x in (v or []):
            if isinstance(x, str) and x.strip():
                out.append(x.strip()[:400])
            elif isinstance(x, dict):
                # 宽容：把 {"text": "..."} 之类拍平
                t = _nz(x.get("text") or x.get("detail") or x.get("value"))
                if t:
                    out.append(t[:400])
            if len(out) >= cap:
                break
        return out

    ups = []
    for u in (data.get("upgrade") or [])[:6]:
        # 组件与目标必须同时给出：只有一半信息对处置没有可执行价值
        if isinstance(u, dict) and _nz(u.get("component")) and _nz(u.get("target")):
            ups.append({"component": _nz(u.get("component"))[:120],
                        "target": _nz(u.get("target"))[:160],
                        "note": _nz(u.get("note"))[:240]})
    cfgs = []
    for c in (data.get("config") or [])[:8]:
        if isinstance(c, dict) and _nz(c.get("item")):
            cfgs.append({"item": _nz(c.get("item"))[:120],
                         "detail": _nz(c.get("detail"))[:400],
                         "code": _nz(c.get("code"))[:800]})
    return {
        "summary": _nz(data.get("summary"))[:600],
        "upgrade": ups, "config": cfgs,
        "mitigations": _strs(data.get("mitigations"), 8),
        "verify": _strs(data.get("verify"), 8),
        "references": _strs(data.get("references"), 10),
    }


# ==========================================================================
# 模板路径（无 Key / LLM 失败）——确定性推导，不是两行空话
# ==========================================================================
def _template_plan(sig: dict) -> dict:
    sev = sig["severity"]
    ups = [{"component": a, "target": "升级至厂商修复版本（以补丁公告为准）",
            "note": "升级前先在测试环境核对功能兼容性；无法立即升级时先执行下方缓解。"}
           for a in sig["affected"][:6]] or \
          [{"component": "受影响组件（语料未给出 CPE 区间，按官方公告确认）",
            "target": "以参考链接中官方公告的修复版本为准",
            "note": "建议先从官方补丁链接确认修复版本号再排期。"}]

    cfgs: List[dict] = []
    for cw in sig["cwes"]:
        cwe_id = cw.split(" ")[0]
        h = _CWE_HARDENING.get(cwe_id)
        if h and h not in cfgs:
            cfgs.append(dict(h))
        if len(cfgs) >= 3:
            break
    vec = sig["vector"] or ""
    if "AV:N" in vec:
        cfgs.append({"item": "暴露面收敛（CVSS AV:N）",
                     "detail": "漏洞可从网络远程利用且无需本地访问：把受影响服务从公网下线或加 ACL/WAF 白名单，只允许可信来源访问。",
                     "code": "# nginx 示例：仅允许内网段访问\nlocation / {\n    allow 10.0.0.0/8;\n    allow 172.16.0.0/12;\n    deny all;\n}"})
    if "PR:N" in vec:
        cfgs.append({"item": "认证强化（CVSS PR:N）", "detail": "漏洞无需认证即可利用：为受影响接口补齐认证（网关侧统一鉴权或应用内登录态校验）。", "code": ""})
    if "AC:L" in vec and len(cfgs) < 4:
        cfgs.append({"item": "虚拟补丁（CVSS AC:L）", "detail": "利用门槛低：在 WAF/网关加拦截规则，针对该漏洞的利用特征（如异常路径/参数）先行阻断。", "code": ""})
    if not cfgs:
        cfgs.append({"item": "最小暴露面", "detail": "按最小权限原则收缩受影响服务的可达范围，关闭非必要功能与端口。", "code": ""})

    mit = []
    if sig["kev"]:
        mit.append("【在野利用】CISA 已确认该漏洞被实际利用（加入 %s，处置截止 %s）："
                   "未修复前建议隔离或下线受影响系统，并排查历史入侵痕迹。"
                   % (sig["kev_date_added"] or "?", sig["kev_due"] or "?"))
        if sig["kev_required_action"]:
            mit.append("CISA 官方处置要求：" + sig["kev_required_action"])
    if _SEV_ORDER.get(sev, 0) >= 3:
        mit.append("高危漏洞（CVSS %s）：按应急流程 24~72 小时内完成处置，处置期间加强日志审计。" % (sig["cvss_score"] or sev))
    mit.append("启用官方缓解配置（见参考链接）；开启针对该漏洞的日志告警，观察利用尝试。")
    if sig["official_remediation"]:
        mit.append("情报库已收录官方提示：" + sig["official_remediation"][0])

    verify = ["升级后复核组件版本指纹，确认不在受影响区间内（%s）。" % ("；".join(sig["affected"][:3]) or "见官方公告"),
              "在测试环境用利用路径复测验证（可用本系统 POC 面板做回归），确认利用已失效且业务正常。",
              "确认参考链接中补丁公告列出的修复版本号与实际部署版本一致。"]

    refs = list(sig["references"])
    if sig["cve"] and sig["cve"].startswith("CVE-"):
        nvd = "https://nvd.nist.gov/vuln/detail/" + sig["cve"]
        if nvd not in refs:
            refs.insert(0, nvd)

    return {
        "summary": "【模板模式】基于 NVD 元数据（CVSS %s %s、CWE %s、KEV %s）推导的通用修复路径。"
                   "配置 AISEC_LLM_API_KEY 后可获得结合漏洞细节的代码级定制方案。"
                   % (sig["cvss_score"] or "—", sev,
                      ", ".join(c.split(" ")[0] for c in sig["cwes"][:3]) or "未标注",
                      "在野利用" if sig["kev"] else "未列入"),
        "upgrade": ups, "config": cfgs, "mitigations": mit[:6], "verify": verify,
        "references": refs[:10], "confidence": "low",
        "generated_by": "template",
    }


# ==========================================================================
# 缓存 + 统一入口
# ==========================================================================
def _load_cache() -> dict:
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_cache(d: dict) -> None:
    tmp = "%s.%d.tmp" % (CACHE_PATH, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False)
        os.replace(tmp, CACHE_PATH)
    except OSError as e:  # noqa: BLE001
        _swallow("remediation._save_cache", e)


def generate(cve_id: str, engine, *, force: bool = False,
             record: Optional[dict] = None) -> Dict[str, Any]:
    """生成（或取缓存）修复方案。"""
    cve_id = _nz(cve_id).upper()
    if not cve_id:
        return {"ok": False, "error": "缺少 CVE 编号"}
    if not force:
        with _LOCK:
            hit = _load_cache().get(cve_id)
        if hit and isinstance(hit.get("plan"), dict):
            plan = dict(hit["plan"])
            plan["cached"] = True
            return {"ok": True, "plan": plan}

    d = record if isinstance(record, dict) and record.get("id") else (
        engine.detail(cve_id) if engine is not None else None)
    if not d:
        return {"ok": False, "error": "语料中不存在 %s" % cve_id}
    sig = build_signals(d)
    cfg = _llm_config()
    plan = _llm_plan(sig, cfg) if cfg.get("api_key") else None
    if not plan:
        plan = _template_plan(sig)
    plan.update({"cve": cve_id, "risk": {
        "cvss_score": sig["cvss_score"], "severity": sig["severity"],
        "vector": sig["vector"], "kev": sig["kev"],
        "kev_due": sig["kev_due"], "cwes": sig["cwes"]},
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "disclaimer": DISCLAIMER})
    plan.pop("cached", None)
    with _LOCK:
        c = _load_cache()
        c[cve_id] = {"ts": time.time(), "plan": plan}
        # 只留最近 500 条，防止无限膨胀
        if len(c) > 500:
            for k in sorted(c, key=lambda k: c[k].get("ts", 0))[:len(c) - 500]:
                c.pop(k, None)
        _save_cache(c)
    return {"ok": True, "plan": plan}


def plan_to_markdown(plan: dict) -> str:
    """方案 → Markdown（导出用）。"""
    L = ["# %s 修复方案" % _nz(plan.get("cve")) or "# 修复方案"]
    L.append("")
    src = "LLM 生成" if plan.get("generated_by") == "llm" else "模板模式（NVD 元数据推导）"
    r = plan.get("risk") or {}
    L.append("> 生成方式：%s ｜ 生成时间：%s ｜ CVSS：%s %s %s ｜ KEV 在野：%s" % (
        src, _nz(plan.get("generated_at")), r.get("cvss_score") or "—",
        r.get("severity") or "—", r.get("vector") or "—",
        "是（截止 %s）" % r.get("kev_due") if r.get("kev") else "否"))
    L.append("")
    L.append("## 概要")
    L.append(_nz(plan.get("summary")))
    if plan.get("upgrade"):
        L.append("")
        L.append("## 升级路径")
        for u in plan["upgrade"]:
            L.append("- **%s** → %s%s" % (u.get("component") or "组件", u.get("target") or "",
                                          ("（%s）" % u["note"]) if u.get("note") else ""))
    if plan.get("config"):
        L.append("")
        L.append("## 配置 / 代码级加固")
        for c in plan["config"]:
            L.append("### %s" % (c.get("item") or "加固项"))
            if c.get("detail"):
                L.append(c["detail"])
            if c.get("code"):
                L.append("")
                L.append("```")
                L.append(c["code"])
                L.append("```")
    if plan.get("mitigations"):
        L.append("")
        L.append("## 临时缓解")
        for m in plan["mitigations"]:
            L.append("- " + m)
    if plan.get("verify"):
        L.append("")
        L.append("## 验证方法")
        for v in plan["verify"]:
            L.append("- " + v)
    if plan.get("references"):
        L.append("")
        L.append("## 参考")
        for u in plan["references"]:
            L.append("- " + u)
    L.append("")
    L.append("> " + _nz(plan.get("disclaimer")))
    return "\n".join(L)
