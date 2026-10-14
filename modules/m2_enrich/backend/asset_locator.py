# -*- coding: utf-8 -*-
"""
asset_locator.py —— 受影响互联网资产定位：测绘语法生成
============================================================
把「这个 CVE 影响了什么」翻译成「去哪、用什么语法找暴露面」：

    input : CVE 编号 + 语料条目（products/vendors/title）+ 受影响资产提取结果（CPE/版本区间）
    output: FOFA / Shodan / Quake / ZoomEye / Google 可直接粘贴的查询语法 + 版本收窄提示

关键设计
--------
1. **本模块不发起任何网络请求，不做主动扫描**：只做语法生成。
   扫描/测绘属于授权范围问题，交给使用者在自有或已授权资产上执行（合规优先）。
2. **精确指纹优先于产品名**：如 Ollama 的 ``body="Ollama is running"``、
   Elasticsearch 的 ``body="You Know, for Search"``、Jenkins 的 ``header="X-Jenkins"``，
   比 ``body="ollama"`` 这类模糊搜索命中率高得多，也少误报。
3. **带版本收窄**：把 affected_versions 原样给出，命中后先核对版本再决定是否验证。

用法::

    from asset_locator import survey
    s = survey("CVE-2024-37032", item=doc, assets=asset_list)
    s["fofa"][0]["q"]      # -> 'app="Ollama"'
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

COMPLIANCE = ("仅供自有资产或已获书面授权的资产使用；本系统只生成查询语法，"
              "不发起扫描、不探测任何第三方主机。")

# 产品 → 测绘平台 app 规则名（FOFA/Quake/ZoomEye 的 app= 命中率远高于裸关键词）
APP_ALIAS: Dict[str, str] = {
    "ollama": "Ollama",
    "vllm": "vLLM",
    "langchain": "LangChain",
    "langflow": "Langflow",
    "flowise": "Flowise",
    "dify": "Dify",
    "open-webui": "Open-WebUI",
    "openwebui": "Open-WebUI",
    "anythingllm": "AnythingLLM",
    "lobe-chat": "LobeChat",
    "lobechat": "LobeChat",
    "nextchat": "NextChat",
    "one-api": "One-API",
    "comfyui": "ComfyUI",
    "stable-diffusion-webui": "Stable-Diffusion-WebUI",
    "automatic1111": "Stable-Diffusion-WebUI",
    "text-generation-webui": "Text-Generation-WebUI",
    "text-generation-inference": "Text-Generation-Inference",
    "triton-inference-server": "NVIDIA-Triton-Inference-Server",
    "mlflow": "MLflow",
    "ray": "Ray",
    "gradio": "Gradio",
    "streamlit": "Streamlit",
    "jupyter": "Jupyter",
    "jupyterlab": "JupyterLab",
    "qdrant": "Qdrant",
    "chroma": "Chroma",
    "milvus": "Milvus",
    "weaviate": "Weaviate",
    "elasticsearch": "Elasticsearch",
    "redis": "Redis",
    "jenkins": "Jenkins",
    "grafana": "Grafana",
    "gitlab": "GitLab",
    "confluence": "Atlassian-Confluence",
    "jira": "Atlassian-Jira",
    "tomcat": "Apache-Tomcat",
    "log4j": "Apache-Log4j",
    "n8n": "n8n",
    "docker-registry": "Docker-Registry",
    "sillytavern": "SillyTavern",
    "fastchat": "FastChat",
    "lmstudio": "LM-Studio",
}

# 产品 → 可用作精确指纹的特征串（body/header/title 命中）
BANNER_HINTS: Dict[str, List[Dict[str, str]]] = {
    "ollama": [{"kind": "body", "value": "Ollama is running",
                "why": "Ollama 服务根路径的固定响应文本，误报极低"}],
    "open-webui": [{"kind": "title", "value": "Open WebUI", "why": "前端页面标题"}],
    "lobe-chat": [{"kind": "title", "value": "LobeChat", "why": "前端页面标题"}],
    "nextchat": [{"kind": "title", "value": "NextChat", "why": "前端页面标题"}],
    "one-api": [{"kind": "title", "value": "One API", "why": "前端页面标题"}],
    "anythingllm": [{"kind": "title", "value": "AnythingLLM", "why": "前端页面标题"}],
    "langflow": [{"kind": "title", "value": "Langflow", "why": "前端页面标题"}],
    "flowise": [{"kind": "title", "value": "Flowise", "why": "前端页面标题"}],
    "dify": [{"kind": "title", "value": "Dify", "why": "控制台标题"}],
    "n8n": [{"kind": "title", "value": "n8n", "why": "前端页面标题"}],
    "comfyui": [{"kind": "title", "value": "ComfyUI", "why": "前端页面标题"}],
    "automatic1111": [{"kind": "title", "value": "Stable Diffusion", "why": "WebUI 标题"}],
    "stable-diffusion-webui": [{"kind": "title", "value": "Stable Diffusion", "why": "WebUI 标题"}],
    "text-generation-inference": [{"kind": "title", "value": "Text Generation Inference",
                                   "why": "TGI 自带调试页标题"}],
    "mlflow": [{"kind": "title", "value": "MLflow", "why": "跟踪服务页面标题"}],
    "gradio": [{"kind": "body", "value": "gradio", "why": "Gradio 前端固定资源路径"}],
    "streamlit": [{"kind": "body", "value": "streamlit", "why": "Streamlit 前端资源路径"}],
    "jupyter": [{"kind": "title", "value": "Jupyter", "why": "Notebook 页面标题"}],
    "jupyterlab": [{"kind": "title", "value": "JupyterLab", "why": "Lab 页面标题"}],
    "ray": [{"kind": "title", "value": "Ray", "why": "Dashboard 标题（通常 8265）"}],
    "qdrant": [{"kind": "body", "value": "qdrant", "why": "Dashboard 文案/资源"}],
    "sillytavern": [{"kind": "title", "value": "SillyTavern", "why": "前端页面标题"}],
    "fastchat": [{"kind": "body", "value": "FastChat", "why": "控制台文案"}],
    "lmstudio": [{"kind": "title", "value": "LM Studio", "why": "服务页标题"}],
    "jenkins": [{"kind": "header", "value": "X-Jenkins", "why": "Jenkins 响应头特征"}],
    "elasticsearch": [{"kind": "body", "value": "You Know, for Search",
                       "why": "ES 根路径固定欢迎语"}],
    "grafana": [{"kind": "title", "value": "Grafana", "why": "登录页标题"}],
    "gitlab": [{"kind": "title", "value": "GitLab", "why": "登录页标题"}],
    "confluence": [{"kind": "title", "value": "Confluence", "why": "登录页标题"}],
    "jira": [{"kind": "title", "value": "Jira", "why": "登录页标题"}],
    "tomcat": [{"kind": "title", "value": "Apache Tomcat", "why": "默认首页标题"}],
    "redis": [{"kind": "note", "value": "6379 端口协议探测需授权",
               "why": "Redis 无 HTTP 指纹，建议先用端口+授权确认"}],
    "docker-registry": [{"kind": "header", "value": "Docker-Distribution-Api-Version",
                         "why": "Registry API 响应头特征"}],
    "text-generation-webui": [{"kind": "title", "value": "Text generation web UI",
                               "why": "前端页面标题"}],
}

# 行业常见组合：把「AI 基础设施」和「通用组件」分开，前端分开展示
AI_KEYWORDS = ("ollama", "vllm", "langchain", "langflow", "flowise", "dify", "open-webui",
               "anythingllm", "lobe", "nextchat", "one-api", "comfyui", "stable-diffusion",
               "text-generation", "triton", "mlflow", "ray", "gradio", "streamlit",
               "jupyter", "qdrant", "chroma", "milvus", "weaviate", "sillytavern",
               "fastchat", "lmstudio", "n8n", "tgi")


def _norm(s: Any) -> str:
    return str(s or "").strip().lower()


def _dedup(seq: Iterable[str], limit: Optional[int] = None) -> List[str]:
    out, seen = [], set()
    for x in seq:
        x = (x or "").strip()
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
        if limit and len(out) >= limit:
            break
    return out


def _is_ai(p: str) -> bool:
    return any(k in p for k in AI_KEYWORDS)


def _collect_terms(cve_id: str, item: Optional[dict], assets: Optional[list]):
    """汇总候选产品/厂商/版本，并标注来源（哪个产品是「主」产品）。"""
    products: List[str] = []
    vendors: List[str] = []
    versions: List[str] = []
    cpes: List[str] = []
    primary: List[str] = []          # 高置信来源（NVD CPE / LLM 提取）

    for a in (assets or []):
        if isinstance(a, dict):
            get = a.get
        else:                        # 兼容 POCResult / 对象形态
            get = lambda k, d=None, _a=a: getattr(_a, k, d)  # noqa: E731
        p, v = _norm(get("product")), _norm(get("vendor"))
        if p:
            products.append(p)
            primary.append(p)
        if v:
            vendors.append(v)
        versions += [str(x) for x in (get("affected_versions") or [])]
        c = get("cpe")
        if c:
            cpes.append(str(c))

    if isinstance(item, dict):
        for p in (item.get("products") or [])[:400]:
            products.append(_norm(p))
        for v in (item.get("vendors") or [])[:200]:
            vendors.append(_norm(v))
        title = str(item.get("title") or "").lower()
        primary += [t for t in AI_KEYWORDS if t in title]

    products = _dedup(products)
    if not products and primary:
        # 该 CVE 没有 CPE 映射时，退而用标题里能认出的 AI 产品名（如 "Ollama MCP Server …"）
        products = _dedup(primary)
    # AI 相关产品优先（本系统主打 AI 安全），其次高置信来源
    products.sort(key=lambda p: (0 if _is_ai(p) else 1, 0 if p in primary else 1, len(p)))
    return {
        "cve": cve_id,
        "products": products[:8],
        "primary": _dedup(primary),
        "vendors": _dedup(vendors)[:6],
        "versions": versions[:12],
        "cpes": cpes[:6],
    }


def _q(kind: str, query: str, why: str, product: str = "") -> Dict[str, str]:
    return {"kind": kind, "q": query, "why": why, "product": product}


def survey(cve_id: str, item: Optional[dict] = None,
           assets: Optional[list] = None) -> Dict[str, Any]:
    """生成受影响互联网资产的测绘语法（不发起请求）。

    :param item: 语料条目（含 products/vendors/title/desc），可为 None
    :param assets: affected_assets.extract_affected_assets 的结果，可为 None
    """
    cve_id = (cve_id or "").strip().upper()
    terms = _collect_terms(cve_id, item, assets)
    prods = terms["products"]

    fofa: List[Dict[str, str]] = []
    shodan: List[Dict[str, str]] = []
    quake: List[Dict[str, str]] = []
    zoomeye: List[Dict[str, str]] = []
    google: List[Dict[str, str]] = []

    for p in prods:
        alias = APP_ALIAS.get(p, "")
        hints = BANNER_HINTS.get(p, [])
        # ① 精确指纹（最高命中率）
        for h in hints[:2]:
            if h["kind"] == "body":
                fofa.append(_q("fofa", f'body="{h["value"]}"', h["why"], p))
                quake.append(_q("quake", f'body:"{h["value"]}"', h["why"], p))
                shodan.append(_q("shodan", f'http.html:"{h["value"]}"', h["why"], p))
                zoomeye.append(_q("zoomeye", f'body:"{h["value"]}"', h["why"], p))
                google.append(_q("google", f'"{h["value"]}"', h["why"], p))
            elif h["kind"] == "title":
                fofa.append(_q("fofa", f'title="{h["value"]}"', h["why"], p))
                shodan.append(_q("shodan", f'http.title:"{h["value"]}"', h["why"], p))
                quake.append(_q("quake", f'title:"{h["value"]}"', h["why"], p))
                zoomeye.append(_q("zoomeye", f'title:"{h["value"]}"', h["why"], p))
                google.append(_q("google", f'intitle:"{h["value"]}"', h["why"], p))
            elif h["kind"] == "header":
                fofa.append(_q("fofa", f'header="{h["value"]}"', h["why"], p))
                shodan.append(_q("shodan", f'"{h["value"]}"', h["why"], p))
                zoomeye.append(_q("zoomeye", f'header:"{h["value"]}"', h["why"], p))
            elif h["kind"] == "note":
                shodan.append(_q("note", h["value"], h["why"], p))
        # ② app 规则（测绘平台的组件指纹库）
        if alias:
            fofa.append(_q("fofa", f'app="{alias}"', f"{alias} 的平台组件指纹规则", p))
            quake.append(_q("quake", f'app:"{alias}"', f"{alias} 的平台组件指纹规则", p))
            zoomeye.append(_q("zoomeye", f'app:"{alias}"', f"{alias} 的平台组件指纹规则", p))
        # ③ 兜底：产品名
        fofa.append(_q("fofa", f'body="{p}"', "产品名兜底搜索（命中面大，建议叠加端口/标题）", p))
        shodan.append(_q("shodan", f'product:"{p}"', "Shodan 产品标签", p))
        google.append(_q("google", f'inurl:"{p}" intitle:"{p}"', "公开页面检索", p))

    # ④ CVE 维度：Shodan 支持 vuln 过滤器；FOFA 支持 cve 语法（部分产品）
    if cve_id:
        shodan.append(_q("shodan", f'vuln:"{cve_id}"',
                         "Shodan 已知漏洞标签（命中即可疑未修复资产）"))
        fofa.append(_q("fofa", f'cve="{cve_id}"',
                       "FOFA CVE 语法（覆盖度视产品而定，可与产品语法取交集）"))

    out = {
        "id": cve_id,
        "generated_from": terms,
        "fofa": _dedup_q(fofa, 10),
        "shodan": _dedup_q(shodan, 10),
        "quake": _dedup_q(quake, 8),
        "zoomeye": _dedup_q(zoomeye, 8),
        "google": _dedup_q(google, 6),
        "version_narrow": terms["versions"],
        "compliance": COMPLIANCE,
        "note": ("命中≠受影响：先核对版本区间与补丁状态，再决定是否验证；"
                 "对第三方资产做任何探测都可能违法，请仅用于自有/授权范围。"),
    }
    if not prods:
        out["note"] = ("未提取到受影响产品（该 CVE 可能没有 CPE 映射）："
                       "可先在详情「关键指标」里看厂商/产品，或配置 LLM Key 走语义提取。")
    return out


def _dedup_q(items: List[Dict[str, str]], limit: int) -> List[Dict[str, str]]:
    out, seen = [], set()
    for it in items:
        key = (it["kind"], it["q"])
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
        if len(out) >= limit:
            break
    return out
