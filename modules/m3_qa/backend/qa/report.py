# -*- coding: utf-8 -*-
"""
report.py —— 问答答案的「结论 + 原始详细资料」结构化产出（v2.4）
================================================================
背景（这次改的是什么问题）：

  提问后拿到的答案是一段"流水账式证据罗列"——先说"检索到以下情报"，
  再逐条贴 CVSS / 发布日期，读者要自己从十几条里拼出结论；而引用来源
  只有一排小小编号 chip，点开是整个页面的检查器抽屉，看不到"这条为什么
  被选中、它的关键字段是什么"。

改造后的答案契约（前端据此分区渲染，接口字段**向后兼容**）：

    {
      "answer":     "...",        # 旧字段，保留（Markdown 全文：结论 + 资料清单）
      "sources":    [...],        # 旧字段，保留（精简引用，评测脚本在读）
      "conclusion": "...",        # ★ 新增：直接给出的结论，**上限 3600 字**（硬截断）
      "conclusion_chars": 1234,
      "conclusion_limit": 3600,
      "conclusion_truncated": false,
      "evidence":   [ {...} ],    # ★ 新增：原始详细资料（每条含关键字段 + 摘要，可点开详情）
      "evidence_total": 20        # ★ 证据池去重后的总条数（≥ len(evidence)，受 EVIDENCE_LIMIT 截断）
    }

两条设计原则：
  1. **结论先行、可复核**：结论里的每个数字都来自证据池结构化字段的确定性聚合
     （严重度分布 / KEV / POC / 最高 CVSS / 组件分布 / 时间跨度），不是生成式编造。
  2. **资料可回溯**：每条 evidence 都带 id/标题/CVSS/严重度/日期/组件/CWE/
     在野利用/公开 POC/来源可信度/摘要，前端点击即取 /api/detail 展开全文。
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

# ── 上限配置（单一来源：qa/config.py 的 ANSWER_CONFIG，可用环境变量覆盖） ──
try:                                    # 兜底值保证 qa 包不完整导入时本模块仍可用
    from qa.config import ANSWER_CONFIG as _AC
    CONCLUSION_LIMIT = int(_AC.get("conclusion_limit") or 3600)   # 结论字数上限（中文按字计）
    EVIDENCE_LIMIT = int(_AC.get("evidence_limit") or 12)         # 原始详细资料最多条数
except Exception:  # noqa: BLE001
    CONCLUSION_LIMIT = 3600
    EVIDENCE_LIMIT = 12
SUMMARY_LEN = 180            # 单条资料在列表里的摘要长度

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "N/A"]
_TAG_RE = re.compile(r"<[^>]+>")


# ── 字段抽取小工具（检索卡片字段 与 详情字段 两套都认） ──────────
def _cvss(d: Dict) -> Dict:
    v = d.get("cvss")
    return v if isinstance(v, dict) else {}


def _score(d: Dict) -> Optional[float]:
    s = _cvss(d).get("score")
    try:
        return float(s) if s is not None else None
    except (TypeError, ValueError):
        return None


def _sev(d: Dict) -> str:
    return str(_cvss(d).get("severity") or "UNKNOWN").upper()


def _exploited(d: Dict) -> bool:
    """在野利用：检索卡片用 exploited/kev:bool，详情用 kev:{exploited:bool}"""
    if d.get("exploited"):
        return True
    kev = d.get("kev")
    if isinstance(kev, dict):
        return bool(kev.get("exploited"))
    return bool(kev)


def _poc_count(d: Dict) -> int:
    n = d.get("poc_count")
    if isinstance(n, (int, float)):
        return int(n)
    links = d.get("poc_links") or []
    return len(links) if isinstance(links, list) else 0


def _cwe_ids(d: Dict) -> List[str]:
    out = []
    for w in (d.get("cwe") or [])[:4]:
        wid = w.get("id") if isinstance(w, dict) else str(w)
        if wid and wid not in out:
            out.append(wid)
    return out


def _plain_text(d: Dict, n: int = SUMMARY_LEN) -> str:
    """资料摘要：优先 desc，其次去 HTML 的 snippet；压缩空白后截断"""
    txt = d.get("desc") or ""
    if not txt:
        txt = _TAG_RE.sub("", d.get("snippet") or "")
    txt = str(txt).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    txt = re.sub(r"\s+", " ", txt).strip()
    return txt[:n] + ("…" if len(txt) > n else "")


# ── ① 原始详细资料（evidence） ────────────────────────────────
def evidence_item(d: Dict) -> Dict:
    """把一条检索/详情文档裁剪成前端能直接渲染的「原始资料卡片」"""
    return {
        "id": d.get("id") or "",
        "title": d.get("title") or "",
        "type": d.get("type") or "",
        "cvss": _score(d),
        "severity": _sev(d),
        "published": (str(d.get("published") or ""))[:10],
        "products": [str(p) for p in (d.get("products") or [])[:6]],
        "cwe": _cwe_ids(d),
        "exploited": _exploited(d),
        "poc_count": _poc_count(d),
        "sources": [str(s) for s in (d.get("sources") or [])[:4]],
        "trust_label": d.get("trust_label") or "",
        "confidence": d.get("confidence"),
        "category": d.get("category") or "",
        "summary": _plain_text(d),
    }


def build_evidence(docs: List[Dict], limit: int = EVIDENCE_LIMIT) -> List[Dict]:
    """证据池 → 去重后的原始资料清单（保持检索相关性顺序）"""
    out, seen = [], set()
    for d in docs or []:
        did = str(d.get("id") or "")
        if not did or did in seen:
            continue
        seen.add(did)
        out.append(evidence_item(d))
        if len(out) >= limit:
            break
    return out


def evidence_from_ids(ids: List[str], limit: int = EVIDENCE_LIMIT) -> List[Dict]:
    """智能体路径专用：手里只有引用编号时，回访主体补齐资料卡片。

    拿不到详情也要留一条"只有编号"的占位 —— 宁可少字段，也不能让
    「答案里引用了、资料列表里却没有」这种名实不符的情况出现。
    """
    from qa.retriever import get_detail          # 延迟导入：qa 包不完整时也不拖垮问答
    out, seen = [], set()
    for cid in (ids or [])[:limit]:
        cid = str(cid or "")
        if not cid or cid in seen:
            continue
        seen.add(cid)
        try:
            d = get_detail(cid) or {}
        except Exception:  # noqa: BLE001
            d = {}
        out.append(evidence_item(d if d.get("id") else {**d, "id": cid}))
    return out


# ── ② 结论：确定性情报汇总（把证据"算"成结论） ──────────────────
def summarize(question: str, docs: List[Dict]) -> str:
    """对证据池做结构化聚合，产出一段可复核的**来源与风险统计**（模板模式结论的第二层）。

    全部是计数/取最值，没有任何生成式推断 —— 每个数字都能回到证据里复核。
    注意：这一层**不回答"资料说了什么"** —— 内容层面的结论由
    `qa/content_answer.py::content_section()` 产出，两层拼成完整结论：

        结论（内容要点） ← 回答"资料说了什么"（content_answer）
        情报汇总（来源与风险统计） ← 回答"这批资料是什么"（本函数）
    """
    if not docs:
        return ("## 情报汇总（来源与风险统计）\n本次未在情报库中检索到相关条目。\n"
                "建议换个关键词（产品名 / CVE 编号 / CWE 编号）再问一次。\n")

    # ── 零相关（v2.6）：候选有、但相关度闸门全判不相关 ──────────────
    # 与"完全没检索到"分开：前者是"库里可能有、但这一问没匹配上"，
    # 后者是"连候选都没有"。两种都**必须如实说**，不能硬凑条数。
    # 判据：上游（retriever.relevance）已把不相关的剔除，这里若发现
    # 每条都带 `_irrelevant` 标记（或 upper 层标注为低置信兜底），就如实说明。
    if all(d.get("_low_confidence") for d in docs):
        return ("## 情报汇总（来源与风险统计）\n"
                "本次检索**未命中高相关度情报**；以下条目仅为按字面相似度的参考"
                f"（共 {len(docs)} 条，已标注低置信），请勿据此下结论。\n"
                "建议换用更具体的**产品/组件名**或 **CVE/CWE 编号**再问一次。\n")


    from collections import Counter
    n = len(docs)
    sev = Counter(_sev(d) for d in docs)
    kev = [d for d in docs if _exploited(d)]
    poc = [d for d in docs if _poc_count(d) > 0]
    # 只认"真有评分"的条目：知识/仓库类条目 CVSS 是 0 或空，混进来只会把结论搅浑
    scored = [(d, s) for d, s in ((d, _score(d)) for d in docs) if s and s > 0]
    prods, cwes, srcs = Counter(), Counter(), Counter()
    for d in docs:
        for p in (d.get("products") or [])[:3]:
            if p:
                prods[str(p)] += 1
        for w in _cwe_ids(d)[:2]:
            cwes[w] += 1
        for s in (d.get("sources") or []):
            srcs[str(s)] += 1
    dates = sorted([str(d.get("published") or "")[:10] for d in docs if d.get("published")])

    lines = [f"## 情报汇总（来源与风险统计）", ""]
    # 一句话结论：先给最该知道的事
    head = f"本次检索命中 **{n} 条**相关情报"
    if sev.get("CRITICAL"):
        head += f"，其中 **{sev['CRITICAL']} 条为 CRITICAL**"
    if kev:
        head += f"；**{len(kev)} 条已被 CISA 列入在野利用（KEV）**"
    if poc:
        head += f"，**{len(poc)} 条已有公开 POC/EXP**"
    if scored:
        bd, bs = max(scored, key=lambda x: x[1])
        head += f"。风险最高的是 **[{bd.get('id')}]（CVSS {bs:g}，{_sev(bd)}）**"
    head += "。"
    lines += [head, ""]

    # 风险分布（全是知识/仓库条目时如实说明，不拿 0 分凑分布）
    dist = " / ".join(f"{s} {sev[s]}" for s in SEV_ORDER if s != "UNKNOWN" and sev.get(s))
    if dist:
        lines.append(f"- **风险分布**：{dist}")
    elif not scored:
        lines.append("- **风险分布**：本次命中的多为知识/仓库类条目，无 CVSS 结构化评分")
    if kev:
        lines.append("- **已在野利用（KEV）**：" + "、".join(f"[{d.get('id')}]" for d in kev[:6])
                     + (" 等" if len(kev) > 6 else "") + f"（共 {len(kev)} 条）")
    if poc:
        lines.append("- **存在公开 POC/EXP**：" + "、".join(f"[{d.get('id')}]" for d in poc[:6])
                     + (" 等" if len(poc) > 6 else "") + f"（共 {len(poc)} 条）")
    if scored:
        top3 = sorted(scored, key=lambda x: -x[1])[:3]
        lines.append("- **CVSS 前三**："
                     + "、".join(f"[{d.get('id')}] {s:g}（{_sev(d)}）" for d, s in top3))
    if prods:
        lines.append("- **主要受影响组件**："
                     + "、".join(f"`{p}`({c})" for p, c in prods.most_common(6)))
    if cwes:
        lines.append("- **主要弱点类型**：" + "、".join(f"{w}({c})" for w, c in cwes.most_common(6)))
    if dates:
        lines.append(f"- **时间跨度**：{dates[0]} ~ {dates[-1]}")
    if srcs:
        lines.append("- **数据来源**：" + "、".join(f"{s}({c})" for s, c in srcs.most_common(5)))

    # 处置建议：只给"由数据直接推出"的动作，不做无依据延伸
    if kev:
        pri, why = kev, "（在野利用优先）"
    elif scored:
        pri, why = [d for d, _ in sorted(scored, key=lambda x: -x[1])[:3]], "（按 CVSS 降序）"
    else:
        pri, why = docs[:3], "（按检索相关度）"
    if pri:
        lines.append("")
        lines.append("**处置优先级**：先处理 "
                     + "、".join(f"[{d.get('id')}]" for d in pri[:5]) + why
                     + "，其余条目按组件排查与补丁排期。")
    lines.append("")
    lines.append(f"_依据：对本次证据池（{n} 条）的结构化字段做计数与取最值，全部可复核。_")
    lines.append("")
    return "\n".join(lines)


# ── ③ 结论截断（3600 字硬上限） ────────────────────────────────
def _balance_bold(text: str) -> str:
    """清洗未闭合的 markdown 粗体标记（2026-10-08 用户截图实测）。

    LLM 偶尔会写出 `**8 条已被在野利用…` 这种**只开不闭**的 `**`，
    前端 md() 的粗体正则配不到对，就把两个星号原样显示在结论卡里 ——
    用户看到的是"结论里有乱码星号"。这里只处理**数量为奇数**的情况
    （成对的 `**` 是正常粗体，不动），全部剥掉保平安。
    """
    t = text or ""
    if t.count("**") % 2 == 1:
        t = t.replace("**", "")
    return t


def clip(text: str, limit: int = CONCLUSION_LIMIT) -> Tuple[str, bool]:
    """结论超过上限就截断，并显式说明被截断（不做静默丢失）。

    注意：截断提示本身也占字数，所以先扣掉它的长度再切 ——
    否则"上限 3600"实际会返回 3600+提示的长度，等于没守住上限。
    """
    t = _balance_bold((text or "").strip())
    if len(t) <= limit:
        return t, False
    suffix = f"\n\n（结论已达 {limit} 字上限，已截断；完整原始情报见下方「原始详细资料」）"
    budget = max(200, limit - len(suffix))
    cut = t[:budget]
    for sep in ("\n\n", "\n", "。"):
        i = cut.rfind(sep)
        if i > budget * 0.6:
            cut = cut[:i + len(sep)].rstrip()
            break
    return cut + suffix, True


# ── ③.5 个性化推荐（related）：基于当前答案证据池的关联情报 ──────────
def _related_cards(docs: List[Dict], limit: int = 5) -> List[Dict]:
    """把关联文档裁剪成前端可直接渲染的推荐卡片（比 evidence 更精简）。

    复用 report 已有的字段抽取小工具（_score/_sev/_exploited/_poc_count/_cwe_ids），
    不新造逻辑；卡片字段与 evidence_item 对齐，前端渲染层可共用。
    """
    out, seen = [], set()
    for d in docs or []:
        did = str(d.get("id") or "")
        if not did or did in seen:
            continue
        seen.add(did)
        out.append({
            "id": did,
            "title": d.get("title") or "",
            "cvss": _score(d),
            "severity": _sev(d),
            "exploited": _exploited(d),
            "poc_count": _poc_count(d),
            "cwe": _cwe_ids(d),
            "products": [str(p) for p in (d.get("products") or [])[:4]],
            "published": (str(d.get("published") or ""))[:10],
        })
        if len(out) >= limit:
            break
    return out


def build_related(question: str, docs: List[Dict], result: Dict = None) -> List[Dict]:
    """生成「猜你还想看」的个性化关联推荐（对应评分表问答-个性化推荐档）。

    设计原则：**推荐必须从"用户当前问的东西"派生，而不是静态热点**，这才是"个性化"。
    三类推荐，按优先级拼装（去重、上限 6 条）：
      ① 同组件/同产品：从证据池抽出现频最高的产品名，回访引擎检索该产品的高危漏洞；
      ② 同弱点类型（CWE）：抽证据池的 CWE，检索同 CWE 的其它漏洞；
      ③ 实时高危热点：KEV 在野利用 + CRITICAL，作为"当下最该关注"的兜底。

    全部走确定性检索（引擎精确路径，skip_vector=True），**不引入生成式编造**；
    拿不到就少给/不给，绝不返回"看起来像真的"占位条目。异常整体降级为空列表，
    绝不影响主问答链路。
    """
    from collections import Counter
    out: List[Dict] = []
    seen: set = set()
    docs = docs or []
    # 证据池里已有的 id 不再推荐（推荐"补充"，不是重复答案本身）
    for d in docs:
        seen.add(str(d.get("id") or ""))

    def _add(cands, reason):
        for c in _related_cards(cands or []):
            if c["id"] and c["id"] not in seen and len(out) < 6:
                seen.add(c["id"])
                c["reason"] = reason
                out.append(c)

    try:
        from qa.retriever import _engine_search
        # ① 同组件推荐：证据池里出现频次最高的产品
        prods = Counter()
        for d in docs:
            for p in (d.get("products") or [])[:3]:
                if p:
                    prods[str(p)] += 1
        for pname, _ in prods.most_common(2):
            if len(out) >= 6:
                break
            r = _engine_search(f'product:{pname} severity:CRITICAL,HIGH', 4)
            _add(r, f"同组件 {pname} 的高危漏洞")
        # ② 同弱点类型推荐
        cwes = Counter()
        for d in docs:
            for w in _cwe_ids(d)[:2]:
                cwes[w] += 1
        for cwe, _ in cwes.most_common(1):
            if len(out) >= 6:
                break
            r = _engine_search(f'cwe:{cwe}', 3)
            _add(r, f"同类弱点 {cwe}")
        # ③ 实时高危热点兜底：KEV 在野利用 + CRITICAL
        if len(out) < 4:
            r = _engine_search("kev:yes severity:CRITICAL", 5)
            _add(r, "当前在野利用高危热点")
    except Exception as e:  # noqa: BLE001
        print(f"[qa.report] 个性化推荐生成失败（不影响答案）: {str(e)[:120]}")

    return out


# ── ④ 统一收口：任何路径产出的答案都补齐 conclusion + evidence ──
def finalize(question: str, result: Dict, docs: List[Dict] = None) -> Dict:
    """给问答结果补齐「结论 + 原始详细资料」两个字段（缺什么补什么，不覆盖已有值）。

    - evidence 优先用路径自己带的（生成器/智能体已按证据顺序排好）；
      没有则用 docs 现造；再没有就按 sources 里的编号回访主体补齐。
    - conclusion 没显式给就用 answer（LLM 路径的典型情况），再按上限截断。
    - sources 是旧契约（评测脚本在读），缺失时从 evidence 生成，保证不为空。
    """
    if not isinstance(result, dict):
        return result

    # evidence_total 必须是**证据池去重后的总条数**，而不是 len(evidence) ——
    # 后者已被 EVIDENCE_LIMIT 截断，两者永远相等的话，前端那句
    # "12 条（命中 20 条）"就永远显示不出来，用户会以为库里只有这 12 条。
    ev = result.get("evidence") or []
    if ev:
        total = len(ev)
    else:
        ev = build_evidence(docs or [])
        total = len({str(d.get("id") or "") for d in (docs or []) if d.get("id")}) or len(ev)
    if not ev and result.get("sources"):
        ev = evidence_from_ids([s.get("id") for s in result["sources"] if isinstance(s, dict)])
        total = len(ev)

    concl = (result.get("conclusion") or "").strip() or (result.get("answer") or "").strip()
    concl, hit = clip(concl)

    result["conclusion"] = concl
    result["conclusion_chars"] = len(concl)
    result["conclusion_limit"] = CONCLUSION_LIMIT
    result["conclusion_truncated"] = hit
    result["evidence"] = ev[:EVIDENCE_LIMIT]
    result["evidence_total"] = max(total, len(ev))

    srcs = result.get("sources") or []
    if not srcs:
        srcs = [{"id": e["id"], "title": e["title"], "cvss": e["cvss"],
                 "severity": e["severity"]} for e in ev[:8]]
    elif ev and all(not (isinstance(s, dict) and s.get("title")) for s in srcs):
        # 智能体路径的 sources 只有编号 —— 用 evidence 补全标题/评分，评测与前端都更好用
        by_id = {e["id"]: e for e in ev}
        srcs = [{"id": s.get("id"), "title": by_id.get(s.get("id"), {}).get("title", ""),
                 "cvss": by_id.get(s.get("id"), {}).get("cvss"),
                 "severity": by_id.get(s.get("id"), {}).get("severity", "")}
                for s in srcs if isinstance(s, dict)]
    result["sources"] = srcs

    # 个性化推荐（related）：从当前证据池派生关联情报，做"猜你还想看"。
    # 只在还没有时生成（避免智能体路径重复算）；失败/空不影响答案。
    if not result.get("related") and not result.get("related_skipped"):
        try:
            result["related"] = build_related(question, docs or [], result)
        except Exception as e:  # noqa: BLE001
            print(f"[qa.report] 个性化推荐注入异常: {str(e)[:120]}")
            result["related"] = []
    return result
