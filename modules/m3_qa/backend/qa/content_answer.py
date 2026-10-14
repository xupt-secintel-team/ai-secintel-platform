# -*- coding: utf-8 -*-
"""
content_answer.py —— 模板模式的「内容分析层」（v2.5 新增）
================================================================
上一版结论只有**情报来源**的分析（命中几条 / 风险分布 / 时间跨度 / 数据来源），
没有**内容**的分析 —— 用户问"数据安全法对企业的要求是什么"，结论却只回了
"命中 8 条、时间跨度 2023-11-17 ~ 2026-09-20"。真正的问题没被回答。

本层在**不引入 LLM** 的前提下补上内容分析：把命中资料的内容当作**唯一的
写作素材**，做抽取式归纳 —— 直答句 + 编号要点，逐条标注来源编号：

    ## 结论（内容要点）
    《中华人民共和国数据安全法》于2021年9月1日起施行，是我国数据安全领域的
    基础性法律〔DSKB:REG01〕
    命中资料中，与「数据安全法对企业的要求是什么」直接相关的要点归纳如下 6 条
    （原文摘录，末尾编号为出处）：

    1. **数据分类分级保护制度** [DSKB:REG01]
       将数据分为一般数据、重要数据和核心数据
    2. **数据安全风险评估、报告、信息共享、监测预警机制** [DSKB:REG01]

素材来源（按条目类型自动选）：
  - **正文**：`desc` 正文摘要（缺失时退回去标签的 `snippet`）。知识/文章类条目的
    正文常在 `desc` 里，且常用 "(1)xxx；(2)yyy" 的清单写法 —— 拆开后一条即一要点；
  - **处置**：CVE/仓库类条目的 `desc` 是英文原文、中文内容在 `remediation`
    （"升级受影响组件 ollama 至官方修复版本；受影响版本区间：<= 0.17.5。"）。
    正文中文含量不足时，按需回访 `/api/detail` 取处置要点补齐（最多 MAX_ENRICH=5 条，避免拖慢问答）。

四条硬约束（避免"看起来在分析、其实在编"）：
  1. **只用命中资料里的字**：每个要点都是原文片段（只做去编号前缀 / 断句 /
     标点清理），不做同义改写，不做跨文档拼接式推理；
  2. **每条都有出处**：要点末尾标注来源编号，前端点编号即跳该条详情；
  3. **够不着就不写**：不满足相关性闸门的片段不进要点；全池都不满足时直接
     返回 None，结论维持"只有来源统计"的原样 —— 宁可少说，不编；
  4. **中文优先**：同一条资料既有中文正文又有英文原文时只留中文，避免中英混排。

选取策略（两档）：
  - **主资料档**：某条资料自身就是"清单式"正文（含 ≥3 个 (1)(2)(3) 条款，
    如法规/标准/要点类条目），且得分占比 ≥0.25 → 按它**自己的条款顺序**讲，
    末尾补 1 条其他资料的高分要点。这类资料往往就是问题的答案本身。
  - **跨资料档**：没有清单式主资料时，全池按相关性排序取前 N 条，
    同一条资料的多条正文合并进同一个要点（标题用资料标题）。

与 deep_answer 的分工：deep_answer 负责**结构化数值**推理（CVSS 极值 / 计数 /
版本 / 论文），本层负责**文本内容**归纳，两者互不覆盖、可同时出现。
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

# ── 上限 ────────────────────────────────────────────────────────
MAX_POINTS = 6          # 内容要点最多几条
MIN_UNIT_LEN = 8        # 短于此长度的片段不成其为"要点"
MAX_BODY_LEN = 190      # 单个要点正文上限（超长截断，完整原文在「原始详细资料」）
MAX_LEAD_LEN = 170      # 直答句上限
MAIN_SHARE = 0.25       # 主资料的得分占比门槛
MAX_ENRICH = 5          # 最多为几条资料回访详情补中文处置要点
COMMON_FIX_MIN = 3      # 同一句处置话出现在 ≥N 条资料里 → 视为模板句，合并成"共性处置"
MAX_BODY_LINES = 3      # 单个要点最多几行正文
CN_RATIO = 0.15         # 判定"有中文内容"的字数占比

_TAG_RE = re.compile(r"<[^>]+>")
_ENUM_RE = re.compile(r"[（(]\s*(\d{1,2})\s*[)）]")
_CN_RE = re.compile(r"[\u4e00-\u9fff]")
_SENT_SPLIT = re.compile(r"(?<=[。！？；!?;])")
_CLAUSE_SPLIT = re.compile(r"[；;]\s*")
_QUOTE_STRIP = "“”\"'‘’《》()（）[]【】、 "
_META_START = re.compile(r"^(本文|该文|文章|本篇|笔者|下面)")   # "本文…"开头的标题不像标题

# 词面重合用：这些字不参与中文 n 元组（虚词/疑问词，命中它们说明不了相关性）
_STOP_CHARS = set("的了呢吗吧啊么什是如有和与或及在请问哪怎怎样何否介绍讲讲我你他她它其之而乃于对以被把将所也都很更最就还又只一二三四五六")
_EN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]{1,}")

# 问题在问"要求/做法/处置"时，含义务性表述的句子更值得进要点
_REQ_Q = re.compile(r"要求|应当?|必须|须|如何|怎么|怎样|措施|做法|规范|义务|责任|合规|注意什么")
_REQ_VERB = re.compile(r"应|须|必须|需|不得|应当|建立|开展|落实|制定|采取|实施|采用|符合|满足|确保|遵循|履行|禁止|定期")
_FIX_Q = re.compile(r"处置|修复|补丁|缓解|加固|升级|防范|防御|怎么防|影响范围|版本")

# 标题尾（"XXX：YYY" 取冒号后那段做要点标题，比整条标题更像主题词）
_TITLE_TAIL = re.compile(r"[：:]\s*(.{4,40})$")


# ── 素材抽取 ────────────────────────────────────────────────────
def _plain(d: Dict) -> str:
    """条目正文：优先 desc（详情/检索都带），缺失时退回去标签的 snippet"""
    txt = d.get("desc") or ""
    if not txt:
        txt = _TAG_RE.sub("", d.get("snippet") or "")
    txt = (str(txt).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
           .replace("&quot;", '"').replace("&#39;", "'"))
    return re.sub(r"\s+", " ", txt).strip()


def _cn_ratio(text: str) -> float:
    text = text or ""
    return (len(_CN_RE.findall(text)) / len(text)) if text else 0.0


def _has_cn(text: str) -> bool:
    return _cn_ratio(text) >= CN_RATIO


def _sentences(text: str) -> List[str]:
    out = []
    for s in _SENT_SPLIT.split(text or ""):
        s = s.strip().strip("。；;")
        if len(s) >= MIN_UNIT_LEN:
            out.append(s)
    return out


def _enum_clauses(text: str) -> List[str]:
    """把 "(1)xxx；(2)yyy；(3)zzz" 这类枚举正文拆成独立条款（保持原顺序）。

    这是知识/法规类条目的常见写法，拆开后每一条天然就是一个"要点"。
    不满足"至少两个编号标记"时返回空列表，交回句子级切分。
    """
    marks = list(_ENUM_RE.finditer(text or ""))
    if len(marks) < 2:
        return []
    out = []
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        seg = text[m.end():end].strip().strip("；;。 ")
        if len(seg) >= 4:
            out.append(seg)
    return out


def _fix_lines(d: Dict) -> List[str]:
    """处置/修复要点：remediation 里已经是中文的句子（详情接口才有）"""
    out = []
    for r in (d.get("remediation") or []):
        r = str(r).strip()
        if not r or "://" in r:                       # 纯链接跳过
            continue
        for seg in _CLAUSE_SPLIT.split(r):
            seg = seg.strip().strip("。；; ")
            if len(seg) >= MIN_UNIT_LEN and _has_cn(seg):
                out.append(seg)
    return out


def _fix_stats(docs: List[Dict]) -> Tuple[Dict[str, int], Dict[str, str]]:
    """跨条目统计处置行：出现次数 + 原文样本。

    返回 (归一化文本 → 出现在几条资料里, 归一化文本 → 展示用原文)。
    用于两件事：① 识别"模板句"（如"升级受影响组件 X 至官方修复版本"），
    ② 把模板句合并成一句"共性处置"，让每条要点只留**差异信息**（版本区间等）。
    """
    cnt: Dict[str, int] = {}
    sample: Dict[str, str] = {}
    for d in docs[:8]:
        for line in set(_fix_lines(d)):
            k = _norm(line)
            if not k:
                continue
            cnt[k] = cnt.get(k, 0) + 1
            sample.setdefault(k, line)
    return cnt, sample


# ── 相关性打分 ──────────────────────────────────────────────────
def _terms(question: str) -> List[Tuple[str, float]]:
    """问题 → (词元, 权重)。中文取二元组（2.0）/三元组（3.5），英文词取 2.5。"""
    terms: Dict[str, float] = {}
    q = re.sub(r"[，。？！、：；,.?!:;()（）\[\]【】]", " ", question or "")
    for seg in re.findall(r"[\u4e00-\u9fff]+", q):
        for i in range(len(seg) - 1):
            g2 = seg[i:i + 2]
            if any(c in _STOP_CHARS for c in g2):
                continue
            terms[g2] = 2.0
        for i in range(len(seg) - 2):
            g3 = seg[i:i + 3]
            if any(c in _STOP_CHARS for c in g3):
                continue
            terms[g3] = 3.5
    for w in _EN_RE.findall(question or ""):
        wl = w.lower()
        if len(wl) >= 2 and wl not in _STOP_CHARS:
            terms[wl] = max(terms.get(wl, 0.0), 2.5)
    return sorted(terms.items(), key=lambda x: -x[1])


def _hit_score(text: str, terms: List[Tuple[str, float]]) -> float:
    low = text.lower()
    return sum(w for t, w in terms if t in low)


def _distinct_hit(text: str, terms: List[Tuple[str, float]]) -> int:
    low = text.lower()
    return sum(1 for t, _ in terms if t in low)


def _authority(d: Dict) -> float:
    """来源权威度加成：知识库/法规类条目 > 社区文章（同分时更该先说权威条目）"""
    if (d.get("type") or "") in ("knowledge", "regulation") or str(d.get("id", "")).startswith("DSKB"):
        return 1.5
    if (d.get("trust_label") or "") in ("权威知识库", "官方", "厂商公告"):
        return 1.0
    return 0.0


def _unit_score(text: str, doc: Dict, terms: List, req_q: bool) -> float:
    """相关性得分：词面命中 - 长度惩罚（惩罚有上限，别把长句直接打成负分）。"""
    hit = _hit_score(text, terms)
    if hit <= 0:
        return 0.0
    s = hit + _authority(doc)
    if req_q and _REQ_VERB.search(text):
        s += 2.0
    s -= min(1.5, max(0.0, (len(text) - 80) / 160.0))
    return s


def _passes_gate(text: str, terms: List, kind: str) -> bool:
    """相关性闸门：够不着就不写。

    - 清单条款（主资料的 (1)(2)(3)）只要命中 ≥1 个词元即可 —— 它属于一个
      整体相关的清单，单独看往往只有"数据"这类泛词；
    - 普通句子/处置行必须自己站得住：命中 ≥2 个不同词元，或命中一个高权重
      三元组/英文词（避免"受影响版本为低于0.1.34…"这种撞上一个泛词就混进来）。
    """
    if _hit_score(text, terms) <= 0:
        return False
    if kind == "clause":
        return True
    return _distinct_hit(text, terms) >= 2 or _hit_score(text, terms) >= 2.5


def _norm(text: str) -> str:
    return re.sub(r"[\s，。；、：:,.!！?？\"'“”‘’()（）\[\]【】]", "", text or "")


def _is_dupe(a: str, b: str, same_doc: bool = True) -> bool:
    """近乎重复：一条包含另一条，或字符三元组 Jaccard 超阈值。

    阈值分档：同一条资料内的重复（自说自话）判得严；跨资料的"模板句"判得松 ——
    CVE 条目的处置行天然长得像（"升级受影响组件 X 至官方修复版本"），
    但组件名/版本区间不同就是不同的事实，不该被当成重复删掉。
    包含判定也要求长度量级相当：短句被长句包住不等于重复。
    """
    na, nb = _norm(a), _norm(b)
    if not na or not nb:
        return False
    short, long_ = (na, nb) if len(na) <= len(nb) else (nb, na)
    if short in long_:
        ratio = len(short) / max(1, len(long_))
        return ratio >= (0.55 if same_doc else 0.8)
    ta = {na[i:i + 3] for i in range(max(1, len(na) - 2))}
    tb = {nb[i:i + 3] for i in range(max(1, len(nb) - 2))}
    if not ta or not tb:
        return False
    return len(ta & tb) / max(1, len(ta | tb)) >= (0.55 if same_doc else 0.85)


def _is_title_echo(unit: str, doc: Dict) -> bool:
    """正文首句常常就是标题本身（"XXX：YYY" 的复述）→ 不成其为要点。"""
    t = _norm(str(doc.get("title") or ""))
    u = _norm(unit)
    if not t or not u:
        return False
    return t in u or u in t


# ── 要点标题 / 正文切分 ─────────────────────────────────────────
_COMMA_RE = re.compile(r"[，,：:]")


def split_heading(text: str) -> Tuple[Optional[str], str]:
    """把一个要点片段切成 (标题, 正文)。找不到自然标题时返回 (None, 片段)。

    规则（保守，只做"切一刀"，不改写）：
      ① 有逗号/冒号，且前半 4~24 字、后半 ≥6 字 → 前半当标题，后半当正文；
        例："数据分类分级保护制度，将数据分为一般数据、重要数据和核心数据"
      ② 整条就是名词短语（≤34 字且不含逗号）→ 整条当标题：
        例："数据安全风险评估、报告、信息共享、监测预警机制"
      ③ 其它 → 无标题，整条当正文（标题交由所属资料的标题补位）。
    """
    t = (text or "").strip()
    m = _COMMA_RE.search(t)
    if m:
        i = m.start()
        if 4 <= i <= 24 and len(t) - i - 1 >= 6:
            return t[:i].strip(_QUOTE_STRIP), t[i + 1:].strip()
    if len(t) <= 34 and "，" not in t:
        return t.strip(_QUOTE_STRIP), ""
    return None, t


def _title_heading(doc: Dict) -> str:
    """资料标题 → 要点标题：优先取冒号后那段主题词，其次整条标题（截断）。

    截断一律落在词/字边界上并加省略号，避免出现 "Ollama MCP Server execAsync
    Command Inje" 这种断在单词中间的标题。
    """
    title = re.sub(r"[。？?！!]+$", "", str(doc.get("title") or "")).strip()
    m = _TITLE_TAIL.search(title)
    head = (m.group(1) if m else title).strip()
    if len(head) <= 40:
        return head
    cut = head[:40]
    if " " in cut[28:]:
        cut = cut[:28 + cut[28:].rfind(" ")]
    return cut.rstrip(" ,;，；") + "…"


def _clip(t: str, limit: int) -> str:
    t = (t or "").strip()
    return t if len(t) <= limit else t[:limit].rstrip() + "…"


# ── 主流程 ──────────────────────────────────────────────────────
def _collect(question: str, docs: List[Dict], terms: List, req_q: bool,
             common_fix: Dict[str, int] = None) -> List[Dict]:
    """收集候选要点：正文（清单条款 / 句子）+ 处置要点（中文 remediation）

    common_fix 里的"模板句"不进要点 —— 它们会被合并成一句共性处置写在段首。
    """
    common_fix = common_fix or {}
    cands: List[Dict] = []
    for d in docs[:8]:
        body = _plain(d)
        chosen: List[Dict] = []
        clauses = _enum_clauses(body)
        if clauses:
            units = [(i, u, "clause") for i, u in enumerate(clauses)]
        else:
            units = [(i, u, "sentence") for i, u in enumerate(_sentences(body))]
        for pos, u, kind in units:
            if _is_title_echo(u, d):          # 复述标题的句子不算要点
                continue
            if not _passes_gate(u, terms, kind):
                continue
            sc = _unit_score(u, d, terms, req_q)
            if sc > 0:
                chosen.append({"doc": d, "pos": pos, "text": u, "score": sc, "kind": kind})
        # 中文正文不足（英文原文条目）→ 取处置要点补齐，让"怎么处置"有内容可讲。
        # 闸门/打分用"完整处置句"（含模板句，里面才带组件名，能对上问题里的词），
        # 渲染只留差异行（版本区间等）—— 模板句已合并进段首的「共性处置」。
        all_fixes = _fix_lines(d)
        distinct = [x for x in all_fixes if _norm(x) not in common_fix]
        if distinct and not any(c["kind"] == "clause" for c in chosen):
            gate_txt = "；".join(all_fixes[:2]) or distinct[0]
            if _passes_gate(gate_txt, terms, "fix"):
                sc = _unit_score(gate_txt, d, terms, req_q) + (1.0 if _FIX_Q.search(question or "") else 0.0)
                if sc > 0:
                    chosen.append({"doc": d, "pos": 90, "text": "；".join(distinct[:2]), "score": sc,
                                   "kind": "fix", "lines": distinct[:2]})
        cands.extend(chosen)
    return cands


def _enrich(docs: List[Dict], need: int = MAX_ENRICH) -> None:
    """就地补齐候选资料的中文处置要点（详情接口才带 remediation）。

    只为"正文中文含量不足"的资料回访，最多 need 条，失败静默跳过 ——
    内容分析是加分项，绝不因为它把问答拖慢或搞崩。
    """
    done = 0
    for d in docs[:8]:
        if done >= need:
            break
        if d.get("remediation") or _has_cn(_plain(d)[:120]):
            continue
        cid = str(d.get("id") or "")
        if not cid:
            continue
        done += 1
        try:
            from qa.retriever import get_detail
            det = get_detail(cid) or {}
            if det.get("remediation"):
                d["remediation"] = det["remediation"]
        except Exception:  # noqa: BLE001
            continue


def content_section(question: str, docs: List[Dict], max_points: int = MAX_POINTS) -> Optional[str]:
    """产出「## 结论（内容要点）」段落；素材不足或完全不相关时返回 None。"""
    if not docs:
        return None
    terms = _terms(question)
    if not terms:
        return None
    req_q = bool(_REQ_Q.search(question or ""))

    _enrich(docs)
    fcnt, fsample = _fix_stats(docs)
    common_fix = {k: v for k, v in fcnt.items() if v >= COMMON_FIX_MIN}
    cands = _collect(question, docs, terms, req_q, common_fix)
    if not cands:
        return None

    # ① 主资料判定：清单式正文（≥3 条款）+ 得分占比达标 → 按它自己的条款顺序讲
    by_doc: Dict[str, List[Dict]] = {}
    for c in cands:
        by_doc.setdefault(str(c["doc"].get("id") or ""), []).append(c)
    total = sum(c["score"] for c in cands) or 1.0
    main_id, main_share = "", 0.0
    for did, items in by_doc.items():
        if sum(1 for c in items if c["kind"] == "clause") < 3:
            continue
        share = sum(c["score"] for c in items) / total
        if share > main_share:
            main_id, main_share = did, share

    picked: List[Dict] = []
    if main_id and main_share >= MAIN_SHARE:
        main = sorted(by_doc[main_id], key=lambda c: c["pos"])
        picked = main[:max_points - 1]
        rest = sorted([c for c in cands if str(c["doc"].get("id")) != main_id],
                      key=lambda c: -c["score"])
    else:
        rest = sorted(cands, key=lambda c: -c["score"])
    for c in rest:
        if len(picked) >= max_points:
            break
        if any(_is_dupe(p["text"], c["text"],
                        str(p["doc"].get("id")) == str(c["doc"].get("id"))) for p in picked):
            continue
        picked.append(c)
    if not picked:
        picked = sorted(cands, key=lambda c: -c["score"])[:max_points]

    # ② 组织成"要点块"：清单条款各占一块；同一资料的句子/处置行归并成一块
    #    （按资料 id 归并，而不是只看上一块 —— 中间夹了别的资料时也要并回去，
    #     否则同一条资料会出现两个标题相同的要点）
    blocks: List[Dict] = []
    doc_block: Dict[str, Dict] = {}
    for c in picked:
        head, body = split_heading(c["text"])
        if head and _META_START.match(head):
            head = None                        # "本文围绕…"当标题不像标题 → 用资料标题
        did = str(c["doc"].get("id") or "")
        if c["kind"] == "clause" and head:
            blocks.append({"doc": c["doc"], "id": did, "heading": head,
                           "bodies": [(body, "body")] if body else [], "from_doc": False})
            continue
        blk = doc_block.get(did)
        if blk is None:
            blk = {"doc": c["doc"], "id": did, "heading": _title_heading(c["doc"]),
                   "bodies": [], "from_doc": True}
            blocks.append(blk)
            doc_block[did] = blk
        if c["kind"] == "fix":
            for line in c.get("lines") or [c["text"]]:
                blk["bodies"].append((line, "fix"))
        else:
            blk["bodies"].append((c["text"], "body"))
    if not blocks:
        return None

    # ③ 中文优先：同一条资料里若有中文正文/处置，丢掉纯英文行（避免中英混排）
    for b in blocks:
        if any(_has_cn(t) for t, _ in b["bodies"]):
            b["bodies"] = [(t, k) for t, k in b["bodies"] if _has_cn(t)]

    # ④ 直答句：主资料（或首个要点来源）正文的第一句有效句。
    #    中文提问时只认中文句 —— 否则会把 "PAN-OS 9.0 versions earlier than
    #    PAN-OS 9.0.9" 这种英文原文片段当结论顶在中文答案最前面。
    lead_doc = next((b["doc"] for b in blocks if b["id"] == main_id), blocks[0]["doc"])
    need_cn = _has_cn(question or "")
    lead = next((s for s in _sentences(_plain(lead_doc))
                 if len(s) >= 15 and not _is_title_echo(s, lead_doc)
                 and (_has_cn(s) or not need_cn)), "")
    lead = _clip(lead, MAX_LEAD_LEN)
    lead_id = str(lead_doc.get("id") or "")

    # ⑤ 渲染
    q_show = (question or "").strip().rstrip("？?")[:40]
    lines = ["## 结论（内容要点）", ""]
    if lead:
        lines += [f"{lead}〔{lead_id}〕" if lead_id else lead, ""]
    lines += [f"命中资料中，与「{q_show}」直接相关的要点归纳如下 {len(blocks)} 条"
              "（原文摘录，末尾编号为出处）：", ""]
    if common_fix:
        k = max(common_fix, key=lambda x: (common_fix[x], len(fsample.get(x, ""))))
        lines += [f"共性处置（{common_fix[k]} 条资料一致）：{fsample.get(k, '')}", ""]
    for i, b in enumerate(blocks, 1):
        cite = f"[{b['id']}]" if b["id"] else ""
        if b["heading"]:
            lines.append(f"{i}. **{b['heading']}** {cite}".rstrip())
        else:
            lines.append(f"{i}. {cite}".rstrip())
        for text, kind in b["bodies"][:MAX_BODY_LINES]:
            prefix = "处置：" if kind == "fix" else ""
            lines.append(f"   {prefix}{_clip(text, MAX_BODY_LEN)}")
    lines.append("")
    lines.append("_依据：以上要点逐条摘自命中资料正文/处置字段，只做断句与标点清理，"
                 "未做改写；完整原文见下方「原始详细资料」。_")
    lines.append("")
    return "\n".join(lines)
