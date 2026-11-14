# -*- coding: utf-8 -*-
"""
relevance.py —— 检索结果的**相关度闸门**（v2.6 新增）
================================================================
要解决的问题（实测：
问「zzzqqq不存在的术语xyzzy」仍返回「本次检索命中 **8 条**相关情报」，
附上 8 条完全无关的条目（PHP 反射类、Lorex 摄像头…））：

  旧链路里 `hybrid_search()` 拿到候选后直接 `results[:top_k]` 截断，
  **没有任何相关度下限**；而 `multi_hop.FINAL_K = 8` 又是固定数 ——
  于是哪怕库里一条都不相关，也必然"凑满 8 条"。用户无法区分
  「真命中」与「兜底填充」，这正是"精准回答"最不能接受的一件事。

本模块提供**单一判据**（`is_relevant` / `gate`），供所有检索入口共用：
  - `hybrid_search()` —— 混合检索
  - `multi_hop_search()` —— 多跳检索
  - `agent` 工具 —— 智能体自主检索

判据的设计原则：**宁可判"相关"也不要误杀真命中**（漏报比误报伤害更大 ——
把一条真实的 CVE 判成无关，用户会以为库里没有，这是不可逆的误导）。
所以门槛取"任一信号够强即通过"，而不是"所有信号都过"：

  ① **实词命中**（最强判据）：查询里的产品名 / CVE / CWE 等实词
     出现在文档的 title / products / cwe / desc 里 —— 这是"用户问的东西
     库里有"的**直接证据**，几乎不会误判；
  ② 向量余弦 ≥ VECTOR_FLOOR 且 **查询里有实词**（见下方定标说明）。

★ **VECTOR_FLOOR 是实测定标的，不是拍的**（2026-10-07 真跑 118348 条库得出）：
    相关组（Ollama / vLLM / LangChain / prompt injection）= **0.90 ~ 0.92**
    不相关组（"如何做红烧肉" / "今天天气怎么样" / 瞎编字符串）= **0.844 ~ 0.885**
  两组虽接近但可分，**0.89 是实测的分离点**。
  为什么不是常见的 0.62：本库**全是安全领域文本**，同域内余弦天然偏高，
  0.62 会把"如何做红烧肉"（0.848）也判成相关 —— 这正是"零命中不诚实"的根因。
  ★ 换语料 / 换嵌入模型必须**重新定标**，不可沿用。

可用环境变量调参：
  AISEC_QA_VECTOR_FLOOR  向量余弦下限（默认 0.89，实测定标）
  AISEC_QA_BM25_FLOOR    BM25 分下限（默认 1.0）
"""
from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple

VECTOR_FLOOR = float(os.environ.get("AISEC_QA_VECTOR_FLOOR", "0.89") or 0.89)
BM25_FLOOR = float(os.environ.get("AISEC_QA_BM25_FLOOR", "1.0") or 1.0)
# 纯 BM25 路的判据（详见 is_relevant 第 ⑤ 条，2026-10-07 实测定标）：
#   ★ 先试"首条断层"，实测**证伪**（这条路不成立）：
#     真命中「哪些 AI 框架存在在野利用的漏洞」kev:yes：
#        23.7, 22.6, 22.3, 22.2, 21.1 …  → **平坦**（无断层）
#     真命中「最近被在野利用的漏洞」kev:yes：
#        24.6, 23.3, 22.8, 22.8, 21.7 …  → **平坦**（无断层）
#     KEV 路是**引擎精确过滤**（kev:yes）的产物，满足条件的条目分值天然接近 ——
#     指望它出现"断层"是错的。而真正该丢弃的是**非 KEV 的中文博客**
#     （那条路径分值 8~20、且 exploited 为空）。
#   ✔ 所以判据分两步：
#     ① 若本批**整体**满足结构化条件（如全是 exploited=true）→ 整批都是真命中，全留；
#     ② 否则退回**绝对下限** `BM25_MIN`（只留分数明显高的），滤掉泛相关长尾。
BM25_MIN = float(os.environ.get("AISEC_QA_BM25_MIN", "8.0") or 8.0)   # 纯 BM25 路首条/兜底分数下限
BM25_RATIO = float(os.environ.get("AISEC_QA_BM25_RATIO", "2.0") or 2.0)  # 保留：断层判据（当前默认不启用）
# ★ 2026-10-26 补：**绝对分强信号**。口语化中文提问（"大模型输出被投毒污染"）的
# BM25 分布天然平坦（27.6/25.8/25.8…），断层比值永远 <2.0，只看比值会把
# 整池判成"泛相关"清空；而真正无关的查询（"如何做红烧肉" 8.6、"zzzqqq…" 13.0）
# 绝对分明显低一个量级。所以补一条：首条分 ≥ BM25_STRONG 时，按"首条的 55%"
# 取带宽保底，既救回真命中，又不会把无关查询放进来（实测分离点是 13 vs 27）。
BM25_STRONG = float(os.environ.get("AISEC_QA_BM25_STRONG", "18") or 18)
BM25_STRONG_RATIO = float(os.environ.get("AISEC_QA_BM25_STRONG_RATIO", "0.55") or 0.55)

# 查询里的「实词」：英文/数字标识符（≥3 字符）与中文词（≥2 字）。
# 停用词不参与判据 —— 否则「有什么漏洞」会因为"漏洞"二字出现在库里而误判相关。
_QUERY_STOP_EN = {
    "the", "and", "for", "with", "what", "which", "how", "why", "are", "is",
    "does", "have", "has", "been", "that", "this", "there", "any", "all",
}
_QUERY_STOP_CN = {
    "什么", "哪些", "哪个", "怎么", "如何", "是否", "有没有", "多少", "几个",
    "相关", "情况", "介绍", "一下", "请问", "帮忙", "帮我", "漏洞", "情报",
    "信息", "内容", "详情", "具体", "现在", "目前", "最近", "这个", "那个",
}
_IDENT_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]{2,}|\d{3,}")
_CJK_RE = re.compile(r"[\u4e00-\u9fff]{2,}")
# CVE / CWE / GHSA 这类**强标识符**：命中即铁证
_STRONG_ID_RE = re.compile(r"(?:CVE-\d{4}-\d{4,7}|CWE-\d+|GHSA-[a-z0-9-]{4,})", re.I)

# ★ 实测踩过的坑（这是本文件最重要的一条）：
#   中文**普通词**做子串匹配会产生大量假阳性 ——
#   实测问「zzzqqq不存在的术语xyzzy」时，`不存在` 命中了
#   《记一次不存在的加解密实战渗透》这类标题（"不存在的X"是中文惯用语），
#   于是 12 条完全无关的渗透文章被判为"相关"，零命中诚实化失效。
#   根因：中文普通词在语料里是**高频偶发**的，它的出现证明不了"用户在问这个主题"。
#   所以**只有标识符类实词才算"铁证"**：
#     - CVE / CWE / GHSA 编号（用户既已在问编号，库里有就是铁证）
#     - 拉丁字母产品名 / 包名（Ollama / vLLM / langchain / numpy …）
#   中文词**降级为"辅助信号"**：只有在"语义也接近"时才作为佐证，不能单独定相关。
_CN_GENERIC = True

# 滑窗产物（跨词边界碎片，如"在野利""野利用"）—— 由 query_terms 填充。
# 碎片只对 BM25 打分有意义，**不能**当"用户在问这个主题"的证据（会假阳性）。
_FRAGMENTS = set()

# ★ 中文长串的切分点（第 3 轮实测补全）：
#   原实现只按 `的了和与或及` 切，遇到 `怎么修复远程代码执行`（12 字，
#   里面一个切分字都没有）就整串滑窗 → **100% 的 terms 变成碎片**，
#   branch ①b/④ 全部失效 —— 真命中反而判不出（典型的"修一个坏一个"）。
#   补全**动词/疑问/助词**类切分点，让常见问句能切成真词：
#     `怎么修复远程代码执行` → 怎么 | 修复 | 远程 | 代码 | 执行
_CN_SPLIT = re.compile(
    r"[的了和与或及]+|"
    r"(?:怎么|如何|什么|哪些|哪个|多少|是否|有没有|请问|"
    r"最近|最新|近期|目前|现在)+|"
    r"(?:修复|解决|处置|缓解|加固|防范|应对|排查|检测|利用|影响|范围|建议|"
    r"介绍|说明|解释|分析|统计|相关|存在|被|有|是|在)+"
    r"(?=[\u4e00-\u9fff])")


def strong_terms(query: str) -> List[str]:
    """只抽**铁证类**实词（CVE/CWE/GHSA 编号 + 拉丁产品名/包名）。

    这些词命中文档 = 用户问的东西**确实在库里**，几乎不可能假阳性。
    中文普通词**不算铁证**（见上方注释：中文惯用语会造成假阳性）。
    """
    out: List[str] = []
    seen = set()
    for m in _STRONG_ID_RE.findall(query or ""):
        t = m.strip().lower()
        if t not in seen:
            seen.add(t)
            out.append(t)
    for m in _IDENT_RE.findall(query or ""):
        tl = m.strip().lower()
        # 纯数字不算（太泛）；英文标识符 ≥3 字符且非停用词才算
        if tl.isdigit() or len(tl) < 3 or tl in _QUERY_STOP_EN:
            continue
        if tl not in seen:
            seen.add(tl)
            out.append(tl)
    return out


def query_terms(query: str) -> List[str]:
    """从问题里抽「实词」（用于判"文档里到底有没有提到我在问的东西"）。

    ★ 实测校准过（否则判据会自证失效）：
      - 英文/数字标识符：保留**完整词**（≥3 字符），**绝不切碎** ——
        `zzzqqq` 若被切成 `zzz`/`qqq` 就可能碰巧命中无关文档；
      - 中文：只保留**整段实词**（2~6 字），**不做 2 字滑窗** ——
        滑窗会把「不存在的术语」切出 `的术`/`术语` 这种碎片，
        碎片一旦碰到任何含"术语"字样的文档就误判相关（实测踩过）。
      - 停用词不参与判据 —— 否则「有什么漏洞」会因为"漏洞"二字在库里普遍出现而误判。

    例：「Ollama 有哪些高危漏洞」→ ["ollama"]；
        「CVE-2024-1234 的修复建议」→ ["cve-2024-1234", "修复建议"]。
    """
    out: List[str] = []
    seen = set()

    def _add(t: str):
        tl = t.strip().lower()
        if not tl or tl in seen:
            return
        if tl in _QUERY_STOP_EN or tl in _QUERY_STOP_CN:
            return
        if len(tl) < 2:
            return
        seen.add(tl)
        out.append(tl)

    # 英文/数字标识符：保留完整词（CVE-2024-1234 这类整串是一个实词）
    for m in _IDENT_RE.findall(query or ""):
        _add(m)
    # 中文：整段实词（2~6 字），**超长段才滑窗**。
    #
    # ★ 第 3 轮实测修正（R3-2 根因）：原实现遇到**长 CJK 连续段**直接整段丢弃 ——
    #   `哪些 AI 框架存在在野利用的漏洞` 里 `框架存在在野利用的漏洞` 是 12 字连续段
    #   （中间没有 `的了和与或及` 可切），`2 <= len <= 6` 不满足就**整段不要**，
    #   于是纯中文提问（"怎么修复远程代码执行"）的 terms 恒为 `[]`。
    #   terms 为空 → 判据①②③全废 → 只剩"余弦 ≥ 0.90"一条独木桥，
    #   而相关组（0.90~0.92）与不相关组（0.844~0.885）在 0.90 附近贴边，
    #   实测把真命中（Ray 的 CVE）全判成不相关 —— 表现就是「证据只剩 1 条」。
    #   所以长段必须**分段取词**，不能整段丢。
    #
    # ★★ 但滑窗产物（"在野利""野利用"）是**跨词边界碎片**，会命中无关文档 ——
    #   实测「最近被在野利用的漏洞」因此放行 8 篇中文博客冒充漏洞。
    #   处理：滑窗词单独记进 `_FRAGMENTS`，`is_relevant` 的"中文佐证"分支
    #   **不认碎片**（碎片只能给 BM25 打分用，不能当"用户在问这个主题"的证据）。
    for m in _CJK_RE.findall(query or ""):
        for piece in re.split(_CN_SPLIT, m):
            if 2 <= len(piece) <= 6:
                _add(piece)          # 整段真词
            elif len(piece) > 6:
                for n in (3, 2):
                    for i in range(len(piece) - n + 1):
                        w = piece[i:i + n]
                        _add(w)
                        if len(w) >= 2:
                            _FRAGMENTS.add(w.lower())   # 标记为滑窗产物
    return out


def _doc_text(doc: Dict) -> str:
    """文档的全文本（title + products + cwe + desc/snippet），用于实词命中判定。"""
    parts = [str(doc.get("title") or ""), str(doc.get("id") or "")]
    for p in (doc.get("products") or [])[:8]:
        if isinstance(p, dict):
            parts.append(str(p.get("name") or p.get("product") or ""))
        else:
            parts.append(str(p))
    for w in (doc.get("cwe") or [])[:4]:
        parts.append(str(w.get("id") if isinstance(w, dict) else w))
    txt = doc.get("desc") or doc.get("summary") or ""
    if not txt:
        txt = re.sub(r"<[^>]+>", "", str(doc.get("snippet") or ""))
    parts.append(str(txt))
    return " ".join(parts).lower()


def _vector_score(doc: Dict) -> Optional[float]:
    v = doc.get("vector_score")
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _bm25_score(doc: Dict) -> float:
    for k in ("score", "bm25_score", "_score"):
        v = doc.get(k)
        if isinstance(v, (int, float)):
            return float(v)
    return 0.0


def is_relevant(doc: Dict, terms: List[str] = None,
                strong: List[str] = None, ctx: Dict = None) -> bool:
    """单条文档是否与查询「确实相关」。

    三条实测结论决定了本函数的设计：
      ★1 **向量余弦单独不足以判相关**：本库全是安全文本，瞎编查询也拿 0.85+
         （实测"如何做红烧肉"=0.848，"zzzqqq不存在的术语xyzzy"=0.885）。
      ★2 **中文普通词做子串匹配会假阳性**："不存在"命中《记一次不存在的加解密
         实战渗透》（中文惯用语），把 12 条无关文章判成相关。
      ★3 因此**只有铁证类实词**（CVE/CWE/GHSA 编号、拉丁产品名）能单独定相关；
         中文词只能做"语义接近时的佐证"。

    判据（任一通过即相关）：
      ① 铁证命中 —— 查询里的 CVE/产品名**确实出现在**文档里；
      ② 余弦 ≥ VECTOR_FLOOR **且** 查询含铁证词 —— 语义高接近 + 提问是有意义实体；
      ③ 双路交集（bm25+vector）**且** 查询含铁证词。
    """
    terms = terms if terms is not None else []
    strong = strong if strong is not None else []
    text = _doc_text(doc)
    strong_hit = bool(strong) and any(t in text for t in strong)

    # ① 铁证命中 → 直接相关（用户问的东西确实在库里）
    if strong_hit:
        return True

    vs = _vector_score(doc)
    # ①b 中文实词命中 **且** 语义接近 → 相关（第 3 轮补）。
    #   为什么必须与语义同时成立：中文普通词子串匹配有假阳性风险
    #   （"不存在"命中《记一次不存在的加解密实战渗透》），单靠词面会误判；
    #   但"词面命中 + 余弦 ≥ 不相关组上限(0.885)"两者同时成立时，假阳性概率极低。
    #   ★ 滑窗碎片必须排除（第 3 轮实测补）：`滑窗` 会切出 `在野利`/`野利用` 这类
    #     **跨词边界碎片**，它们能命中"在野利用"字样的无关博客 → 实测
    #     「最近被在野利用的漏洞」因此放行 8 篇中文博客冒充漏洞。
    #     所以这里只认**真词**：长度 ≥ 3 **且不是滑窗产物**（见 `_is_fragment`）。
    if strong:
        pass  # 有铁证词时，下面按铁证口径判（更严）
    elif terms and vs is not None and vs >= max(VECTOR_FLOOR, 0.885):
        # 只认**真词**：长度 ≥ 3、命中文本，且**不是滑窗碎片**
        # （碎片如"野利用"能命中无关博客，实测让 8 篇中文博客冒充漏洞）
        if any(len(t) >= 3 and t in text and t not in _FRAGMENTS for t in terms):
            return True

    # ② 语义高度接近 **且** 铁证词**确实命中**文档。
    #    ★ 第 6 轮实测修正（R6-A）：原判据只看 `strong` **非空**，不看是否命中 ——
    #      实测「foobarbaz-9x 的安全漏洞」「CWE-99999 相关的漏洞」
    #      （都是**库里根本不存在**的东西）：strong=['foobarbaz-9x'] 非空但
    #      从未出现在任何文档里，却因为 `strong` 非空放行了
    #      语义路 0.9008~0.9054 的噪声条目 → 假查询返回 4~8 条无关情报，
    #      **违反第 1 轮就立下的"零命中诚实化"**（同一系统 6 个假查询里
    #      只有 3 个如实说"没有"，另 3 个在凑数）。
    #      根因：把"提问里有标识符"当成了"标识符在库里"，两件事完全不同。
    #      判据必须是 `strong_hit`（真的在文档文本里）——
    #      这正是分支①的定义；本条要的是"语义也高"这个**额外**条件。
    if vs is not None and vs >= VECTOR_FLOOR and strong_hit:
        return True
    # ③ 双路交集 + 铁证词**确实命中**
    if doc.get("_fusion") == "bm25+vector" and strong_hit:
        return True
    # ④ 查询里**没有铁证词**（纯中文提问）：语义是唯一信号，门槛抬高一档。
    #    这类提问（"怎么修复远程代码执行"）无法用标识符判，只能靠语义 ——
    #    但必须是"明显高于不相关组上限 0.885"的余弦（实测相关组 0.90+）。
    #    ★ 第 3 轮实测修正：**必须同时有"真词"命中**，不能只看余弦。
    #      反例实测：问「最近被在野利用的漏洞」，8 篇中文博客以
    #      `_fusion=vector, vec=0.9017~0.9063` 全部通过 —— 它们只是"安全主题"，
    #      与"在野利用"无关，余弦却刚好压线。根因：本库全是安全文本，
    #      **纯余弦区分不了"同域"与"同题"**（两者都能上 0.90）。
    #      加上"真词命中（排除滑窗碎片）"后这类同域噪声被拦掉，
    #      真命中（标题/正文含查询实词的条目）仍通过；`bm25+vector` 双路命中
    #      视为引擎已确认词面匹配，也放行。
    if not strong and vs is not None and vs >= max(VECTOR_FLOOR, 0.90):
        _word_ok = any(len(t) >= 2 and t not in _FRAGMENTS and t in text for t in terms)
        if _word_ok or doc.get("_fusion") == "bm25+vector":
            return True
    # ④b **双路交集**（词面 BM25 + 语义）不再要求铁证词（2026-10-18 实测补）：
    #    原 ③ 要求 `strong_hit`，但铁证词只认拉丁标识符（CVE/产品名），纯中文
    #    提问永远抽不出 → ③ 对纯中文查询恒死。而 `_fusion == "bm25+vector"`
    #    本身已是**两个独立信号的交集**：BM25 引擎确认词面匹配 + 语义余弦
    #    ≥ VECTOR_FLOOR（实测不相关组上限 0.885）。实测《中华人民共和国
    #    数据安全法》（DSKB:REG01）双路命中（BM25 17.3 + vec 0.8991）却被
    #    全灭 —— 卡在两处：查询长段「数据安全法对企业」滑窗产物全被标为
    #    碎片（真词判据失效），0.8991 又差 0.0009 不过纯语义路的 0.90 门槛。
    #    门槛说明：0.90 高门槛是给**纯语义单路**的（防"同域泛相关"）；
    #    双路有词面佐证，回到实测分离点 VECTOR_FLOOR(0.89) 即可。
    if not strong and vs is not None and vs >= VECTOR_FLOOR \
            and doc.get("_fusion") == "bm25+vector":
        return True
    # ⑤ **纯 BM25 路**（无 vector_score）**且查询无铁证词**。
    #    为什么必须有这一条（第 3 轮 R3-2 根因，整条链路实测还原）：
    #      `hybrid_search` 识别到"强标记意图"（在野利用/POC/高危）时会**主动跳过
    #      语义路**（retriever.py:117），返回条目只有 `_fusion='bm25'`、**无 vector_score**；
    #      而纯中文提问又抽不出铁证词 → ①②③④ 全落空，**真命中也全判不相关**
    #      （实测「哪些 AI 框架存在在野利用的漏洞」证据从应 6~8 条塌成 1 条）。
    #    ⚠ 这里**不能用词面命中判** —— 实测该题真命中标题是英文
    #      （"Ray is an AI compute engine"），中文查询词一个字都对不上，词面判据必失效。
    #    ✔ 用**首条断层**判（实测定标见文件顶部注释）：
    #      真命中首条 35.4 vs 次条 6.9（5.1×）；不相关是平坦群 8.4/8.3（1.05×）。
    #      `ctx["cut"]` 是 gate() 预算好的"断层以上同梯队"的分数线，
    #      这里只做一次比较 —— 判定逻辑集中在 gate()，避免每个 doc 重复算分布。
    # ⑤c **混合池里的 BM25 命中**（2026-10-26 补）：池子里既有 BM25 条目
    #    （带 score）又有向量条目（只有 vector_score）时，BM25 条目过去必须
    #    二选一：要么余弦 ≥0.89（它没这么高），要么走下面「纯 BM25 路」（vs 必须
    #    为 None，但它被融合时挂上了 vector_score）→ **两条都进不去，整池被清空**。
    #    实测检索评测 8 道语义改写/中文题混合检索返回 0 条即此因。
    #    修法：只要这条候选在 BM25 断层线以上就认它 —— 引擎的词面排序本来就是
    #    本系统最强的信号，语义路不该把它挤掉。
    if not strong:
        _cut = (ctx or {}).get("bm25_cut")
        if _cut and _cut > 0 and _bm25_score(doc) >= _cut:
            return True

    if not strong and vs is None:
        ctx = ctx or {}
        # ① 引擎已按结构化条件（kev:yes 等）精确过滤过整批 → 全部放行。
        #    ★ 不需要 terms：引擎的字段级过滤比我们的词面启发式更可信，
        #      而中文查询常常抽不出真词（"最近被在野利用的漏洞" → terms=[]），
        #      要求 terms 会让这条唯一可信的判据失效（实测整池被清空）。
        if ctx.get("bm25_all_kev"):
            return True
        # ①c **逐条**字段证据放行（2026-10-18 实测补，修复"整批"前提失效）：
        #    strong_marker 把「在野利用」翻成 kev:yes 后，retriever 会把
        #    **boosted（KEV 精确过滤）批**与**原始查询批**合并成一个候选池 ——
        #    于是「整批都 exploited」的前提永远不成立（实测 72 条候选中 50 条
        #    KEV + 22 条普通），上面 ① 判不出来；断层判据对 KEV 平坦分布
        #    （26.2/25.5/24.6，比值 1.03 < 2.0）也天然不成立 → 50 条真命中
        #    全灭，问答答"知识库没有匹配情报"，而页面"相关推荐"明明列着
        #    同样的 KEV 热点 —— 自相矛盾。
        #    修法：exploited=True 本身就是 CISA KEV 的**权威在野利用确认**，
        #    是与词面/断层启发式不同维度的可信信号（本闸门设计原则：
        #    "引擎的字段级过滤比我们的启发式更可信"），逐条放行；
        #    叠加 BM25_FLOOR 要求"引擎确实召回它"（防纯噪声混入）。
        #    零命中诚实化不受影响：无关查询（"红烧肉"）词面与 KEV 条目
        #    毫无交集，BM25 分 < 1.0，进不了候选池。
        if doc.get("exploited") and _bm25_score(doc) >= BM25_FLOOR:
            return True
        # ② 无精确过滤 → 必须"有真词命中 + 分数过断层线"才留
        cut = ctx.get("bm25_cut")
        if terms and cut and _bm25_score(doc) >= cut:
            return True
    return False


def gate(docs: List[Dict], query: str,
         keep_min: int = 0) -> Tuple[List[Dict], Dict]:
    """相关度闸门：过滤掉不相关文档，返回 (保留的文档, 统计信息)。

    keep_min: 至少保留多少条（0 = 一条不相关就全丢）。
      调用方若必须给"兜底展示"，可传较小的值（如 3），但**必须如实标注**；
      问答主链路的正确做法是传 0，让零命中原样暴露。

    统计信息 dict 供上层写进 `reasoning_chain` / 响应字段，用于如实说明
    「候选 N 条中 M 条被判不相关」—— 不静默丢弃。
    """
    terms = query_terms(query)
    strong = strong_terms(query)
    # ── 纯 BM25 路的判据（见 is_relevant 第 ⑤ 条）───────────────────────
    # 判据分两步（实测定标，见文件顶部注释）：
    #   ① 本批**整体满足结构化条件**（全是 exploited=true，即引擎已按 kev:yes
    #      精确过滤过）→ 整批都是真命中，全部放行。KEV 路分值天然平坦（24.6/23.3/
    #      22.8…），用"断层"判会误杀 —— 引擎的精确过滤比我们的启发式更可信。
    #   ② 否则退回**绝对下限**：只留分数 ≥ BM25_MIN 的，滤掉泛相关长尾
    #      （非 KEV 中文博客典型 8~20 分且 exploited 为空）。
    ctx = {"top_bm25": 0.0, "bm25_cut": None, "bm25_all_kev": False}
    # 只统计**正值** BM25 分：向量路独有条目没有 score（记 0），
    # 把它们混进排序会让 top2=0，从而把"首条断层"误判成成立。
    _scores = sorted((x for x in (_bm25_score(d) for d in (docs or [])) if x > 0),
                     reverse=True)
    if _scores:
        ctx["top_bm25"] = _scores[0]
    _all_bm25 = bool(docs) and all(_vector_score(d) is None for d in docs)
    # ★ 2026-10-26 修：断层线过去**只在纯 BM25 池**里算（_all_bm25 才进这个分支）。
    #   混合检索的池子是 BM25（有 score）+ 向量（有 vector_score）混排，
    #   _all_bm25=False → ctx["bm25_cut"] 恒为 None → is_relevant 第⑤条（纯 BM25 路）
    #   对 BM25 命中一律失效，只能靠 0.89/0.90 的余弦门槛；而口语化提问的余弦
    #   普遍停在 0.86~0.88（同域噪声区）→ **整池被清空**。
    #   实测：检索评测 40 题里 8 道"语义改写/中文源"题混合检索返回 0 条
    #   （@10 从 92.5% 掉到 80%），而同一问题走 /api/search 关键词路排第 1。
    #   修法：断层线与池子是否含向量无关，只要能算出显著断层就给出 cut。
    if not strong:
        _expl = [d for d in (docs or []) if d.get("exploited")]
        if _all_bm25 and _expl and len(_expl) == len(docs):
            # ① 引擎精确过滤过（整批都满足条件）→ 全留
            ctx["bm25_all_kev"] = True
            ctx["bm25_cut"] = 0.0
        elif _scores:
            # ② **无精确过滤** → 必须同时满足"首条断层"与"绝对下限"才留。
            #    为什么非要断层：实测不相关查询（"如何做红烧肉"）的分数分布是
            #    **平坦群** 8.4/8.3/8.3/8.3（1.05×）—— 词只在库里"普遍出现"，
            #    没有定向命中；而真命中一定有相对断层。只卡绝对下限会被
            #    平坦群整批绕过（8.4 > 8.0 全过）。
            top1 = _scores[0]
            top2 = _scores[1] if len(_scores) > 1 else 0.0
            if top1 >= BM25_MIN and (top2 <= 0 or top1 >= top2 * BM25_RATIO):
                ctx["bm25_cut"] = max(BM25_MIN, top2 * BM25_RATIO * 0.5)
            elif top1 >= BM25_STRONG:
                # 平坦分布 + 绝对分很高：正常的多词同主题命中，按首条取带宽
                # （不启用这条时，8 道口语化题会整池被清空 —— 见 2026-10-26 实测）
                ctx["bm25_cut"] = max(BM25_MIN, top1 * BM25_STRONG_RATIO)
    kept, dropped = [], 0
    for d in docs or []:
        if is_relevant(d, terms, strong, ctx):
            kept.append(d)
        else:
            dropped += 1
    if keep_min and len(kept) < keep_min:
        # 相关条目不足时按原顺序补足（调用方负责标注"低置信度"）
        kept_ids = {id(d) for d in kept}
        for d in docs or []:
            if len(kept) >= keep_min:
                break
            if id(d) not in kept_ids:
                d["_low_confidence"] = True   # 如实标注：这是兜底补的，不是真命中
                kept.append(d)
                kept_ids.add(id(d))
    return kept, {
        "candidates": len(docs or []),
        "relevant": len(kept),
        "dropped": dropped,
        "terms": terms,
        "strong_terms": strong,
        "vector_floor": VECTOR_FLOOR,
        "bm25_floor": BM25_FLOOR,
        "bm25_ratio": BM25_RATIO,
        "bm25_min": BM25_MIN,
        "top_bm25": ctx["top_bm25"],
        "bm25_cut": ctx["bm25_cut"],
        "bm25_all_kev": ctx["bm25_all_kev"],
    }


def no_hit_note(query: str, stats: Dict = None) -> str:
    """零命中时的标准文案（统一措辞，避免各模块各写一套）。

    ★ 第 4 轮实测修正（R4-A 配套）：必须区分"检索到候选但都不相关"与
      "一条候选都没检索到"—— 前者是判据否掉了，后者是**引擎根本没召回**。
      原文案对两者都说"候选 0 条…均不相关"，0 条却说"均"不相关是**逻辑不通**，
      而且掩盖了"零召回"这个更该被排查的信号（索引/分词/算子问题）。
    """
    terms = (stats or {}).get("terms") or query_terms(query)
    cand = (stats or {}).get("candidates")
    hint = ("、".join(terms[:3]) if terms else "问题关键词")
    if cand == 0:
        mid = (
            "本次检索**没有召回任何候选条目**（引擎侧零命中）——\n"
            "可能是检索词与库内表述差异过大，或分词/算子未能匹配。\n\n"
        )
    elif cand is None:
        mid = ""
    else:
        mid = (
            f"本次检索的候选 {cand} 条经相关度闸门（向量余弦 ≥ {VECTOR_FLOOR} / "
            f"关键词命中）判定**均不相关**，已如实剔除，不做兜底填充。\n\n"
        )
    return (
        "## 结论\n"
        f"**知识库中没有与该问题匹配的情报。**\n\n"
        + mid +
        f"- 已尝试的检索词：`{hint}`\n"
        "- **建议**：换个更具体的说法再问一次 —— 系统识别度最高的是\n"
        "  **产品/组件名**（如 `Ollama`、`vLLM`、`LangChain`）、"
        "**CVE 编号**（如 `CVE-2024-1234`）、**CWE 编号**（如 `CWE-78`）。\n"
        "- 也可以直接把检索式写成结构化算子："
        "`product:ollama kev:yes cvss>=9`。\n"
    )
