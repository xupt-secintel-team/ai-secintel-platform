# -*- coding: utf-8 -*-
"""qa模块：情报问答（RAG）"""
import re
import time

from qa.multi_hop import multi_hop_search
from qa.generator import generate
from qa.config import QA_BUDGET, LLM_TIMEOUT

# 输入长度上限：超长问题几乎必是误粘贴/攻击载荷，检索也捞不出东西。
# 取 1000 字 —— 正常安全提问（含 CVE 编号、产品名、几个条件）远低于此。
MAX_QUESTION_CHARS = 1000

# "有意义的字符"：中文、拉丁字母、数字。纯符号/emoji/空白组成的提问不是问题。
_MEANINGFUL_RE = re.compile(r"[\u4e00-\u9fffA-Za-z0-9]")


def _precheck(question: str):
    """输入合理性前置校验。返回 None 表示通过；否则返回**可直接作为结果**的 dict。

    为什么要在检索前做（第 2 轮实测）：
      原先「???」「   」「a」这类输入会一路走完多跳检索（含向量编码 + 引擎 HTTP 调用），
      最后返回 200 + 一堆无关条目；而「'; DROP TABLE docs;--」这种载荷也会被当成
      查询词去检索。既浪费资源，也误导用户以为"系统听懂了"。
      （注：本模块**没有任何 SQL 执行路径**，注入载荷不会被执行；这里纯粹是
        "别把非问题当问题检索"的体验与资源问题。）
    """
    q = question or ""
    stripped = q.strip()
    if not _MEANINGFUL_RE.search(stripped):
        note = ("## 结论\n"
                "**这看起来不是一个可以用情报库回答的问题。**\n\n"
                "问题里没有可检索的内容（只含符号、表情或空白）。\n"
                "请描述你关心的**产品/组件**、**漏洞编号**或**弱点类型**，例如：\n"
                "- `Ollama 有哪些高危漏洞`\n"
                "- `CVE-2024-1234 的修复建议`\n"
                "- `CWE-78 相关的在野利用漏洞`\n")
        return {"answer": note, "conclusion": note, "sources": [], "evidence": [],
                "used_llm": False, "empty_reason": "invalid_input"}
    if len(stripped) > MAX_QUESTION_CHARS:
        note = ("## 结论\n"
                f"**问题过长（{len(stripped)} 字，上限 {MAX_QUESTION_CHARS} 字）。**\n\n"
                "请把它压缩成一句可检索的问题 —— 保留**产品名/组件名**、"
                "**CVE/CWE 编号**与关键条件即可：\n"
                "- 把整段粘贴的公告正文，改成 `产品名 + 关注点`（如 `vLLM 的 RCE 修复建议`）\n"
                "- 若要查具体漏洞，直接用编号提问（如 `CVE-2025-32434`）\n")
        return {"answer": note, "conclusion": note, "sources": [], "evidence": [],
                "used_llm": False, "empty_reason": "too_long"}
    return None


def _chain_from_agent(agent_result: dict, ms: int) -> dict:
    """把智能体的工具调用留痕转成统一格式的推理链。

    前端只认一种链结构（hop / query / basis / hits / ms），
    所以 Agent 路径在这里对齐到 multi_hop 的形状，接口契约才不会分叉。
    """
    agent = (agent_result or {}).get("agent") or {}
    trace = agent.get("trace") or []
    hops = []
    for i, step in enumerate(trace):
        args = step.get("args") or {}
        arg_s = "、".join("%s=%s" % (k, str(v)[:24]) for k, v in list(args.items())[:3])
        hops.append({
            "hop": i + 1,
            "query": "%s(%s)" % (step.get("tool") or "?", arg_s or "-"),
            "basis": "模型自主选择工具（function calling）",
            "hits": step.get("n") or 0,
            "new_docs": step.get("n") or 0,
            "ms": step.get("ms") or 0,
            "ok": bool(step.get("ok")),
        })
    return {
        "strategy": "tool-calling-agent",
        "hop_count": len(hops),
        "hops": hops,
        "rounds": agent.get("rounds") or 0,
        "total_ms": ms,
    }


def chat(question: str, history: list = None, llm_config: dict = None,
         on_event=None) -> dict:
    """
    问答主入口
    - question: 用户问题
    - history: 历史对话
    - llm_config: 用户自己传的LLM配置（前端从设置页收集），不传用默认
    - on_event(kind, payload): 流式进度回调（SSE 用）。
      kind ∈ stage(检索/工具/生成阶段) / token(答案逐字片段)。
      None 时行为与旧版完全一致（评测脚本/模板路径零影响）。

    两条路径（**上层无需感知，降级全自动**）：
      ① 智能体路径：有 LLM Key 且工具能调通时，由模型**自主**决定调什么工具、调几轮
         （`qa/agent.py`，OpenAI 兼容 function calling），答案里带 `agent.trace` 全程留痕；
      ② 传统路径：无 Key / 工具全失败 / LLM 异常 → 走 multi_hop 迭代多跳检索 + generator。

    两条路径的答案都会经 `qa/report.py::finalize()` 收口，产出统一契约：
      conclusion     —— 直接可用的结论（上限 3600 字，超限截断并标注）
      evidence       —— 原始详细资料清单（每条可点开全文详情）
      reasoning_chain—— **推理链**（每跳的检索式 + 派生依据 + 命中数 + 耗时），可解释
      elapsed_ms     —— 端到端耗时（回答"响应是否可控"）
      answer / sources —— 旧字段保留，评测脚本与既有前端不受影响
    """
    t0 = time.time()
    deadline = QA_BUDGET

    def _emit(kind, payload):
        if on_event:
            try:
                on_event(kind, payload)
            except Exception:  # noqa: BLE001 —— 进度推送失败绝不能打断作答
                pass

    # 0'. 输入合理性校验（第 2 轮实测补）：
    #     「超长问题/纯符号/纯空白/单字符」原先一律返回 200 + 完整答案 ——
    #     纯符号会走完整个多跳检索，最后拿回一堆无关条目（"命中 N 条"），
    #     既浪费一次检索，也让用户以为"系统听懂了"。
    #     这里在**检索之前**就判掉，给出明确、可操作的反馈。
    guard = _precheck(question)
    if guard:
        guard["reasoning_chain"] = {"strategy": "input-guard", "hop_count": 0, "hops": []}
        guard["elapsed_ms"] = int((time.time() - t0) * 1000)
        return guard

    # 0. 多轮指代消解（v2.2）："第一个漏洞的CWE是什么"这类回指，
    #    先把上一轮答案里的第 N 个 CVE 显式注入本轮问题，再走检索/智能体
    resolved_cve = None
    history_note = ""
    if history:
        # ★ 第 7 轮实测补（R7-A'）：history 契约是 [{role, content}]（role ∈ user/assistant）。
        #   实测传错形状（如 [{q,a}] 或垃圾对象）时**不报错、静默丢失上下文** ——
        #   前端若哪天改错，用户只会觉得"系统变笨了"，没有任何线索。
        #   这里做**非破坏性**自检：格式明显不对时在结果里附一条提示，
        #   但**不改 HTTP 状态、不改变回答**（第三方调用者零负担）。
        try:
            _roles = [str(h.get("role") or "") for h in history if isinstance(h, dict)]
            _has_role = any(x in ("user", "assistant") for x in _roles)
            if not _has_role:
                history_note = ("history 格式可能不对：期望 [{role:'user'|'assistant', content}]，"
                                "本轮未能接上多轮上下文。")
        except Exception:  # noqa: BLE001
            pass
        try:
            from qa.deep_answer import resolve_reference
            question, resolved_cve = resolve_reference(question, history)
        except Exception as e:  # noqa: BLE001
            print(f"[qa.chat] 指代消解异常（按原问题继续）：{e}")

    # 0b. 改写式提问 → 产品名锚定（第 3 轮实测补）：
    #     实测"本地跑开源大模型的那个工具有文件读取问题"会被语义检索带到
    #     dspy/llama-hub 等无关仓库（错误结果余弦 0.907 与正确描述句 0.906 在噪声内，
    #     阈值救不了）—— 根因是该问句**没有锚点**。
    #     这里先把描述锚定成真实产品名（Ollama/vLLM/LangChain…）再检索，
    #     让关键词路与语义路都拿到锚。提问里本来就写了产品名时不介入。
    anchor_note = ""
    try:
        from qa.query_anchor import expand_query, anchor_note as _anote
        _expanded = expand_query(question)
        if _expanded != question:
            anchor_note = _anote(question)
            question = _expanded
    except Exception as e:  # noqa: BLE001
        print(f"[qa.chat] 查询锚定异常（按原问题继续）：{e}")

    # 1. 先试智能体工具编排（返回 None 就代表这次不走，继续下面的传统路径）
    try:
        from qa.agent import run_agent
        from qa.report import finalize
        agent_result = run_agent(question, history=history, llm_config=llm_config,
                                 on_event=_emit)
        if agent_result:
            _emit("stage", {"stage": "finalize", "msg": "整理原始资料与推理链…"})
            out = finalize(question, agent_result)
            out["reasoning_chain"] = _chain_from_agent(agent_result,
                                                      int((time.time() - t0) * 1000))
            out["elapsed_ms"] = int((time.time() - t0) * 1000)
            if resolved_cve:
                out["resolved_ref"] = resolved_cve
            if anchor_note:
                out["anchor_note"] = anchor_note
            if history_note:
                out["history_note"] = history_note
            return out
    except Exception as e:  # noqa: BLE001
        print(f"[qa.chat] 智能体层异常，退回传统链路：{e}")

    # 2. 迭代多跳检索（有 LLM 配置时由大模型拆解子查询，无 LLM 走规则拆解；
    #    第2跳起检索式由上一跳命中的实体派生 —— 见 multi_hop._iterative_expand）
    docs, chain = multi_hop_search(question, llm_config, with_chain=True)

    # 2a. 泛指修复意图兜底（2026-10-08 实测补）：
    #     实测「这些漏洞应该怎么修复？给出修复建议。」→ 规则式改写把询问角度词
    #     剔净后只剩零信息残渣 `这些漏洞应 给出` → 命中全被相关度闸门拒掉 →
    #     用户拿到「知识库中没有与该问题匹配的情报」，而 /api/remediation
    #     能力其实完整可用（用户点名的缺口）。
    #     判据（三者同时成立才兜底，不影响正常检索）：
    #       ① 有修复意图（_FIX_Q_RE）② 句中没有 CVE 编号（无实体，是代词指代）
    #       ③ 常规检索零命中
    #     兜底动作：取知识库 cvss>=9 的高危情报作证据池，交给 fix_section 渲染
    #     可操作处置（补丁链接 / 受影响区间 / 厂商公告），并如实标注来源。
    if not docs:
        try:
            from qa.deep_answer import _FIX_Q_RE, CVE_RE, latest_high_risk_docs
            if _FIX_Q_RE.search(question or "") and not CVE_RE.search(question or ""):
                _fb = latest_high_risk_docs(5)
                if _fb:
                    docs = _fb
                    chain["query_fallback"] = (
                        "泛指修复意图（『这些漏洞』无实体）→ 取知识库 cvss>=9 "
                        "高危情报作证据池；如需针对特定 CVE，请带上编号再问")
        except Exception as e:  # noqa: BLE001
            print(f"[qa.chat] 修复意图兜底异常（按原结果继续）：{e}")

    # 2b. 端到端预算：检索已吃掉大半预算时，生成阶段不再调 LLM（必然超预算），
    #     直接用证据模板出结论 —— 宁可答案朴素，也不能让用户一直等。
    spent = time.time() - t0
    gen_cfg = llm_config
    budget_skip = False
    if (deadline - spent) < min(8.0, LLM_TIMEOUT):
        gen_cfg = dict(llm_config or {})
        gen_cfg["disable_llm"] = True
        budget_skip = True
    chain["budget_ms"] = int(deadline * 1000)
    chain["spent_ms"] = int(spent * 1000)

    # 3. 生成答案
    result = generate(question, docs, history, gen_cfg)
    # generation 如实反映实际走的哪条路（此前固定写 "llm"，与 used_llm 矛盾）
    if budget_skip:
        chain["generation"] = "template(预算不足)"
    elif result.get("used_llm"):
        chain["generation"] = "llm(%s)" % (result.get("model") or "-")
    else:
        chain["generation"] = "template(%s)" % (
            "显式关闭" if result.get("llm_disabled") else "未配置Key或调用失败")
    if resolved_cve:
        result["resolved_ref"] = resolved_cve  # 前端/评测可见：本轮指代被解析成了谁
    result["reasoning_chain"] = chain

    # 4. 收口：补齐「结论（≤3600字）+ 原始详细资料」，证据池作为兜底来源
    try:
        from qa.report import finalize
        result = finalize(question, result, docs=docs)
    except Exception as e:  # noqa: BLE001
        print(f"[qa.chat] 结论/资料结构化失败（不影响答案文本）：{e}")

    result["reasoning_chain"] = chain
    if anchor_note:
        result["anchor_note"] = anchor_note  # 前端可见：本轮提问被锚定成了什么
    if history_note:
        result["history_note"] = history_note  # 前端可见：多轮契约可能有误
    result["elapsed_ms"] = int((time.time() - t0) * 1000)
    return result
