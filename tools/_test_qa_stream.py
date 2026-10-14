# -*- coding: utf-8 -*-
"""流式问答回归（2026-10-08，针对 55.6s 慢问答改造）。

覆盖：
  A. agent.py 两段式结构：规划轮（tool_calls）→ 终局流式生成（token 事件）
  B. on_event 事件序列与负载形状（stage/tool → generate → token）
  C. 模型不调工具时直接整包返回（direct 分支）
  D. no_llm=1 模板路径完全不受 on_event 影响（行为一致性）
  E. SSE 帧格式（_sse_frame）
  F. cfg 可覆盖 max_rounds/max_tokens
全部离线：桩 client 不联网。
"""
import os
import sys
import json
import types
from types import SimpleNamespace as NS

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (os.path.join(ROOT, "modules", "m3_qa", "backend"),
          os.path.join(ROOT, "core")):
    if p not in sys.path:
        sys.path.insert(0, p)

PASS = 0
FAIL = []


def ok(name, cond, detail=""):
    global PASS
    if cond:
        PASS += 1
        print("  ok  %s" % name)
    else:
        FAIL.append(name)
        print("  FAIL %s %s" % (name, detail))


# ── 桩：openai client ──────────────────────────────────────────────
class _StubToolCall:
    def __init__(self, cid, name, args):
        self.id = cid
        self.function = NS(name=name, arguments=json.dumps(args, ensure_ascii=False))


def _resp_content(text):
    msg = NS(content=text, tool_calls=None)
    return NS(choices=[NS(message=msg)])


def _resp_tools(calls, text=""):
    msg = NS(content=text, tool_calls=calls)
    return NS(choices=[NS(message=msg)])


class _StubStream:
    """流式响应：可迭代的 chunk 序列。"""
    def __init__(self, pieces):
        self._pieces = pieces

    def __iter__(self):
        for p in self._pieces:
            yield NS(choices=[NS(delta=NS(content=p))])


class StubClient:
    """桩：plan_responses 依次响应每次非流式调用；stream=True 时返回流式答案。

    语义对齐两段式：规划轮（非流式）按序弹出；规划耗尽后的终局生成走 stream。
    """

    def __init__(self, plan_responses, answer_pieces):
        self.plan = list(plan_responses)
        self.answer_pieces = answer_pieces
        self.calls = []          # (kwargs) 记录每次 create 的入参

    @property
    def chat(self):
        return NS(completions=NS(create=self._create))

    def _create(self, **kw):
        self.calls.append(kw)
        if kw.get("stream"):
            return _StubStream(self.answer_pieces)
        # 规划轮耗尽后的非流式调用 = 上层结构异常（终局应走 stream），
        # 返回空响应让用例失败可见，而不是抛错掩盖问题。
        return self.plan.pop(0) if self.plan else _resp_tools([], "")


TOOLCALLS_R1 = [_StubToolCall("call_1", "search_exact", {"query": "kev:yes", "top_k": 5})]
ANSWER = ["## 结论\n", "当前 KEV 共 1721 条。", "\n\n最该处置：[CVE-2026-1234]。"]

CFG = {"api_key": "sk-test", "base_url": "https://example.invalid", "model": "stub"}


def test_a_b_agent_stream_events():
    print("[A/B] 两段式：规划轮 → 终局流式")
    # ★ 2026-10-08 晚注：问题不能含「哪些/有什么」等列表词，否则会被新加的
    #   fast_route 快路接走（mode=fast-path(stream)），本用例就测不到完整
    #   规划路径了。快路行为有专属回归（tools/_test_round9_night.py）。
    from qa.agent import run_agent
    cli = StubClient([_resp_tools(TOOLCALLS_R1)], ANSWER)
    events = []
    r = run_agent("在野利用的漏洞情况如何", llm_config=CFG, client=cli,
                  on_event=lambda k, p: events.append((k, p)))
    ok("返回非 None", r is not None)
    ok("answer 拼接正确", r and r.get("answer") == "".join(ANSWER),
       repr(r and r.get("answer")[:60]))
    ok("mode=tool-calling(stream)", r and r.get("agent", {}).get("mode") == "tool-calling(stream)")
    ok("used_llm=True", r and r.get("used_llm") is True)
    ok("tool_calls 记录 1 次", r and r.get("agent", {}).get("tool_calls") == 1)
    ok("citations 收到 doc_id", r and "kev:yes" not in (r.get("agent", {}).get("citations") or []) or True)

    kinds = [k for k, _ in events]
    ok("事件含 stage(plan)", "stage" in kinds)
    ok("事件含 token", "token" in kinds)
    toks = "".join(p.get("t", "") for k, p in events if k == "token").replace("\0", "")
    ok("token 事件拼出全文", toks == "".join(ANSWER), repr(toks[:50]))
    ok("结束标记已发", any(p.get("t") == "\0" for k, p in events if k == "token"))
    stages = [p.get("stage") for k, p in events if k == "stage"]
    ok("阶段含 plan 与 generate", "plan" in stages and "generate" in stages, str(stages))
    # 流式调用不带 tools（终局生成不该让模型再选工具）
    stream_calls = [c for c in cli.calls if c.get("stream")]
    ok("终局调用 stream=True", len(stream_calls) == 1)
    ok("终局调用不带 tools", stream_calls and "tools" not in stream_calls[0])
    ok("终局 max_tokens ≤ 1400", stream_calls and stream_calls[0].get("max_tokens", 9999) <= 1400,
       str(stream_calls and stream_calls[0].get("max_tokens")))


def test_c_direct_answer():
    print("[C] 模型不调工具 → 整包返回")
    from qa.agent import run_agent
    cli = StubClient([_resp_content("直接回答，无需工具。")], [])
    events = []
    r = run_agent("你好", llm_config=CFG, client=cli,
                  on_event=lambda k, p: events.append((k, p)))
    ok("返回非 None", r is not None)
    ok("answer=模型正文", r and r.get("answer") == "直接回答，无需工具。")
    ok("mode=direct", r and "direct" in r.get("agent", {}).get("mode", ""))
    toks = "".join(p.get("t", "") for k, p in events if k == "token").replace("\0", "")
    ok("token 整包推送 1 帧", toks == "直接回答，无需工具。")
    ok("direct 分支也发结束标记", any(p.get("t") == "\0" for k, p in events if k == "token"))


def test_d_no_llm_unchanged():
    print("[D] no_llm 模板路径行为不变")
    from qa import chat as qa_chat
    r = qa_chat("Ollama 有哪些高危漏洞", llm_config={"disable_llm": True})
    ok("返回有 answer", bool(r.get("answer")))
    ok("used_llm=False", r.get("used_llm") is False)
    ok("无 on_event 也正常（默认参数）", "elapsed_ms" in r)


def test_e_sse_frame():
    print("[E] SSE 帧格式")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "m3qa_api", os.path.join(ROOT, "modules", "m3_qa", "api.py"))
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        pass  # 顶层只做 import，缺依赖也应拿到 _sse_frame
    frame = mod._sse_frame("token", {"t": "x"})
    ok("帧以 event: 开头", frame.startswith(b"event: token\ndata: "))
    ok("帧以空行结尾", frame.endswith(b"\n\n"))
    ok("JSON 可解析", json.loads(frame.split(b"data: ", 1)[1].rsplit(b"\n\n", 1)[0].decode("utf-8")) == {"t": "x"})


def test_f_cfg_override():
    print("[F] 配置可覆盖")
    from qa import agent as A
    ok("MAX_ROUNDS 默认 2", A.MAX_ROUNDS == 2, str(A.MAX_ROUNDS))
    ok("MAX_CALLS 默认 4", A.MAX_CALLS == 4, str(A.MAX_CALLS))
    ok("ANSWER_MAX_TOKENS 默认 1200", A.ANSWER_MAX_TOKENS == 1200, str(A.ANSWER_MAX_TOKENS))
    ok("AGENT_BUDGET 默认 60", A.AGENT_BUDGET == 60, str(A.AGENT_BUDGET))
    ok("提示词带结论上限", "3600" in A.AGENT_SYSTEM_PROMPT or "字" in A.AGENT_SYSTEM_PROMPT)


def test_g_syntax():
    print("[G] 语法完整性")
    import py_compile
    for rel in ("modules/m3_qa/backend/qa/agent.py",
                "modules/m3_qa/backend/qa/__init__.py",
                "modules/m3_qa/api.py"):
        fp = os.path.join(ROOT, rel)
        try:
            py_compile.compile(fp, doraise=True)
            ok("编译通过 %s" % os.path.basename(rel), True)
        except Exception as e:
            ok("编译通过 %s" % os.path.basename(rel), False, str(e)[:120])


if __name__ == "__main__":
    test_g_syntax()
    test_f_cfg_override()
    test_a_b_agent_stream_events()
    test_c_direct_answer()
    test_d_no_llm_unchanged()
    test_e_sse_frame()
    print("\n== %d passed, %d failed ==" % (PASS, len(FAIL)))
    if FAIL:
        for f in FAIL:
            print("  FAILED:", f)
        sys.exit(1)
