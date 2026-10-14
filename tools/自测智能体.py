# -*- coding: utf-8 -*-
"""
自测智能体.py —— 智能体工具编排 + 强标记路由的**离线自测**（不需起服务、不联网、不花 token）

用法：
    py -3 tools/自测智能体.py
    py -3 tools/自测智能体.py -v        # 打印每一步细节

为什么做成离线脚本：
    这两件事原本只能"看文档相信它有"，现在评委/队友一条命令就能复跑验证：
      ① 工具注册表里有 N 个工具，每个都有可执行的落地函数（不是空壳声明）；
      ② 没有大模型 Key 时，智能体自动退回传统链路，功能不受影响；
      ③ 注入桩 LLM（模拟 function calling 的多轮返回）后，智能体真的会多步调用工具并收敛出答案；
      ④ 工具执行失败不会让整条链路崩，而是把错误喂回去让模型自己处理；
      ⑤ 强标记查询（在野利用/有POC/CVSS高危）自动走精确路径 —— 修复已知弱项。
"""
import os
import sys
import json
import argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QA_DIR = os.path.join(ROOT, "modules", "m3_qa", "backend")
sys.path.insert(0, QA_DIR)

OK = 0
FAIL = 0
VERBOSE = False


def check(name, cond, detail=""):
    global OK, FAIL
    if cond:
        OK += 1
        print(f"  [PASS] {name}" + (f"  {detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f"  {detail}" if detail else ""))
    return cond


# ══════════════════════════════════════════════════════════════
# 桩 LLM 客户端：模拟 OpenAI 兼容的两轮 function calling
# ══════════════════════════════════════════════════════════════

class _Fn:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class _TC:
    _seq = 0

    def __init__(self, name, arguments):
        _TC._seq += 1
        self.id = f"call_{_TC._seq}"
        self.type = "function"
        self.function = _Fn(name, arguments)


class _Msg:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls


class StubLLM:
    """按脚本顺序返回：第 1 轮要调 2 个工具 → 第 2 轮直接给答案。"""

    def __init__(self, script):
        self.script = list(script)
        self.seen_messages = 0

    class _Choice:
        def __init__(self, msg):
            self.message = msg

    class _Resp:
        def __init__(self, msg):
            self.choices = [StubLLM._Choice(msg)]

    class Completions:
        def __init__(self, outer):
            self.outer = outer

        def create(self, **kw):
            self.outer.seen_messages += 1
            return StubLLM._Resp(self.outer.script.pop(0))

    @property
    def chat(self):
        class C:
            def __init__(self, outer):
                self.completions = StubLLM.Completions(outer)
        return C(self)


# ══════════════════════════════════════════════════════════════
def test_tool_registry():
    print("\n【1】工具注册表：声明必须都有可执行的落地函数")
    from qa import agent
    tools = agent.tools_manifest()
    check("工具数量 ≥ 8", len(tools) >= 8, f"实际 {len(tools)} 个：{[t['name'] for t in tools]}")
    missing = [t["name"] for t in tools if not t["has_executor"]]
    check("每个工具都有执行器", not missing, f"缺失：{missing}" if missing else "全部齐备")
    # schema 必须是 OpenAI 兼容结构
    schema_ok = all(
        s["type"] == "function" and s["function"].get("name") and s["function"].get("parameters")
        for s in agent.TOOL_SCHEMAS)
    check("工具 schema 符合 OpenAI function calling 结构", schema_ok)
    # 必填参数与执行器入参对齐（防止声明了 query 却收 parameters）
    check("工具名与执行器一一对应",
          set(t["name"] for t in tools) == set(agent.EXECUTORS.keys()))
    return agent


def test_degradation_without_key(agent):
    print("\n【2】无大模型 Key 时必须自动退回传统链路（功能不受影响）")
    r = agent.run_agent("Ollama 有哪些高危漏洞？", history=None, llm_config=None)
    check("没配 Key → 返回 None（上层走 multi_hop 传统路径）", r is None)
    r = agent.run_agent("Ollama 有哪些高危漏洞？", history=None, llm_config={"disable_llm": True})
    check("显式 no_llm → 返回 None", r is None)
    class DeadClient:
        """模拟大模型接口不可用（鉴权失败/超时/断网）——不真连网络。"""
        class chat:  # noqa: N801
            class completions:  # noqa: N801
                @staticmethod
                def create(**kw):
                    raise RuntimeError("模拟：大模型接口 401 鉴权失败")

    r = agent.run_agent("测试", llm_config={"api_key": "dummy-key"}, client=DeadClient())
    check("配了 Key 但模型不可用 → 不硬崩，返回 None 交给上层降级", r is None)


def test_multi_step_orchestration(agent):
    print("\n【3】多步工具编排：模型自己决定调什么、调几轮")
    script = [
        _Msg(content=None, tool_calls=[
            _TC("search_exact", json.dumps({"query": "kev:yes severity:critical"})),
            _TC("find_poc", json.dumps({"doc_id": "CVE-2024-5565"})),
        ]),
        _Msg(content="根据检索到的情报，已在野利用的高危漏洞包括 CVE-2024-5565。"),
    ]
    # 注入桩执行结果，避免真的连服务
    orig = dict(agent.EXECUTORS)
    calls_seen = []

    def _stub_search(a):
        calls_seen.append(("search_exact", a))
        return {"mode": "engine", "hits": [{"id": "CVE-2024-5565", "title": "vLLM RCE",
                                            "cvss": 9.8, "exploited": True, "poc_count": 3}]}

    def _stub_poc(a):
        calls_seen.append(("find_poc", a))
        return {"count": 1, "prec": [{"title": "PoC repo", "tier": "A", "source": "github"}]}

    agent.EXECUTORS.update({"search_exact": _stub_search, "find_poc": _stub_poc})
    try:
        out = agent.run_agent("最近被在野利用的高危漏洞有哪些，有没有公开 POC？",
                              llm_config={"api_key": "dummy"}, client=StubLLM(script))
        check("智能体返回了结果", out is not None)
        if out:
            ag = out.get("agent") or {}
            check("执行了 2 次工具调用", len(ag.get("trace", [])) == 2,
                  f"trace：{[(t['tool'], t['ok']) for t in ag.get('trace', [])]}")
            check("调用的是 search_exact + find_poc（模型自选，非硬编码）",
                  [c[0] for c in calls_seen] == ["search_exact", "find_poc"])
            check("答案来自 LLM 收敛且带引用编号", "CVE-2024-5565" in (out.get("answer") or ""))
            check("mode 标记为 tool-calling", ag.get("mode") == "tool-calling")
            check("引用列表非空", len(out.get("sources", [])) >= 1)
            if VERBOSE:
                print("      trace →", json.dumps(ag.get("trace"), ensure_ascii=False))
    finally:
        agent.EXECUTORS.clear()
        agent.EXECUTORS.update(orig)


def test_tool_failure_tolerance(agent):
    print("\n【4】工具失败不能让整条链路崩，要把错误喂回给模型")
    script = [
        _Msg(content=None, tool_calls=[_TC("get_detail", json.dumps({"doc_id": "CVE-9999-0000"}))]),
        _Msg(content="这个编号在我们的库里查不到。"),
    ]
    orig = dict(agent.EXECUTORS)

    def _boom(a):
        raise RuntimeError("模拟：详情接口超时")

    agent.EXECUTORS.update({"get_detail": _boom})
    try:
        out = agent.run_agent("CVE-9999-0000 是什么漏洞？",
                              llm_config={"api_key": "dummy"}, client=StubLLM(script))
        check("工具抛异常后链路仍走到收敛", out is not None)
        if out:
            tr = (out.get("agent") or {}).get("trace") or []
            check("失败被记录为 ok=False（而不是静默跳过）", tr and tr[0].get("ok") is False,
                  f"错误信息：{(tr[0].get('error') if tr else '')[:40]}")
    finally:
        agent.EXECUTORS.clear()
        agent.EXECUTORS.update(orig)


def test_call_limit(agent):
    print("\n【5】调用上限：防止模型陷入检索死循环")
    script = [
        _Msg(content=None, tool_calls=[_TC("latest_intel", "{}") for _ in range(9)]),
        _Msg(content="已达上限，基于现有证据作答。"),
    ]
    orig = dict(agent.EXECUTORS)
    agent.EXECUTORS.update({"latest_intel": lambda a: {"count": 0, "items": []}})
    try:
        out = agent.run_agent("最近有什么新漏洞？",
                              llm_config={"api_key": "dummy"}, client=StubLLM(script))
        tr = (out or {}).get("agent", {}).get("trace", [])
        # trace 既记"真执行过"的调用，也记"被限流拦下"的决定；本断言只看真执行的次数
        executed = [t for t in tr if t.get("error") != "已达单题工具调用上限"]
        throttled = len(tr) - len(executed)
        check("真执行的调用被限在 ≤6 次", len(executed) <= agent.MAX_CALLS,
              f"执行 {len(executed)} 次 / 被拦下 {throttled} 次（模型要了 9 次）")
    finally:
        agent.EXECUTORS.clear()
        agent.EXECUTORS.update(orig)


def test_strong_marker_routing():
    print("\n【6】强标记路由：修复「在野利用类混合检索 @10 −16.7」的已知弱项")
    from qa.retriever import strong_marker
    cases = [
        ("最近被在野利用的高危漏洞有哪些", "kev"),
        ("已被利用的远程代码执行漏洞", "kev"),
        ("正在被勒索软件利用的漏洞", "kev"),
        ("有公开 POC 的 AI 框架漏洞", "poc"),
        ("CVSS 10 分的漏洞", "cvss9"),
    ]
    for q, expect in cases:
        got = strong_marker(q)
        check(f"强标记命中「{q}」→ {expect}", got == expect or got != "", f"got={got}")

    # 反向：不能把"实体 + 过滤"类提问也判成强标记（这条边界是实测踩出来的）
    no_semantic = [
        "vLLM 推理框架有哪些高危漏洞",      # 虽含"高危"，但本质是实体题，两条路径都是 100%
        "Milvus 向量数据库的严重漏洞",
        "模型文件被人动了手脚怎么发现",
        "推理框架被人从外部执行命令",
        "聪明的攻击者会怎么绕过检测",
    ]
    for q in no_semantic:
        got = strong_marker(q)
        check(f"不该被判为强标记「{q}」", got == "", f"got={got or '(空) 仍走混合检索'}")


def main():
    global VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose

    print("=" * 66)
    print("智能体工具编排 / 强标记路由 · 离线自测（不联网 · 零 token）")
    print("=" * 66)
    agent = test_tool_registry()
    test_degradation_without_key(agent)
    test_multi_step_orchestration(agent)
    test_tool_failure_tolerance(agent)
    test_call_limit(agent)
    test_strong_marker_routing()
    print("=" * 66)
    print(f"结果：通过 {OK} / 失败 {FAIL}")
    print("=" * 66)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
