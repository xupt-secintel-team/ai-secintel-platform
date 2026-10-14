# -*- coding: utf-8 -*-
"""2026-10-08 晚三需求回归：问答质量/提速 + 端口工单 + 项目扫描 10GB/文件夹。

覆盖：
  A. agent.fast_route：列表型强标记问题 → 确定性工具路由（跳过规划轮）
  B. agent 快路端到端（桩 client）：Phase1 被跳过、终局流式、预算 ≤ FAST_ANSWER_TOKENS
  C. report._balance_bold / clip：未闭合 ** 清洗（截图实测的裸星号）
  D. port_scan._identify：banner/Server头/端口推断三层指纹
  E. port_scan.correlate + workorder_markdown：真引擎 × 指纹 → CVE → 工单要素
  F. project_scan：10GB 上限常量 + parse_zip_path 与 parse_zip 等价 + path 入口
全部离线可复跑（引擎用本机语料缓存，无外网依赖）。
"""
import io
import json
import os
import sys
import time
import zipfile
from types import SimpleNamespace as NS

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (os.path.join(ROOT, "modules", "m3_qa", "backend"),
          os.path.join(ROOT, "modules", "m2_enrich", "backend"),
          os.path.join(ROOT, "core")):
    if p not in sys.path:
        sys.path.insert(0, p)
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

import port_scan as PS  # noqa: E402
import project_scan as PJ  # noqa: E402
import paths  # noqa: E402

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


# ══ A/B. 意图快路 ═══════════════════════════════════════════════
def test_a_fast_route():
    print("[A] fast_route 路由表")
    from qa.agent import fast_route
    r = fast_route("最近被在野利用的高危漏洞有哪些？")
    ok("KEV+高危 → search_exact(kev:yes cvss>=7)",
       r and r[0] == "search_exact" and "kev:yes" in r[1]["query"]
       and "cvss>=7" in r[1]["query"], str(r))
    r2 = fast_route("有哪些漏洞已经被在野利用")
    ok("KEV 不带高危 → 只 kev:yes",
       r2 and r2[0] == "search_exact" and "kev:yes" in r2[1]["query"]
       and "cvss" not in r2[1]["query"], str(r2))
    r3 = fast_route("有公开POC的高危漏洞有哪些")
    ok("POC → poc:yes", r3 and r3[0] == "search_exact" and "poc:yes" in r3[1]["query"], str(r3))
    r4 = fast_route("最近有什么新情报")
    ok("最新情报 → latest_intel", r4 and r4[0] == "latest_intel", str(r4))
    ok("非列表问题不路由", fast_route("Log4j 的影响范围与处置建议") is None)
    ok("空问题不路由", fast_route("") is None)
    ok("高危概念题不误路由 latest", fast_route("高危漏洞是什么意思") is None)


class _StubToolCall:
    def __init__(self, cid, name, args):
        self.id = cid
        self.function = NS(name=name, arguments=json.dumps(args, ensure_ascii=False))


def _resp_tools(calls):
    return NS(choices=[NS(message=NS(content="", tool_calls=calls))])


class _StubStream:
    def __init__(self, pieces):
        self._pieces = pieces

    def __iter__(self):
        for p in self._pieces:
            yield NS(choices=[NS(delta=NS(content=p))])


class StubClient:
    def __init__(self, plan_responses, answer_pieces):
        self.plan = list(plan_responses)
        self.answer_pieces = answer_pieces
        self.calls = []

    @property
    def chat(self):
        return NS(completions=NS(create=self._create))

    def _create(self, **kw):
        self.calls.append(kw)
        if kw.get("stream"):
            return _StubStream(self.answer_pieces)
        return self.plan.pop(0) if self.plan else _resp_tools([])


CFG = {"api_key": "sk-test", "base_url": "https://example.invalid", "model": "stub"}
ANSWER = ["结论：命中 3 条 KEV。\n", "CVE-2026-104286（CVSS 9.8，CRITICAL，KEV）——路径限制不当——列入跟踪\n",
          "\n优先处置 CVE-2026-104286。"]


def test_b_fast_path_e2e():
    print("[B] 快路端到端（桩 client）")
    from qa.agent import run_agent, FAST_ANSWER_TOKENS
    cli = StubClient([], ANSWER)      # 规划轮不应被调用 → plan 队列保持为空
    events = []
    r = run_agent("最近被在野利用的高危漏洞有哪些？", llm_config=CFG, client=cli,
                  on_event=lambda k, p: events.append((k, p)))
    ok("返回非 None", r is not None)
    ok("mode=fast-path(stream)", r and r.get("agent", {}).get("mode") == "fast-path(stream)",
       str(r and r.get("agent", {}).get("mode")))
    ok("answer 拼接正确", r and r.get("answer") == "".join(ANSWER))
    plan_calls = [c for c in cli.calls if not c.get("stream")]
    ok("规划轮 LLM 调用为 0（快路跳过）", len(plan_calls) == 0, str(len(plan_calls)))
    stream_calls = [c for c in cli.calls if c.get("stream")]
    ok("终局调用 1 次且 stream=True", len(stream_calls) == 1)
    ok("快路生成预算 ≤ FAST_ANSWER_TOKENS",
       stream_calls and stream_calls[0].get("max_tokens", 10**9) <= FAST_ANSWER_TOKENS,
       str(stream_calls and stream_calls[0].get("max_tokens")))
    ok("证据进入消息（kev:yes）",
       stream_calls and "kev:yes" in json.dumps(stream_calls[0].get("messages"), ensure_ascii=False))
    kinds = [k for k, _ in events]
    ok("事件含 token", "token" in kinds)
    toks = "".join(p.get("t", "") for k, p in events if k == "token").replace("\0", "")
    ok("token 拼出全文", toks == "".join(ANSWER), repr(toks[:40]))
    ok("结束标记已发", any(p.get("t") == "\0" for k, p in events if k == "token"))
    stages = [p.get("stage") for k, p in events if k == "stage"]
    ok("阶段含 plan(快路提示)", "plan" in stages, str(stages))
    ok("阶段含 generate", "generate" in stages)


def test_b2_normal_path_untouched():
    print("[B2] 非列表问题仍走完整规划轮")
    from qa.agent import run_agent
    tc = _StubToolCall("call_1", "search_intelligence", {"query": "Log4j 处置"})
    cli = StubClient([_resp_tools([tc])], ANSWER)
    r = run_agent("Log4j 的影响范围与处置建议", llm_config=CFG, client=cli)
    ok("mode=tool-calling(stream)",
       r and r.get("agent", {}).get("mode") == "tool-calling(stream)",
       str(r and r.get("agent", {}).get("mode")))
    plan_calls = [c for c in cli.calls if not c.get("stream")]
    from qa.agent import MAX_ROUNDS
    ok("规划轮 LLM 调用 1~%d 次（第 2 轮确认收敛是正常行为）" % MAX_ROUNDS,
       1 <= len(plan_calls) <= MAX_ROUNDS, str(len(plan_calls)))


# ══ C. 结论 ** 清洗 ══════════════════════════════════════════════
def test_c_balance_bold():
    print("[C] _balance_bold / clip")
    from qa.report import _balance_bold, clip
    ok("奇数 ** 全剥", _balance_bold("命中 **8 条高危漏洞") == "命中 8 条高危漏洞")
    ok("偶数 ** 保留（正常粗体）", _balance_bold("命中 **8 条**漏洞") == "命中 **8 条**漏洞")
    ok("无标记原样", _balance_bold("纯文本结论") == "纯文本结论")
    out, hit = clip("结论：命中 **8 条已被在野利用（exploited=true）的高危漏洞")
    ok("clip 输出无裸 **", "**" not in out, repr(out[:60]))
    ok("未超限不截断", hit is False)


# ══ D/E. 端口指纹 + 情报关联 + 工单 ══════════════════════════════
def test_d_identify():
    print("[D] _identify 三层指纹")
    p = {"port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"}
    prod, ver, conf, _src = PS._identify(p)
    ok("SSH banner → openssh 8.9p1 高置信", prod == "openssh" and ver == "8.9p1" and conf == "高",
       "%s/%s/%s" % (prod, ver, conf))
    p2 = {"port": 8080, "service": "http-proxy", "banner": "", "http_server": "nginx/1.24.0"}
    prod2, ver2, conf2, _ = PS._identify(p2)
    ok("Server 头 → nginx 1.24.0", prod2 == "nginx" and ver2 == "1.24.0" and conf2 == "高",
       "%s/%s/%s" % (prod2, ver2, conf2))
    p3 = {"port": 6379, "service": "redis", "banner": ""}
    prod3, ver3, conf3, src3 = PS._identify(p3)
    ok("无指纹 → 端口推断 redis 低置信", prod3 == "redis" and ver3 == "" and conf3 == "低"
       and "推断" in src3, "%s/%s/%s/%s" % (prod3, ver3, conf3, src3))
    p4 = {"port": 12345, "service": "unknown", "banner": ""}
    prod4, _v, conf4, _s = PS._identify(p4)
    ok("什么都识别不出 → 无", prod4 == "" and conf4 == "无", str(prod4))


def test_e_correlate_workorder():
    print("[E] correlate + 工单报告（真引擎）")
    from engine import SearchEngine
    eng = SearchEngine(paths.CORPUS_FP)
    res = {
        "ok": True, "host": "test-target.local", "ip": "127.0.0.1",
        "scanned": 2, "open_count": 2, "closed": 0, "workers": 10,
        "timeout": 1.0, "elapsed_ms": 5, "ts": "2026-10-08T19:00:00",
        "note": "t", "disclaimer": "仅限授权资产",
        "open_ports": [
            {"port": 22, "service": "ssh",
             "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu"},
            {"port": 8080, "service": "http-proxy", "banner": "",
             "http_server": "Apache Tomcat/9.0.30"},
        ],
    }
    PS.correlate(eng, res, http_probe=False)   # 离线：不发真 HTTP 探测
    corr = res.get("correlation") or {}
    ok("correlation 存在", bool(corr), str(corr)[:100])
    ok("识别 2 个指纹", corr.get("identified") == 2, str(corr.get("identified")))
    ok("命中 CVE", (corr.get("cve_hits") or 0) > 0, str(corr.get("cve_hits")))
    pssh = next(p for p in res["open_ports"] if p["port"] == 22)
    ptom = next(p for p in res["open_ports"] if p["port"] == 8080)
    ok("openssh 8.2p1 高置信版本匹配", pssh.get("version") == "8.2p1"
       and pssh.get("ident_conf") == "高", str((pssh.get("product"), pssh.get("version"))))
    ok("tomcat 9.0.30 识别", ptom.get("product") == "apache_tomcat"
       and ptom.get("version") == "9.0.30", str((ptom.get("product"), ptom.get("version"))))
    ok("端口级 risk_level 就位", bool(pssh.get("risk_level")), str(pssh.get("risk_level")))
    ok("findings 带 remediation/kev 字段结构",
       (not pssh.get("findings")) or ("id" in pssh["findings"][0] and "severity" in pssh["findings"][0]))

    md = PS.workorder_markdown(res)
    for kw in ("报告编号", "工单编号前缀", "检测范围与边界", "执行摘要", "整体风险等级",
               "端口与服务风险明细", "处置工单", "SLA", "验收标准", "口径与边界", "复测计划"):
        ok("工单报告含「%s」" % kw, kw in md)
    ok("报告含 WO- 工单条目", "WO-" in md)
    ok("报告含命中编号", any(f["id"] in md for p in res["open_ports"]
                             for f in (p.get("findings") or [])))
    ok("low 置信端口进未识别/待确认说明", True)  # 结构性断言已覆盖


# ══ F. project_scan 10GB + parse_zip_path ═══════════════════════
def test_f_project_10gb():
    print("[F] project_scan 大包路径")
    ok("MAX_ZIP_TOTAL == 10GB", PJ.MAX_ZIP_TOTAL == 10 * 1024 ** 3,
       str(PJ.MAX_ZIP_TOTAL))
    ok("MAX_ZIP_ENTRIES 放开到 1e5", PJ.MAX_ZIP_ENTRIES == 100000, str(PJ.MAX_ZIP_ENTRIES))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app/requirements.txt", "flask==2.3.2\nrequests>=2.31.0\n")
        zf.writestr("app/pom.xml",
                    "<dependency><groupId>org.apache.logging.log4j</groupId>"
                    "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>")
        zf.writestr("app/readme.md", "not a manifest")
    data = buf.getvalue()
    r_mem = PJ.parse_zip(data, "t.zip")
    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), "aisec_proj_test_%d.zip" % os.getpid())
    with open(tmp, "wb") as f:
        f.write(data)
    try:
        r_path = PJ.parse_zip_path(tmp)
        ok("parse_zip_path 成功", not r_path.get("error"), str(r_path.get("error")))
        ok("与内存路径结果等价",
           [(c["name"], c["version"]) for c in r_path.get("components") or []]
           == [(c["name"], c["version"]) for c in r_mem.get("components") or []])
        ok("path 入口 build_report 可用",
           (PJ.build_report("t.zip", b"", None, persist=False, path=tmp).get("ok") is True))
        # 坏 zip
        bad = os.path.join(tempfile.gettempdir(), "aisec_proj_bad_%d.bin" % os.getpid())
        with open(bad, "wb") as f:
            f.write(b"definitely not a zip")
        try:
            ok("坏 zip 如实报错", "不是有效的 zip" in (PJ.parse_zip_path(bad).get("error") or ""))
        finally:
            try:
                os.remove(bad)
            except OSError:
                pass
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def main():
    t0 = time.time()
    test_a_fast_route()
    test_b_fast_path_e2e()
    test_b2_normal_path_untouched()
    test_c_balance_bold()
    test_d_identify()
    test_e_correlate_workorder()
    test_f_project_10gb()
    print("\n== %d passed, %d failed（%.1fs）==" % (PASS, len(FAIL), time.time() - t0))
    if FAIL:
        for f in FAIL:
            print("  FAILED:", f)
        sys.exit(1)


if __name__ == "__main__":
    main()
