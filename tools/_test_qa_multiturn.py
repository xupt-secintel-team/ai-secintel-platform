# -*- coding: utf-8 -*-
"""_test_qa_multiturn.py —— 情报问答「多轮指代消解」回归测试

钉死实测发现的失效场景（2026-10-07）：
  原 `_REF_RE` 只认"第N个/首个/它/该漏洞/上述"，实测
  「那怎么修」「还有别的吗」「继续」**全部不匹配** → 第二轮起丢失上下文，
  答案退化成泛泛的情报汇总。

本测试覆盖：
  ① 显式序号指代（第一个漏洞 / 第2条）→ 唯一定位到上一轮某个 CVE；
  ② 隐式承接（那怎么修 / 还有别的吗 / 继续说说）→ 并入上一轮主旨实体；
  ③ 独立提问不得被误改（"Ollama 有哪些漏洞" 不能变成别的）；
  ④ 自带编号的提问不消解（用户已点名，不需要上下文）；
  ⑤ 无 history 时不消解（第一轮没有上下文可言）。

用法： py tools/_test_qa_multiturn.py
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "modules", "m3_qa", "backend"))

PASS = FAIL = 0


def ok(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % label)
    else:
        FAIL += 1
        print("  [FAIL] %s %s" % (label, extra))


def main():
    from qa.deep_answer import is_reference, resolve_reference, _last_turn_entities

    hist = [
        {"role": "user", "content": "Ollama 有哪些漏洞"},
        {"role": "assistant",
         "content": "本次命中 CVE-2024-39722 与 CVE-2024-39719，"
                    "涉及 Ollama 模型文件存在性漏洞与 DoS。"},
    ]

    print("\n[1] 显式序号指代 → 唯一定位")
    for q, want in [("第一个漏洞的CWE是什么", "CVE-2024-39722"),
                    ("第2条漏洞详情", "CVE-2024-39719"),
                    ("它影响哪些版本", "CVE-2024-39722")]:
        r, anchor = resolve_reference(q, hist)
        ok("%s → 锚定 %s" % (q, want), anchor == want, "got=%s" % anchor)
        ok("  改写后的问题含锚点编号", want in r, r)

    print("\n[2] 隐式承接 → 并入上一轮实体（原先完全失效）")
    for q in ("那怎么修", "还有别的吗", "继续说说", "详细讲讲", "还有其他的吗"):
        r, anchor = resolve_reference(q, hist)
        ok("%s 被识别为承接" % q, is_reference(q), "is_reference=False")
        ok("  %s → 锚定上一轮实体" % q, anchor == "CVE-2024-39722", "got=%s" % anchor)
        ok("  改写后问题含锚点", anchor and anchor in r, r)

    print("\n[3] 独立提问不得被误改")
    for q in ("Ollama 有哪些漏洞", "vLLM 的高危漏洞", "最近被在野利用的漏洞"):
        r, anchor = resolve_reference(q, hist)
        ok("%s 不被当作承接" % q, not is_reference(q), "is_reference=True")
        ok("  %s 原样返回" % q, r == q and anchor is None, "r=%s anchor=%s" % (r, anchor))

    print("\n[4] 自带编号 → 不消解（用户已点名）")
    r, anchor = resolve_reference("CVE-2024-1234 怎么修", hist)
    ok("带 CVE 的提问不消解", anchor is None and r == "CVE-2024-1234 怎么修", r)

    print("\n[5] 无 history → 不消解")
    r, anchor = resolve_reference("那怎么修", None)
    ok("无 history 时原样返回", anchor is None and r == "那怎么修", r)
    r2, a2 = resolve_reference("那怎么修", [])
    ok("空 history 时原样返回", a2 is None and r2 == "那怎么修", r2)

    print("\n[6] 上一轮实体抽取")
    ents = _last_turn_entities(hist)
    ok("抽出上一轮 CVE 编号（优先级最高）",
       ents[:2] == ["CVE-2024-39722", "CVE-2024-39719"], str(ents))
    # 没有编号时退化为产品名
    h2 = [{"role": "assistant", "content": "vLLM 的远程代码执行漏洞很严重，vLLM 需要升级。"}]
    e2 = _last_turn_entities(h2)
    ok("无编号时抽出产品名", "vLLM" in e2 or "vllm" in [x.lower() for x in e2], str(e2))

    print("\n" + "=" * 60)
    print("  通过 %d · 失败 %d" % (PASS, FAIL))
    print("=" * 60)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
