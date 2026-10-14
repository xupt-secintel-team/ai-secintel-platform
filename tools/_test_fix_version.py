# -*- coding: utf-8 -*-
"""_test_fix_version.py —— 修复建议里「升级到哪个版本」必须取**修复版本**

为什么补这条
------------
`fix_section` 原先用 `_ver_from_links` 从 advisory 链接抽版本号。遇到 GitHub 的
compare 链接 `/compare/v0.1.33...v0.1.34` 时，兜底正则取到**首个**版本号
v0.1.33 —— 那是**受影响版本**，不是修复版本。结果答案里同时出现
「升级到 v0.1.33」和「受影响区间 <0.1.34」，自相矛盾（0.1.33 落在受影响区间内）。

对用户而言这是**安全建议级错误**：照着做等于升级到仍有漏洞的版本。
而既有的《富化准确率评测》只测 CVSS/CWE/KEV/资产/论文五维，**没覆盖修复版本**，
所以这个错能一路溜到线上——本测试就是把这一维钉死。

判据（离线、确定性，不依赖网络与服务）：
  1. compare 链接必须取右侧版本；
  2. CPE 的 end_excl 是修复版本的真值，优先级高于链接抽取；
  3. 端到端：CVE-2024-37032（真值 0.1.34）的答案里不得出现 v0.1.33。

用法： py tools/_test_fix_version.py
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m3_qa", "backend"))
try:
    import loopback  # noqa: F401  打本机必备，否则代理机 502
    loopback.enable()
except Exception:  # pragma: no cover
    pass

PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % name)
    else:
        FAIL += 1
        print("  [FAIL] %s %s" % (name, detail))


def main() -> int:
    from qa.deep_answer import _ver_from_links, fix_section

    print("=== A. compare 链接取右侧（修复版本），不取左侧（受影响版本） ===")
    got = _ver_from_links(["https://github.com/ollama/ollama/compare/v0.1.33...v0.1.34"])
    check("A1 compare 取右", got == ["0.1.34"], "got=%s" % got)
    got2 = _ver_from_links(["https://github.com/x/y/compare/v1.2...v1.3.1"])
    check("A2 三段版本", got2 == ["1.3.1"], "got=%s" % got2)
    got3 = _ver_from_links(["https://github.com/x/y/releases/tag/v0.17.1"])
    check("A3 tag 链接不受影响", got3 == ["0.17.1"], "got=%s" % got3)
    check("A4 空输入不炸", _ver_from_links([]) == [])
    check("A5 脏数据不炸", _ver_from_links([None, 123, ""]) == [])

    print("\n=== B. 端到端：真实 CVE 的修复建议段 ===")
    corpus_fp = os.path.join(ROOT, "data", "corpus.json")
    if not os.path.isfile(corpus_fp):
        print("  [跳过] 语料不存在，B 组不测")
        return 1 if FAIL else 0
    with open(corpus_fp, "r", encoding="utf-8") as f:
        recs = json.load(f).get("records") or []
    rec = None
    for r in recs:
        if r.get("id") == "CVE-2024-37032":
            rec = r
            break
    if rec is None:
        print("  [跳过] 语料里没有 CVE-2024-37032")
        return 1 if FAIL else 0

    # 真值：CPE end_excl 才是修复版本
    truth = None
    for c in rec.get("cpe") or []:
        if isinstance(c, dict) and c.get("end_excl"):
            truth = str(c["end_excl"])
            break
    check("B1 语料真值可读", truth == "0.1.34", "truth=%s" % truth)

    out = fix_section("这些漏洞应该怎么修复？给出修复建议。", [rec]) or ""
    check("B2 输出修复版本真值", ("v%s" % truth) in out, "输出：%s" % out[:160])
    check("B3 不再出现受影响版 v0.1.33", "v0.1.33" not in out,
          "仍把受影响版本写成升级目标：%s" % out[:160])
    check("B4 依据标明来自 CPE", "end_excl" in out, "依据未标注来源：%s" % out[:200])
    check("B5 非修复意图不触发", fix_section("Ollama 有哪些漏洞？", [rec]) is None)

    print("\n" + "=" * 62)
    print("  通过 %d · 失败 %d" % (PASS, FAIL))
    print("=" * 62)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
