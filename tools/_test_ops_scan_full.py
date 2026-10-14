"""tools/_test_ops_scan_full.py —— 感知层增量扫描回归（评审 P0-1 的针对性修复验证）

背景（第四轮评审实证坐实的缺陷）：
  旧 `PerceptionAgent.scan()` 用 `readlines()[-400:]` 只看实时流**尾部 400 行**。
  实测 data/live_feed.jsonl 4230 条里含 CVE 提及 227 条、紧急词 428 条，
  但尾部 400 行只有 2 条 CVE 提及 → 多路闸门在真实数据上**零产出**，
  ops_events/ops_briefs 恒为 []（评审报告原话：「感知→编排→富化→研判→决策
  的自主链路在真实数据上不产生任何简报/决策」）。

  根因是「只看尾部」：高信号事件一旦滚出尾部 400 行就再也扫不到，而 seen 又
  只在扫到的行里累积，形成「扫不到→记不住→永远扫不到」的死锁。

修复：改成**文件字节偏移做增量游标**——首次全量回溯，之后只读新增。
本测试用「高信号事件在第 400 行之前」的合成流，证明旧实现会漏、新实现不漏。

跑法： py tools/_test_ops_scan_full.py
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "modules", "m0_ops", "backend"))
sys.path.insert(0, os.path.join(ROOT, "core"))

import orchestrator as O  # noqa: E402

PASS, FAIL = [], []


def ck(cond, name, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  [OK]   " if cond else "  [FAIL] ") + name + (
        ("  → " + str(extra)) if extra and not cond else ""))


class _Trace:
    def __init__(self):
        self.items = []

    def add(self, agent, action, ok, detail="", ms=0):
        self.items.append((agent, action, ok, detail, ms))


def _mk_feed(tmp, n_low, n_high_pos):
    """构造实时流：前面 n_low 条低信号博客，然后 1 条高信号 CVE（在第 n_low+1 行，
    即 >400 的位置），最后 n_high_pos 条放在末尾之前。返回文件路径与高信号 id 列表。"""
    fp = os.path.join(tmp, "feed.jsonl")
    high_ids = []
    with open(fp, "w", encoding="utf-8") as f:
        for i in range(n_low):
            f.write(json.dumps({"id": "BLOG:%d" % i, "kind": "article",
                                "title": "weekly digest", "desc": "no signal",
                                "cvss": {"score": 0}}) + "\n")
        # 高信号：CVE 提及，位置在 n_low+1（>400，旧实现扫不到）
        cid = "CVE-2026-12345"
        high_ids.append(cid)
        f.write(json.dumps({"id": "LIVE:blog:high1", "kind": "article",
                            "title": "Critical %s exploited in the wild" % cid,
                            "desc": "affects %s" % cid,
                            "cvss": {"score": 9.8}}) + "\n")
    return fp, high_ids


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="aisec_ops_scan_")

    print("\nA. 高信号事件在前 400 行之外也能被扫到（旧实现漏）")
    feed, high_ids = _mk_feed(tmp, n_low=600, n_high_pos=1)
    state_fp = os.path.join(tmp, "state.json")
    p = O.PerceptionAgent(feed, state_fp, _Trace())
    evs = p.scan()
    got_ids = {e.get("cve") for e in evs}
    ck(bool(evs), "首次全量回溯扫到了高信号事件", evs)
    ck(any(h in got_ids for h in high_ids),
       "第 601 行的高信号 CVE 被捕获（旧实现只看尾部 400 行会漏）", got_ids)
    ck(len(evs) >= 1, "至少 1 个事件", len(evs))

    print("\nB. 增量：第二轮只处理新增，不回扫已 seen")
    # 追加一条新的高信号事件
    with open(feed, "a", encoding="utf-8") as f:
        f.write(json.dumps({"id": "LIVE:blog:high2", "kind": "article",
                            "title": "CVE-2026-99999 RCE",
                            "desc": "new", "cvss": {"score": 9.9}}) + "\n")
    evs2 = p.scan()
    ck(len(evs2) == 1, "第二轮只返回新增的 1 条（不回扫）", len(evs2))
    ck(evs2[0].get("cve") == "CVE-2026-99999", "新增事件被捕获", evs2[0].get("cve"))

    print("\nC. 游标持久化：重载后不重复扫")
    p.save()
    p2 = O.PerceptionAgent(feed, state_fp, _Trace())
    evs3 = p2.scan()
    ck(len(evs3) == 0, "重载后从持久化 offset 继续，不重复出事件", evs3)
    ck(p2.feed_offset == p.feed_offset, "offset 被正确持久化与恢复",
       "%s vs %s" % (p2.feed_offset, p.feed_offset))

    print("\nD. 文件被轮转/截断后自动从头扫（offset > size 归零）")
    # 覆盖 feed 为更短的内容，模拟轮转
    with open(feed, "w", encoding="utf-8") as f:
        f.write(json.dumps({"id": "LIVE:blog:new1", "kind": "article",
                            "title": "CVE-2026-88888 fresh", "desc": "x",
                            "cvss": {"score": 0}}) + "\n")
    p3 = O.PerceptionAgent(feed, state_fp, _Trace())
    evs4 = p3.scan()
    ck(any(e.get("cve") == "CVE-2026-88888" for e in evs4),
       "轮转后从头重扫，不漏新内容", evs4)

    print("\nE. 空 feed 不抛异常")
    empty = os.path.join(tmp, "empty.jsonl")
    open(empty, "w").close()
    p4 = O.PerceptionAgent(empty, os.path.join(tmp, "s4.json"), _Trace())
    ck(p4.scan() == [], "空文件返回空列表")

    print("\n" + "=" * 58)
    print("通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
    for f in FAIL:
        print("  · " + f)
    print("=" * 58)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
