"""tools/_test_cvss_primary.py —— CVSS 必须取 NVD Primary 度量的回归测试

背景（真实缺陷，由 tools/评测门禁.py 真跑发现，不是代码审查猜的）：
  `core/fetch_corpus.py::parse_cvss` 曾直接取 `metrics.cvssMetric*` 数组的
  **第一条** `arr[0]`。但 NVD 对同一 CVE 常同时给：
      · type="Primary"    —— NVD 官方评分（权威口径）
      · type="Secondary"  —— CNA/厂商自评（CNAD 等）
  **数组顺序不保证 Primary 在前**。实测语料中 6733 条取错了：
      CVE-2022-0902  语料 8.1/HIGH(Secondary) → NVD Primary 9.8/CRITICAL
      CVE-2026-4395  语料 1.3/LOW(Secondary)   → NVD Primary 9.8/CRITICAL  Δ8.5
  方向统计：4314 条被**低估**、2419 条被高估。即约 5% 的 CVE 被错误标成低危 ——
  对安全产品是实质性错误。

跑法： py tools/_test_cvss_primary.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import paths  # noqa: E402
from fetch_corpus import parse_cvss  # noqa: E402

NVD_FP = os.path.join(paths.DATA_DIR, "nvd_cache.json")
CORPUS_FP = os.path.join(paths.DATA_DIR, "corpus.json")

PASS, FAIL = [], []


def ck(cond, name, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  [OK]   " if cond else "  [FAIL] ") + name + (
        ("  → " + str(extra)) if extra and not cond else ""))


def main() -> int:
    print("\nA. parse_cvss 对多度量记录的取值")
    # 构造 Primary 在**后**的记录 —— 这是旧实现会取错的场景
    cve = {"metrics": {"cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH",
                                          "version": "3.1"}},
        {"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                                         "version": "3.1"}},
    ]}}
    r = parse_cvss(cve)
    ck(r.get("score") == 9.8, "Primary 在后时取 Primary（不是 arr[0]）", r.get("score"))
    ck(r.get("severity") == "CRITICAL", "严重级取 CRITICAL", r.get("severity"))

    # Primary 在前（顺序恰好正确时也要对）
    cve2 = {"metrics": {"cvssMetricV31": [
        {"type": "Primary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH",
                                         "version": "3.1"}},
        {"type": "Secondary", "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}},
    ]}}
    ck(parse_cvss(cve2).get("score") == 7.5, "Primary 在前时同样取 Primary")

    # 无 type 标注 → 退回第一条，不返回 None（不得因缺 type 就丢数据）
    cve3 = {"metrics": {"cvssMetricV31": [
        {"cvssData": {"baseScore": 6.0, "baseSeverity": "MEDIUM"}},
    ]}}
    ck(parse_cvss(cve3).get("score") == 6.0, "无 type 标注时退回第一条")

    # 版本优先级：V4 > V31 > V30 > V2（都没有 Primary 时才按版本优先级）
    cve4 = {"metrics": {
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0}}],
        "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 8.0}}],
    }}
    ck(parse_cvss(cve4).get("score") == 8.0, "多版本并存时优先高版本 V31")

    # ★★ Primary 只标在**老版本**上（实测 CVE-2013-2423 / CVE-2021-34473 的形态）：
    #   NVD 有时只给 V2 打 Primary，而 V3.1 全是 CNA 的 Secondary。
    #   若按 V40→V2 逐版本"找 Primary"，会在只有 Secondary 的 V3.1 上停下 → 退化成取 Secondary。
    cve5 = {"metrics": {"cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"baseScore": 3.7, "baseSeverity": "LOW",
                                          "version": "3.1"}},
        {"type": "Primary", "cvssData": {"baseScore": 4.3, "baseSeverity": "MEDIUM",
                                         "version": "2.0"}},
    ]}}
    r5 = parse_cvss(cve5)
    ck(r5.get("score") == 4.3, "Primary 只在 V2 时也能取到（不跳过老版本）", r5.get("score"))
    ck(str(r5.get("version")) == "2.0", "version 取原值 2.0（不是派生的 '2'）",
       r5.get("version"))

    # version 必须是 cvssData.version 原值，不能用 key.replace 派生 ——
    # 派生会写出 "31"/"2"，与语料存的 "3.1"/"2.0" 对不上，评测会误判"版本不同"
    cve6 = {"metrics": {"cvssMetricV31": [
        {"type": "Primary", "cvssData": {"baseScore": 7.5, "version": "3.1"}}]}}
    ck(str(parse_cvss(cve6).get("version")) == "3.1",
       "version 用 cvssData.version 原值", parse_cvss(cve6).get("version"))

    # ★★ **多个版本同时标 Primary**（实测语料 58210 条里 22230 条如此）：
    #   CVE-2022-31210 的 V3.1=9.8 与 V2=7.5 都是 Primary。
    #   必须取**最高版本**（V3.1 9.8）—— V2 是老版本、评分口径已过时。
    #   这与"数组顺序不保证 Primary 在前"是**两个独立的坑**，只修一个不够：
    #   "全版本扫 Primary 取首个命中"才对，"取最后一个命中"仍会拿到 V2。
    cve7 = {"metrics": {
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 7.5,
                                                          "baseSeverity": "HIGH",
                                                          "version": "2.0"}}],
        "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8,
                                                           "baseSeverity": "CRITICAL",
                                                           "version": "3.1"}}],
    }}
    r7 = parse_cvss(cve7)
    ck(r7.get("score") == 9.8, "多版本均标 Primary 时取最高版本（不是 V2）",
       r7.get("score"))
    ck(str(r7.get("version")) == "3.1", "version 为 3.1", r7.get("version"))

    # 顺序颠倒（V2 排在字典前面）也必须取 V31
    cve8 = {"metrics": {
        "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8,
                                                           "version": "3.1"}}],
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 3.5,
                                                          "version": "2.0"}}],
    }}
    ck(parse_cvss(cve8).get("score") == 9.8, "键顺序颠倒仍取最高版本")

    # 无 metrics → 不得抛异常
    ck(parse_cvss({}).get("score") is None, "空记录返回 None 不抛异常")

    if not os.path.isfile(NVD_FP):
        print("\n  (跳过数据级检查：无 %s)" % NVD_FP)
        print("\n" + "=" * 58)
        print("通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
        return 1 if FAIL else 0

    print("\nB. 数据级：语料 CVSS 与 NVD Primary 一致性")
    with open(NVD_FP, encoding="utf-8") as f:
        nvd = json.load(f).get("cves") or {}

    def primary(rec):
        """取**最高版本**的 Primary；没有 Primary 返回 None。

        与 parse_cvss 同一判据（否则会出现"语料是对的、测试报不一致"的假阳性）。
        两个要点：①按版本从新到旧扫，首个带 Primary 的版本即取；
        ②没有 Primary 则返回 None（不退回 Secondary）——实测 9440 条 CVE
        只有 Secondary，其语料值来自 GitHub Advisory/OSV 等其他权威源，
        本就不该和 NVD 比，判为错是冤枉。
        """
        m = rec.get("metrics") or {}
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for x in (m.get(k) or []):
                if x.get("type") == "Primary":
                    sc = (x.get("cvssData") or {}).get("baseScore")
                    if sc is not None:
                        return sc
        return None

    try:
        with open(CORPUS_FP, encoding="utf-8") as f:
            c = json.load(f)
    except Exception as e:  # noqa: BLE001
        ck(False, "corpus 可读", e)
        return 1

    mismatch = []
    n_cmp = 0
    for key in ("records", "papers", "knowledge"):
        for d in c.get(key) or []:
            cid = (d.get("id") or "").strip().upper()
            if not cid.startswith("CVE-"):
                continue
            rec = nvd.get(cid)
            if not rec:
                continue
            t = primary(rec)
            if t is None:
                continue
            cur = d.get("cvss")
            cs = cur.get("score") if isinstance(cur, dict) else cur
            try:
                cs = float(cs)
            except (TypeError, ValueError):
                continue
            n_cmp += 1
            if abs(t - cs) > 0.05:
                mismatch.append((cid, cs, t))
    ck(n_cmp > 1000, "可比对样本量足够", n_cmp)
    rate = pct = (len(mismatch) / n_cmp) if n_cmp else 0
    ck(rate <= 0.001, "语料 CVSS 与 NVD Primary 不一致率 ≤0.1%%（实测 %.3f%%）"
       % (rate * 100), mismatch[:5])

    print("\nC. 反向验证：无 Primary 的记录不参与比对（不是判为错）")
    # 统计 NVD 里只有 Secondary 的比例 —— 这类样本语料值来自 GitHub/OSV 等其他源，
    # 本就不该和 NVD 比。不如实统计就会在报告里变成"语料错了"，是冤枉。
    only_sec = 0
    for key in ("records", "papers", "knowledge"):
        for d in c.get(key) or []:
            cid = (d.get("id") or "").strip().upper()
            if not cid.startswith("CVE-"):
                continue
            rec = nvd.get(cid)
            if not rec or primary(rec) is not None:
                continue
            m = rec.get("metrics") or {}
            if any(m.get(k) for k in ("cvssMetricV40", "cvssMetricV31",
                                       "cvssMetricV30", "cvssMetricV2")):
                only_sec += 1
    print("  NVD 仅有 Secondary（不参与比对）的 CVE: %d 条" % only_sec)
    ck(not mismatch, "不存在不一致记录（无 Primary 的已排除）", mismatch[:3])

    print("\n" + "=" * 58)
    print("通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
    for f in FAIL:
        print("  · " + f)
    print("=" * 58)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
