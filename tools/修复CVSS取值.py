"""tools/修复CVSS取值.py —— 把语料里「取了 Secondary 度量」的 CVSS 回填为 NVD Primary

发现方式（不是代码审查猜的，是评测门禁真跑出来的）：
  `tools/评测门禁.py` 对 300 个标注样本逐字段比 NVD 官方原始响应，
  CVSS 只有 289/300 对得上，11 条不一致**全部是语料值低于真值**。
  逐条核查后确认根因：`core/fetch_corpus.py::parse_cvss` 直接取
  `metrics.cvssMetricV*` 数组的**第一条**，而 NVD 对同一 CVE 常同时给
  Primary（NVD 官方评分）与 Secondary（CNAD/厂商自评），**顺序不保证 Primary 在前**。
    CVE-2022-0902 语料 8.1/HIGH（Secondary） → NVD Primary 9.8/CRITICAL
    CVE-2022-2750 语料 6.3/MEDIUM（Secondary） → NVD Primary 9.8/CRITICAL
  差 3.5 分、跨两个等级。对安全产品这是实质错误：会让高危漏洞显示成"不紧急"。

本脚本只回填**能由权威源确定**的那些：
  · 语料 CVE 在 nvd_cache 里有记录 → 用其 Primary 度量覆盖；
  · 拿不到 Primary（记录里没标 type）→ 保留原值不动，**不猜、不编**。
其余语料条目（非 CVE、nvd_cache 无记录）一律不动。

用法：
    python tools/修复CVSS取值.py --check     # 只报会改多少，不写
    python tools/修复CVSS取值.py            # 实际回填（自动备份）
    python tools/修复CVSS取值.py --no-corpus  # 只修 live_feed 不修 corpus
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "core"))
import paths  # noqa: E402

NVD_FP = os.path.join(paths.DATA_DIR, "nvd_cache.json")
CORPUS_FP = os.path.join(paths.DATA_DIR, "corpus.json")
FEED_FP = os.path.join(paths.DATA_DIR, "live_feed.jsonl")


def _primary_cvss(rec):
    """取 NVD Primary 度量（**最高版本**的 Primary）；没有则返回 None。

    ★★ 两个独立的坑，必须同时处理：
    1. **type 标在哪个版本上是独立的**（实测 CVE-2013-2423 / CVE-2021-34473）：
       NVD 可能只在老版本 V2 上标 Primary，而新版本 V3.1 全是 CNA 的 Secondary。
       按 V40→V2 逐版本"找 Primary"会落在只有 Secondary 的版本上。
    2. **多个版本同时标了 Primary**（实测语料 58210 条里 22230 条如此，如
       CVE-2022-31210 V3.1=9.8 与 V2=7.5 都是 Primary）：必须取**最高版本**的分数，
       V2 口径已过时。早先"全版本扫 Primary"取最后一个命中的实现会拿到 V2，
       把正确值判成错。
    正确写法就是：**按版本从新到旧扫，首个带 Primary 的版本即取它**。
    """
    m = rec.get("metrics") or {}
    order = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
    for key in order:
        for p in (m.get(key) or []):
            if p.get("type") != "Primary":
                continue
            d = p.get("cvssData") or {}
            sc = d.get("baseScore")
            if sc is None:
                continue
            sev = d.get("baseSeverity") or p.get("baseSeverity") or ""
            return {"score": sc, "severity": (sev or "").upper(),
                    "vector": d.get("vectorString", ""),
                    # version 用 cvssData.version 原值（"3.1"/"4.0"/"2.0"），
                    # 别用 key.replace("cvssMetricV","") —— 那会写出 "31"/"2" 这种
                    # 与语料原值对不上的串（实测 CVE-2002-2250 "2" vs "2.0"，分数相同
                    # 却被评测判成"版本不同"）。
                    "version": d.get("version") or key.replace("cvssMetricV", ""),
                    "exploitability": p.get("exploitabilityScore"),
                    "impact": p.get("impactScore")}
    # NVD 只有 Secondary 的记录（实测 9440 条 CVE）**返回 None，不覆盖语料**：
    # 这类条目的分值来自 GitHub Advisory / OSV 等其他权威源，同样是权威口径，
    # 拿 NVD 的 Secondary 去覆盖它是"用较差的口径替换较好的口径"，反而制造错误。
    return None


def _load_json(fp):
    with open(fp, encoding="utf-8") as f:
        return json.load(f)


def _atomic_write(fp, data, indent=1):
    tmp = fp + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=indent)
    with open(tmp, encoding="utf-8") as f:      # 回读校验，别写半截
        json.load(f)
    os.replace(tmp, fp)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只统计不写")
    ap.add_argument("--no-corpus", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(NVD_FP):
        print("[cvss] 找不到真值源 %s" % NVD_FP)
        return 2
    nvd = _load_json(NVD_FP).get("cves") or {}
    print("[cvss] 真值源 %d 条" % len(nvd))

    changed = 0
    checked = 0
    samples = []

    def _fix_doc(d, keys):
        nonlocal changed, checked
        cid = (d.get("id") or "").strip().upper()
        if not cid.startswith("CVE-"):
            return
        rec = nvd.get(cid)
        if not rec:
            return
        truth = _primary_cvss(rec)
        if not truth:
            return                     # 无 Primary → 不动（不猜）
        cur = d.get("cvss")
        cur_score = cur.get("score") if isinstance(cur, dict) else cur
        try:
            cur_score = float(cur_score)
        except (TypeError, ValueError):
            cur_score = None
        if cur_score is not None and abs(float(truth["score"]) - cur_score) <= 0.05:
            return                     # 一样，不动
        checked += 1
        # 保留语料里已有的 exploitability/impact，只覆盖评分相关字段
        if isinstance(cur, dict):
            new = dict(cur)
            new.update({"score": truth["score"], "severity": truth["severity"],
                        "vector": truth["vector"] or cur.get("vector", ""),
                        "version": truth["version"] or cur.get("version", "")})
            if truth["exploitability"] is not None:
                new["exploitability"] = truth["exploitability"]
            if truth["impact"] is not None:
                new["impact"] = truth["impact"]
        else:
            new = truth
        d["cvss"] = new
        changed += 1
        if len(samples) < 10:
            samples.append((cid, cur_score, truth["score"], truth["severity"]))

    # —— corpus ——
    if not args.no_corpus:
        c = _load_json(CORPUS_FP)
        before = changed
        for key in ("records", "papers", "knowledge"):
            for d in c.get(key) or []:
                if isinstance(d, dict):
                    _fix_doc(d, key)
        print("[cvss] corpus 需修正 %d 条" % (changed - before))
        if not args.check and changed > before:
            import datetime as dt
            bak = CORPUS_FP + ".bak-cvss-%s" % dt.date.today().strftime("%Y%m%d")
            if not os.path.isfile(bak):
                os.replace(CORPUS_FP, bak)
                _atomic_write(CORPUS_FP, c)
                print("[cvss] 已备份 → %s" % os.path.basename(bak))
            else:
                _atomic_write(CORPUS_FP, c)
            print("[cvss] 已写回 corpus.json")

    # —— live_feed ——
    fb = changed
    if os.path.isfile(FEED_FP):
        rows = []
        with open(FEED_FP, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:  # noqa: BLE001
                    continue
        for d in rows:
            if isinstance(d, dict):
                _fix_doc(d, "live")
        print("[cvss] live_feed 需修正 %d 条" % (changed - fb))
        if not args.check and changed > fb:
            import datetime as dt
            bak = FEED_FP + ".bak-cvss-%s" % dt.date.today().strftime("%Y%m%d")
            with open(bak, "w", encoding="utf-8") as f:
                for d in rows:
                    f.write(json.dumps(d, ensure_ascii=False) + "\n")
            tmp = FEED_FP + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                for d in rows:
                    f.write(json.dumps(d, ensure_ascii=False) + "\n")
            # 回读校验行数一致
            n = sum(1 for _ in open(tmp, encoding="utf-8"))
            assert n == len(rows), "行数不一致(%d vs %d)" % (n, len(rows))
            os.replace(tmp, FEED_FP)
            print("[cvss] 已备份并写回 live_feed.jsonl")

    print("\n共需修正 %d 条%s" % (changed, "（--check 模式未写入）" if args.check else ""))
    for cid, a, b, sev in samples:
        print("  · %s  %s → %s (%s)" % (cid, a, b, sev))
    if changed and not args.check:
        print("★ CVSS 参与索引：下次启动会重建 .idxcache（实测约 13 分钟，一次性）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
