"""tools/_test_goldset.py —— 标注集自洽性检查（可在 GitHub CI 跑，不需要本机大语料）

为什么要单独一个检查：
  `tools/评测门禁.py` 要读 `data/corpus.json`（283MB，不在版本库里），
  所以只能在**本机** CI 跑。但"标注集本身是否自洽"是可以在任何地方查的 ——
  评审最可能追问的恰恰是这块：
    · 标注集有 provenance 吗？真值来源写清楚了吗？
    · 抽样可复现吗（同 seed 出同样本）？
    · 有没有把"无权威真值"的维度伪装成有真值？
    · 样本量够不够支撑它给出的结论？
  这些不需要 283MB 语料，所以做成一个纯离线小测试，放进 tools/_test_*.py
  —— 现有 CI 的 `for t in tools/_test_*.py` 会自动带上它，不用改 ci.yml。

  （本机 CI 另加了第 9 步跑真正的评测门禁；GitHub CI 跑不了那一步，
    因为没有语料。这是刻意的分工，不是漏配。）
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EVAL_DIR = os.path.join(ROOT, "评测集")

PASS, FAIL = [], []


def ck(cond, name, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  [OK]   " if cond else "  [FAIL] ") + name + (
        ("  → " + str(extra)) if extra and not cond else ""))


def main() -> int:
    if not os.path.isdir(EVAL_DIR):
        print("  [FAIL] 找不到评测集/ 目录（标注集必须进版本库才能追溯）")
        return 1
    fps = sorted(f for f in os.listdir(EVAL_DIR) if f.startswith("gold_")
                 and f.endswith(".json"))
    ck(bool(fps), "评测集/ 下有 gold_v*.json", os.listdir(EVAL_DIR))
    if not fps:
        return 1

    for fn in fps:
        fp = os.path.join(EVAL_DIR, fn)
        print("\n%s" % fn)
        with open(fp, encoding="utf-8") as f:
            raw = f.read()
        try:
            d = json.loads(raw)
        except Exception as e:  # noqa: BLE001
            ck(False, "JSON 可解析", e)
            continue
        ck(True, "JSON 可解析")

        # 1. provenance 是 ground-truth 的核心，缺了整个文件不算真值集
        prov = d.get("provenance")
        ck(bool(prov), "带 provenance（真值来源可追溯）")
        if prov:
            ck("cvss_cwe_desc" in prov, "CVSS/CWE 真值来源已声明")
            src = (prov.get("cvss_cwe_desc") or {}).get("source", "")
            ck("NVD" in src, "真值源为 NVD 官方源", src)
            ck("field_map" in prov["cvss_cwe_desc"],
               "字段映射写清楚（能逐字段复核）")
            ck("independence" in (prov.get("kev") or {}),
               "KEV 真值的独立性限制被如实声明")

        # 2. scope：必须区分「有权威真值」与「无真值不标注」
        scope = d.get("scope") or {}
        ck(bool(scope.get("has_authoritative_gold")), "声明了有权威真值的维度")
        ck(bool(scope.get("no_gold_reason")), "声明了不标注的维度及原因")
        ck("paper_relevance" in (scope.get("no_gold_reason") or {}),
           "论文相关性明确列为无真值（不伪标注）")

        # 3. 抽样可复现：seed 必须固定
        ck(isinstance(d.get("seed"), int), "抽样种子已固定（结果可复现）")
        ck(bool(d.get("generated_at")), "记录了生成时间")

        # 4. 样本量：太小则任何百分比都没意义
        items = d.get("items") or []
        ck(len(items) >= 20, "样本量 ≥20（低于此统计无意义）", len(items))
        ck(d.get("sample_size") == len(items),
           "sample_size 与 items 实际条数一致",
           "%s vs %s" % (d.get("sample_size"), len(items)))

        # 5. 抽样偏差必须说清（过采样后指标是条件准确率）
        samp = d.get("sampling") or {}
        ck(bool(samp.get("caveat")), "过采样/口径限制已声明（不冒充全库准确率）")

        # 6. 单条标注的结构完整性
        bad = []
        for it in items:
            cid = it.get("cve", "")
            if not cid.startswith("CVE-") or not isinstance(it.get("cvss"), dict) \
                    or not (it.get("cwe") or []) or "in_kev" not in it:
                bad.append(cid or "?")
        ck(not bad, "每条标注结构完整（CVE/cvss/cwe/in_kev）", bad[:5])

        # 7. 指纹可校验：MANIFEST 里记的 sha256 前缀要对得上
        # 必须是**文件原始字节**的 sha256（与 建标注集.py 一致）。
        # 曾写成 hashlib.sha256(raw.encode("utf-8"))，其中 raw 是读出来的 str；
        # 读文本时结尾换行已被规范化，再 encode 回去与磁盘字节不一致，
        # 导致指纹永远对不上（实测踩到）。
        with open(fp, "rb") as fbin:
            h = hashlib.sha256(fbin.read()).hexdigest()[:16]
        man = os.path.join(EVAL_DIR, "MANIFEST.md")
        if os.path.isfile(man):
            with open(man, encoding="utf-8") as f:
                m = f.read()
            ck(h in m, "MANIFEST 记录的指纹与文件一致（防手改真值）", h)

        # 8. CVE 编号不得重复（重复会让"样本量"虚高）
        ids = [it.get("cve") for it in items]
        ck(len(set(ids)) == len(ids), "CVE 编号无重复（样本量不虚高）",
           "%d 条里 %d 个唯一" % (len(ids), len(set(ids))))

    print("\n" + "=" * 58)
    print("通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
    for f in FAIL:
        print("  · " + f)
    print("=" * 58)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
