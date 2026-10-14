"""tools/建标注集.py —— 生成**版本化** ground-truth 评测集（评审失分点 1 的基础）

为什么要有这个文件（评审原话：「代码里没有持续运行的标注评测集，
无法证明"富化准确率≥85%"或"问答响应≤5s"」）：
  此前所有评测指标都是**跑一次看一眼**的脚本，输出散落在 `测试报告/*.md`，
  既没有可追溯的标注来源，也没法在 CI 里当门禁。要"自证"，必须先把
  **真值固化下来**，并且说清楚它是怎么来的、什么时候固化的。

真值来源（防自证，三条独立于本项目生产链路）：
  1. **NVD 官方原始 API 响应缓存**（data/nvd_cache.json，58210 条）
     —— 权威源。本项目语料里的 cvss/cwe/products 都是**从别处解析来的**，
        用 NVD 原始记录去比，才叫"独立真值"；拿自己解析的结果比自己，
        无论多准都是循环论证。
  2. **CISA KEV 官方 JSON 缓存**（data/kev_snapshot.json）
     —— 权威源，用于 KEV 标记的精确率/召回率。
  3. **语料本身的客观字段**（published/cve id 存在性）
     —— 只用于"结构性断言"（如 id 格式、日期合法性），不用于主观判定。

**关键设计：标注是"确定性抽样"，不是"人工逐条打分"。**
  人工标注 100 条既慢又会因人而异，且无法在 CI 里复现。这里用固定随机种子
  （默认 20261008）从真值源抽样，标注内容 = 真值源字段的原样搬运。
  它的诚实性来自"真值源权威 + 抽样可复现"，而不是"标得准"。
  凡是无法从权威源机械判定的维度（如"论文关联是否相关"），
  **本文件一律不生成标注**，宁可评测维度少，也不用伪标注凑数。

产物：
  评测集/gold_v1.json   —— 标注集（含 version/provenance/生成时间/样本量）
  评测集/MANIFEST.md    —— 人类可读的版本说明与判据边界

为什么放 评测集/ 而不是 data/：data/ 整个在 .gitignore 里（语料 283MB 不进版本库），
标注集必须能提交 —— 否则"这次评测用的是哪份真值"无法追溯，CI 上也拿不到。

用法：
  python tools/建标注集.py                 # 生成 v1（默认 300 条）
  python tools/建标注集.py --sample 500 --version v2
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "core"))
import paths  # noqa: E402

# 标注集放**仓库内**的 评测集/，不放 data/。
# 原因：data/ 整个在 .gitignore 里（语料 283MB 不该进版本库），
# 标注集必须能提交 —— 否则"评测用了哪份真值"无法追溯，CI 上也拿不到，
# 就又回到评审说的"无法自证"。真值源（nvd_cache 等）仍从 data/ 读。
EVAL_DIR = os.path.join(ROOT, "评测集")
SEED = 20261008          # 固定种子：同版本必得同样本，评测结果可复现
NVD_FP = os.path.join(paths.DATA_DIR, "nvd_cache.json")
KEV_FP = os.path.join(paths.DATA_DIR, "kev_snapshot.json")
CORPUS_FP = os.path.join(paths.DATA_DIR, "corpus.json")


def _cvss_of(rec: dict):
    """从 NVD 原始记录抽 {score, severity, version}，取 **type=Primary**。

    ★ 版本遍历顺序不能想当然（2026-10-08 实测踩过）：
      原本按 V40→V31→V30→V2 逐版本找 Primary。但这 4 个版本**各自独立标注
      type**，NVD 完全可能只给老版本打 Primary：
        CVE-2013-2423  V31 里只有 Secondary 3.7，V2 里才是 Primary 4.3
        CVE-2021-34473 V31 里两条 Secondary(9.1/9.8)，V2 才是 Primary 10.0
      按高版本优先遍历 → 落到 V31 只剩 Secondary → 标注集把 Secondary 当真值，
      于是**评测报告里出现"语料没报错"的假不一致**（语料其实是对的）。
      查证后确认：剩余 4 条不一致 100% 由此而来，不是语料缺陷。

    所以：**全版本扫 Primary，找不到才按版本优先级退回第一条**。
    这样"真值"和"语料实现"用的是同一套判据 —— 判据与实现必须同源，
    否则不一致率就成了噪声，看不出真问题。
    """
    m = rec.get("metrics") or {}
    order = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

    def _pack(x, key):
        d = x.get("cvssData") or {}
        sc = d.get("baseScore")
        if sc is None:
            return None
        # version 取 cvssData.version 的**原值**（"3.1"/"4.0"/"2.0"），
        # 不要用 key.replace(...) —— 那会给出 "31"/"4"/"2" 这种没法和语料对齐的串
        # （实测 CVE-2002-2250 标注集 "2" vs 语料 "2.0"，分数完全相同却被判版本不一致）。
        return {"score": sc,
                "severity": d.get("baseSeverity") or x.get("baseSeverity"),
                "version": d.get("version") or key.replace("cvssMetricV", "")}

    # 按版本从新到旧扫，**首个带 Primary 的版本即取它**。
    # ★ 实测 22230 条 CVE 在**多个版本上同时标了 Primary**（如 CVE-2022-31210
    #   V3.1=9.8 与 V2=7.5 都是 Primary）。必须取**最高版本**的分数 ——
    #   V2 是老版本、评分口径已过时。早先"全版本扫 Primary"取最后一个命中，
    #   拿到的是 V2 的 7.5，会把正确值判成错（这与"数组顺序不保证 Primary 在前"
    #   是**两个独立的坑**，不能只修一个）。
    for key in order:
        for x in (m.get(key) or []):
            if x.get("type") == "Primary":
                r = _pack(x, key)
                if r:
                    return r
    # 没有任何版本标 Primary 的记录（实测 9440 条 CVE 只有 Secondary）
    # **不作为 CVSS 真值**：语料里这类条目的分值来自 GitHub Advisory / OSV
    # 等其他权威源，本就不该和 NVD 对得上。硬取"第一条 Secondary"当真值
    # 会造成假不一致，让报告出现"语料没报错"的冤枉结论。
    return None


def _cwes_of(rec: dict):
    out = []
    for w in rec.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = (d.get("value") or "").strip()
            if v and v != "NVD-CWE-noinfo" and v != "NVD-CWE-Other":
                out.append(v)
    return sorted(set(out))


def _products_of(rec: dict):
    """从 configurations 解析 vendor:product（CPE 2.3 / 2.2 都处理）。"""
    out = set()
    for node in rec.get("configurations") or []:
        for c in node.get("nodes") or []:
            for cpe in c.get("cpeMatch") or []:
                uri = cpe.get("criteria") or cpe.get("cpe23Uri") or ""
                parts = uri.split(":")
                # cpe:2.3:a:vendor:product:...
                if len(parts) >= 5 and parts[2] in ("a", "h", "o"):
                    out.add("%s:%s" % (parts[3], parts[4]))
    return sorted(out)


def _cisa_kev() -> set:
    """CISA KEV CVE 集合。**三种**落盘结构都要兼容（实测踩过坑）：
      1. `kev_cache.json`      —— {CVE: {...}}  本项目加工的扁平 dict（**实际用的是这个**）
      2. `kev_snapshot.json`   —— {"ts":..., "kev": {CVE: {...}}}   本项目快照
      3. CISA 官方原始响应      —— {"vulnerabilities":[{cveID:...}]} / {"cves":[...]}
    原实现只认第 3 种，实测 KEV 真值集解析出 **0 条** —— KEV 维度评测会形同虚设，
    而报告里照样能打印一个"准确率 100%"（因为没有正例也没有负例，空集全对）。
    这类"静默失效"比报错危险得多，所以现在按实际结构逐个尝试。

    独立性说明：第 1/2 种是**本项目自己落盘的中间格式**（内容源自 CISA 官方 JSON，
    但经过了本项目的解析）。用它做真值，独立性弱于直接用 NVD 原始响应。
    如实标注在 manifest 里，不假装它是与生产链路完全无关的第三方真值。
    """
    def _from_list(v) -> set:
        out = set()
        for x in v:
            if isinstance(x, dict):
                cid = x.get("cveID") or x.get("cveId") or x.get("id")
            else:
                cid = x
            if isinstance(cid, str) and cid.strip().upper().startswith("CVE-"):
                out.add(cid.strip().upper())
        return out

    def _from_dict(d) -> set:
        return {str(k).strip().upper() for k in d
                if str(k).strip().upper().startswith("CVE-")}

    cands = [KEV_FP,
             os.path.join(paths.DATA_DIR, "kev_cache.json"),
             os.path.join(paths.DATA_DIR, "kev_cve_cache.json")]
    for fp in cands:
        try:
            with open(fp, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(d, dict):
            continue
        # 结构 3：官方原始响应
        for key in ("vulnerabilities", "cves", "catalogs", "items"):
            v = d.get(key)
            if isinstance(v, list) and v:
                got = _from_list(v)
                if got:
                    return got
        # 结构 2：{ts, kev:{...}}
        for key in ("kev", "data", "cache"):
            v = d.get(key)
            if isinstance(v, dict):
                got = _from_dict(v)
                if got:
                    return got
            if isinstance(v, list) and v:
                got = _from_list(v)
                if got:
                    return got
        # 结构 1：顶层就是 {CVE: {...}}
        got = _from_dict(d)
        if got:
            return got
    return set()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=300, help="标注样本量")
    ap.add_argument("--version", default="v1", help="版本号（写进文件与 manifest）")
    args = ap.parse_args()

    if not os.path.isfile(NVD_FP):
        print("[标注] 找不到真值源 %s —— 无法生成评测集" % NVD_FP)
        return 2
    with open(NVD_FP, encoding="utf-8") as f:
        nvd = json.load(f).get("cves") or {}
    kev = _cisa_kev()
    print("[标注] 真值源: nvd_cache %d 条 · CISA KEV %d 条" % (len(nvd), len(kev)))

    # 只保留「真值字段足够完整」的 CVE：CVSS + CWE 至少各一项。
    # 理由：真值不完整的样本无法判定"富化对不对"，标了也是噪声。
    pool = []
    for cid, rec in nvd.items():
        cid = cid.strip().upper()
        if not cid.startswith("CVE-"):
            continue
        cv = _cvss_of(rec)
        cw = _cwes_of(rec)
        if not cv or not cw:
            continue
        descs = rec.get("descriptions") or []
        en = next((d.get("value") for d in descs
                   if d.get("lang") == "en"), None)
        if not en:
            continue
        pool.append({
            "cve": cid,
            "published": rec.get("published") or "",
            "cvss": cv,
            "cwe": cw,
            "products": _products_of(rec),
            "in_kev": cid in kev,
            "desc_en": en[:600],
        })
    print("[标注] 可用真值样本池: %d 条（有 CVSS+CWE+英文描述）" % len(pool))
    if len(pool) < args.sample:
        print("[标注] 样本池不足 %d 条，按实际池大小生成" % args.sample)
        args.sample = len(pool)

    rnd = random.Random(SEED)
    # —— 分层抽样，而不是纯随机 ——
    # 纯随机从数万条里抽 300，KEV 正例只有 2 个（实测）。2 个正例算出来的
    # "召回率"没有任何统计意义，却照样能打印成一个百分比 —— 这正是评审质疑的
    # "无 ground-truth 自证"。所以对稀有的正例类**过采样**，
    # 让每个有权威真值的维度都有足够样本量。
    # 代价要说清：过采样后各维度指标是**条件准确率**（在该类内正确率），
    # 不能直接当成"全库准确率"。manifest 里写明。
    picked = []
    # 层 1：KEV 正例（保证 KEV 维度可评测）
    kev_pos = [x for x in pool if x["in_kev"]]
    # 层 2：CVSS>=9 严重漏洞（保证高危维度可评测）
    crit = [x for x in pool if not x["in_kev"] and x["cvss"]["score"] >= 9.0]
    # 层 3：其余（保证总量到 sample，也让各 severity 等级都有覆盖）
    rest = [x for x in pool if not x["in_kev"] and x["cvss"]["score"] < 9.0]

    quota_kev = min(len(kev_pos), max(20, args.sample // 6))   # ≥20 或池子大小
    quota_crit = min(len(crit), max(30, args.sample // 4))
    for grp, quota in ((kev_pos, quota_kev), (crit, quota_crit)):
        picked.extend(rnd.sample(grp, quota))
    # 剩下的名额从 rest 补足（不再按"有 products"分层 —— 上一版实测导致
    # 总样本被压到 155 条：真值池收紧（有 Primary 才算 CVSS 真值）后
    # "有 CPE" 子池不够，rest+prod 补不满。分层只为保证稀有类有样本量，
    # 总量必须补足到 --sample，否则报告里 n 一栏会低于声明的样本量。）
    rest_quota = max(0, args.sample - len(picked))
    picked.extend(rnd.sample(rest, min(len(rest), rest_quota)))
    picked = picked[:args.sample]
    picked.sort(key=lambda x: x["cve"])          # 排序保证文件 diff 稳定
    strata = {"kev_positive": quota_kev, "cvss_ge9": quota_crit}

    os.makedirs(EVAL_DIR, exist_ok=True)
    out_fp = os.path.join(EVAL_DIR, "gold_%s.json" % args.version)
    payload = {
        "version": args.version,
        "generated_at": dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "seed": SEED,
        "sample_size": len(picked),
        "sampling": {
            "method": "分层过采样（保证稀有正例类有足够样本量）",
            "strata": strata,
            "caveat": "过采样后各维度指标是**条件准确率**（该类内正确率），"
                      "不能当作全库准确率；报告须按维度分别陈述样本量。",
        },
        # provenance 是这份文件的核心价值：不说清真值从哪来，就不叫 ground-truth
        "provenance": {
            "cvss_cwe_desc": {
                "source": "NVD 官方 API 原始响应缓存",
                "file": "data/nvd_cache.json",
                "pool_size": len(pool),
                "field_map": {
                    "cvss.score": "metrics.cvssMetricV*.cvssData.baseScore（取 Primary）",
                    "cvss.severity": "metrics.cvssMetricV*.cvssData.baseSeverity",
                    "cwe": "weaknesses[].description[].value（剔除 NVD-CWE-noinfo）",
                    "products": "configurations[].nodes[].cpeMatch[].criteria 的 vendor:product",
                    "desc_en": "descriptions[lang=en].value",
                    "published": "published",
                },
            },
            "kev": {
                "source": "CISA KEV 官方 JSON（本项目落盘副本）",
                "file": "data/kev_cache.json",
                "kev_size": len(kev),
                "independence": "弱于 NVD：内容源自 CISA 官方，但文件是本项目解析后的"
                                 "中间格式，与生产链路共用同一套解析代码。"
                                 "故 KEV 维度结论应表述为「与官方清单一致率」，"
                                 "不宜表述为「独立第三方验证」。",
            },
        },
        # 明确声明能力边界：哪些维度有权威真值、哪些没有。
        # 这是为了防止"用伪标注的分数当权威结论"——评审最可能追问的就是这个。
        "scope": {
            "has_authoritative_gold": ["cvss", "severity", "cwe", "kev", "products"],
            "no_gold_reason": {
                "paper_relevance": "论文与漏洞的相关性无权威判定源，需人工标注，"
                                   "本版本不生成（评测时只报覆盖度，不报准确率）",
                "qa_answer_quality": "答案质量无唯一正解，本版本只做时延与召回评测",
                "assets_exposure": "资产暴露与否依赖企业自身资产台账，不在语料范围",
            },
        },
        "items": picked,
    }
    tmp = out_fp + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    with open(tmp, encoding="utf-8") as f:      # 回读校验，别写出半截文件
        json.load(f)
    os.replace(tmp, out_fp)

    h = hashlib.sha256(open(out_fp, "rb").read()).hexdigest()[:16]
    man = os.path.join(EVAL_DIR, "MANIFEST.md")
    with open(man, "w", encoding="utf-8") as f:
        f.write("# 标注评测集 %s\n\n" % args.version)
        f.write("- 生成时间：%s\n" % payload["generated_at"])
        f.write("- 样本量：%d（随机种子 %d，同种子可复现）\n" % (len(picked), SEED))
        f.write("- 文件指纹（sha256 前 16 位）：`%s`\n" % h)
        f.write("- 真值源：`data/nvd_cache.json`（NVD 官方 API 原始响应，池 %d 条）\n"
                % len(pool))
        f.write("  + `data/kev_snapshot.json`（CISA KEV 官方 JSON，%d 条）\n\n" % len(kev))
        f.write("## 有权威真值的维度\n\n")
        for k in payload["scope"]["has_authoritative_gold"]:
            f.write("- `%s`\n" % k)
        f.write("\n## 明确不标注的维度（避免伪标注）\n\n")
        for k, v in payload["scope"]["no_gold_reason"].items():
            f.write("- `%s`：%s\n" % (k, v))
        f.write("\n> 变更标注集请新建版本（`--version v2`），不要覆盖旧版本 ——\n")
        f.write("> 评测分数只在同一版本内可比。\n")
    print("[标注] 已生成 %s（%d 条，指纹 %s）" % (out_fp, len(picked), h))
    print("[标注] 说明文件 %s" % man)
    return 0


if __name__ == "__main__":
    sys.exit(main())
