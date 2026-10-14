# -*- coding: utf-8 -*-
"""A/B 验证：语料被删后「索引缓存复用（下标平移）」与「全量重建」是否等价。

背景
----
平台语料被删是常态（AI 闸门筛选 / 重采集替换一轮就能去掉近两千条）。旧口径下
只要缓存里有一条文档对不上，整份 .idxcache 就作废，每次启动都要重新分词
（10 万条实测 321s）。改成「按下标平移复用」后必须证明：省下的时间没有换来
错误的检索结果。

做法
----
同一份 modified 语料，走两条路径各建一次引擎：
  B = 复用旧缓存（剔除已删 + 尾部增量）      —— 待验证路径
  C = 删掉缓存后全量重建                     —— 基准真值
再逐项比对 N / dl / tf / df / postings / id_map / 检索 top-10。

用法
----
  python tools/_test_index_drop.py            # 默认 8000 条子集
  python tools/_test_index_drop.py 30000      # 指定规模（越大越慢，越接近真实）
"""
import json
import os
import random
import shutil
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))

DATA = os.path.join(ROOT, "data")
CORPUS = os.path.join(DATA, "corpus.json")
P_BASE = os.path.join(DATA, "_ab_base.json")
P_MOD = os.path.join(DATA, "_ab_mod.json")

QUERIES = [
    "ollama 远程代码执行",
    "供应链攻击 依赖投毒",
    "prompt injection 提示词注入",
    "已被在野利用的漏洞",
    "vLLM 高危漏洞影响哪些版本",
    "CVE-2025 反序列化",
    "大模型 越狱 防护",
    "渗透测试开源工具有哪些",
    "勒索软件 内网横向移动",
    "RAG 知识库 数据泄露",
]


def build_corpus(records, knowledge):
    return {"meta": {"ab": True}, "records": records,
            "knowledge": knowledge, "papers": []}


def write(path, corpus):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(corpus, f, ensure_ascii=False, separators=(",", ":"))


def engine_of(path, label, drop_cache=False):
    from engine import SearchEngine
    if drop_cache and os.path.isfile(path + ".idxcache"):
        os.remove(path + ".idxcache")
    t0 = time.time()
    e = SearchEngine(path)
    dt = time.time() - t0
    print("  %-8s 建引擎 %6.1fs | 命中缓存=%s 剔除=%d 增量=%d 文档=%d"
          % (label, dt, e._loaded_from_cache,
             getattr(e, "_dropped_from_cache", 0),
             getattr(e, "_incremental_from_cache", 0), e.N))
    return e, dt


def cmp_index(ea, eb, name_a, name_b):
    """按**语义**比对两份索引，返回 (差异描述列表, 通过项数)。

    注意不能按下标逐项比：两条路径的文档排列顺序本就不同 —— B 沿用缓存的
    doc_order，C 用语料文件里的顺序。下标体系不同是设计使然（正因如此才要
    做下标平移），要验的是「同一个文档 id 的数据是否一致」以及「各自的下标
    体系是否自洽」。
    """
    diffs, ok = [], 0

    def chk(cond, desc):
        nonlocal ok
        if cond:
            ok += 1
        else:
            diffs.append(desc)

    chk(ea.N == eb.N, "文档数 N：%d vs %d" % (ea.N, eb.N))
    ids_a = [d.get("id") for d in ea.docs]
    ids_b = [d.get("id") for d in eb.docs]
    chk(set(ids_a) == set(ids_b),
        "文档 id 集合不同（仅%s %d 条 / 仅%s %d 条）"
        % (name_a, len(set(ids_a) - set(ids_b)), name_b, len(set(ids_b) - set(ids_a))))
    if set(ids_a) != set(ids_b):
        return diffs, ok

    ia = {v: i for i, v in enumerate(ids_a)}
    ib = {v: i for i, v in enumerate(ids_b)}

    # 逐文档比对（按 id 对齐，与排列顺序无关）
    bad = [k for k in ia if ea.dl[ia[k]] != eb.dl[ib[k]]]
    chk(not bad, "dl 有 %d 条文档不同（例 %s）" % (len(bad), bad[:3]))
    bad = [k for k in ia if ea.tf[ia[k]] != eb.tf[ib[k]]]
    chk(not bad, "tf 有 %d 条文档不同（例 %s）" % (len(bad), bad[:3]))

    # 倒排表：转成「命中文档 id 集合」再比，绕开下标体系差异
    pa, pb = ea.postings, eb.postings
    if set(pa) != set(pb):
        diffs.append("postings 词表不同：仅%s有 %d 项 / 仅%s有 %d 项"
                     % (name_a, len(set(pa) - set(pb)), name_b, len(set(pb) - set(pa))))
    else:
        bad_t = []
        for t in pa:
            if {ids_a[i] for i in pa[t]} != {ids_b[i] for i in pb[t]}:
                bad_t.append(t)
        chk(not bad_t, "postings 有 %d 个词项的命中文档集合不同（例 %s）"
            % (len(bad_t), bad_t[:5]))

    # 文档频次 / 派生量（这些与下标无关，必须严格相等）
    if ea.df != eb.df:
        ka, kb_ = set(ea.df), set(eb.df)
        both = [t for t in ka & kb_ if ea.df[t] != eb.df[t]]
        diffs.append("df 不同：仅%s有 %d 项 / 仅%s有 %d 项 / 值不同 %d 项（例 %s）"
                     % (name_a, len(ka - kb_), name_b, len(kb_ - ka), len(both),
                        [(t, ea.df[t], eb.df[t]) for t in both[:3]]))
    else:
        ok += 1
    chk(abs((ea.avgdl or 0) - (eb.avgdl or 0)) < 1e-9,
        "avgdl：%r vs %r" % (ea.avgdl, eb.avgdl))
    if ea.idf != eb.idf:
        both = [t for t in set(ea.idf) & set(eb.idf) if abs(ea.idf[t] - eb.idf[t]) > 1e-9]
        diffs.append("idf 有 %d 项不同（例 %s）" % (len(both), both[:3]))
    else:
        ok += 1
    chk(ea.phrase_df == eb.phrase_df,
        "phrase_df 不同（%d vs %d 项）" % (len(ea.phrase_df or {}), len(eb.phrase_df or {})))

    # ---- 下标自洽性：下标一旦平移错，postings 会指向不含该词项的文档 ----
    rnd = random.Random(7)
    for e, nm in ((ea, name_a), (eb, name_b)):
        sample = rnd.sample(list(e.postings), min(2000, len(e.postings)))
        broken = [t for t in sample
                  if any(t not in e.tf[i] for i in e.postings[t])]
        chk(not broken, "%s 的 postings 有 %d/%d 个抽样词项指向不含该词的文档（下标错位）"
            % (nm, len(broken), len(sample)))
        bad_map = sum(1 for k, i in e.id_map.items()
                      if not (0 <= i < len(e.docs)
                              and (e.docs[i].get("id") or "").upper() == k))
        chk(bad_map == 0, "%s 的 id_map 有 %d 项指向了错误文档" % (nm, bad_map))
        bad_df = sum(1 for t, p in e.postings.items() if e.df.get(t) != len(p))
        chk(bad_df == 0, "%s 有 %d 个词项的 df != len(postings)" % (nm, bad_df))
    return diffs, ok


def top10(e, q):
    r = e.search(q, top_k=10)
    items = r.get("items") if isinstance(r, dict) else r
    out = []
    for it in (items or [])[:10]:
        did = it.get("id") if isinstance(it, dict) else it
        sc = it.get("score") if isinstance(it, dict) else None
        out.append((did, round(float(sc or 0), 6)))
    return out


def main():
    n_base = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print("=" * 72)
    print("索引缓存「容忍删除」A/B 验证 · 基准规模 %d 条" % n_base)
    print("=" * 72)

    if not os.path.isfile(CORPUS):
        print("找不到语料：%s" % CORPUS)
        return 1
    t0 = time.time()
    with open(CORPUS, "r", encoding="utf-8") as f:
        full = json.load(f)
    recs = full.get("records") or []
    kb = full.get("knowledge") or []
    print("真实语料：records %d / knowledge %d（读取 %.1fs）"
          % (len(recs), len(kb), time.time() - t0))

    n_kb = min(1000, len(kb))
    if len(recs) < n_base + 40:
        print("语料不足，降低规模")
        n_base = max(100, len(recs) - 40)

    base_recs = recs[:n_base]
    base_kb = kb[:n_kb]
    extra = recs[n_base:n_base + 20]          # 用作"新增"（缓存里一定没有）

    # ---------- ① 建基准语料 + 它的索引缓存 ----------
    write(P_BASE, build_corpus(base_recs, base_kb))
    for p in (P_BASE, P_BASE + ".idxcache"):
        if os.path.isfile(p + ".idxcache"):
            os.remove(p + ".idxcache")
    print("\n① 建基准索引（全量重建，模拟" "服务上次运行时落盘的缓存）")
    e0, _ = engine_of(P_BASE, "基准", drop_cache=True)
    cache_fp = P_BASE + ".idxcache"
    if not os.path.isfile(cache_fp):
        print("基准缓存未落盘，无法继续")
        return 1

    # ---------- ② 造一份"被删过 + 有新增"的语料 ----------
    rnd = random.Random(20261003)
    n_drop_rec = int(n_base * 0.037)          # ≈3.7%，真实场景是 1.76%
    n_drop_kb = int(n_kb * 0.03)
    drop_r = set(rnd.sample(range(len(base_recs)), n_drop_rec))
    drop_k = set(rnd.sample(range(len(base_kb)), n_drop_kb))
    mod_recs = [r for i, r in enumerate(base_recs) if i not in drop_r]
    mod_kb = [r for i, r in enumerate(base_kb) if i not in drop_k]
    mod_recs += extra
    write(P_MOD, build_corpus(mod_recs, mod_kb))
    n_drop = len(drop_r) + len(drop_k)
    print("\n② 构造变更语料：删除 %d 条（%.2f%%）· 新增 %d 条 · 最终 %d 条"
          % (n_drop, n_drop * 100.0 / (n_base + n_kb), len(extra), len(mod_recs) + len(mod_kb)))

    # ---------- ③ 路径 B：复用缓存（剔除 + 增量） ----------
    shutil.copyfile(cache_fp, P_MOD + ".idxcache")
    print("\n③ 路径 B —— 复用旧缓存（下标平移剔除已删 + 尾部增量）")
    eb, t_b = engine_of(P_MOD, "B复用")
    if not eb._loaded_from_cache:
        print("  !! 路径 B 没命中缓存，验证无意义：%s" % getattr(eb, "_cache_reject", ""))
        return 1
    got_drop = getattr(eb, "_dropped_from_cache", 0)
    got_inc = getattr(eb, "_incremental_from_cache", 0)
    if got_drop != n_drop or got_inc != len(extra):
        print("  !! 剔除/增量数量对不上：期望 剔除%d 增量%d，实际 剔除%d 增量%d"
              % (n_drop, len(extra), got_drop, got_inc))
        return 1
    print("  ✓ 剔除 %d 条、增量 %d 条，与预期一致" % (got_drop, got_inc))

    # ---------- ④ 路径 C：全量重建（真值） ----------
    print("\n④ 路径 C —— 删掉缓存后全量重建（基准真值）")
    ec, t_c = engine_of(P_MOD, "C重建", drop_cache=True)
    if ec._loaded_from_cache:
        print("  !! 路径 C 竟然命中了缓存，基准不成立")
        return 1

    # ---------- ⑤ 逐项比对 ----------
    print("\n⑤ 逐项比对 B（复用） vs C（全量重建）")
    diffs, ok = cmp_index(eb, ec, "B", "C")
    if diffs:
        print("  索引结构差异：")
        for d in diffs:
            print("    ✗ " + d)
    else:
        print("  ✓ 索引结构全部一致（N / docs顺序 / dl / tf / df / postings / id_map / avgdl / idf），共 %d 项" % ok)

    # 检索结果比对
    print("\n⑥ 检索结果比对（%d 个查询 × top-10）" % len(QUERIES))
    bad_q = []
    for q in QUERIES:
        ra, rb = top10(eb, q), top10(ec, q)
        if ra != rb:
            bad_q.append((q, ra, rb))
    if bad_q:
        for q, ra, rb in bad_q:
            print("  ✗ %r" % q)
            print("      B: %s" % (ra[:5],))
            print("      C: %s" % (rb[:5],))
    else:
        print("  ✓ 全部 %d 个查询的 top-10（文档 + 分数）完全一致" % len(QUERIES))

    # phrase_df：过去是"删了文档也扣不掉"的近似项，现在靠 phrase_of 明细精确重算
    pa, pc = getattr(eb, "phrase_df", {}) or {}, getattr(ec, "phrase_df", {}) or {}
    common = set(pa) & set(pc)
    diff_n = sum(1 for t in common if pa[t] != pc[t])
    print("\n⑦ phrase_df（短语文档频次）")
    if pa == pc:
        print("  ✓ 完全一致（%d 项）—— 逐条短语明细 phrase_of 使精确重算成为可能" % len(pa))
    else:
        print("  ✗ B %d 项 / C %d 项，交集 %d 项中 %d 项不同（占 %.2f%%）"
              % (len(pa), len(pc), len(common), diff_n,
                 diff_n * 100.0 / max(len(common), 1)))

    print("\n" + "=" * 72)
    speed = (t_c / t_b) if t_b > 0 else 0
    print("耗时：全量重建 %.1fs · 缓存复用 %.1fs · 加速 %.2fx" % (t_c, t_b, speed))
    verdict = "一致 ✅" if (not diffs and not bad_q) else "不一致 ❌"
    print("结论：索引结构 + 检索结果 %s" % verdict)
    print("=" * 72)

    # 清理临时文件
    for p in (P_BASE, P_MOD, P_BASE + ".idxcache", P_MOD + ".idxcache"):
        try:
            if os.path.isfile(p):
                os.remove(p)
        except OSError:
            pass
    return 0 if (not diffs and not bad_q) else 2


if __name__ == "__main__":
    sys.exit(main())
