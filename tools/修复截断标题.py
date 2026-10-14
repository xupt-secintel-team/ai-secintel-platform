# -*- coding: utf-8 -*-
"""
修复截断标题.py —— 重算「修复 short_title 之前」生成的遗留标题
================================================================
背景（2026-10-08 实测）：
  实时监测里出现只有 19 个字符的条目「IBM Langflow OSS 1」，既没有 CVE 编号，
  也没按惯例截断到 _TITLE_MAX。查语料发现 CVE-2026-97680 的 desc 是完整的：
    "IBM Langflow OSS 1.0.0 through 1.12.2 could allow a remote authenticated…"
  而 title 被切成了 "IBM Langflow OSS 1"。

根因：`fetch_corpus.short_title` 早期版本按**第 1 个点**切句子，于是版本号里的
  "1.0.0" 把标题切成 "IBM Langflow OSS 1"。该函数后来已修（改为按
  「. ! ? + 空白 + 大写/数字」判句边界，并在标题前加 CVE 号，注释里字面写着
  这个案例），但**修复前生成的记录仍留在语料里**，没有重算。

危害不止是难看：
  ① 标题撞车 —— 三条不同 CVE（CVE-2026-97680 / 93679 / 101329）共用同一个
     坏标题「IBM Langflow OSS 1」，日报按标题去重时会被**合并成一条**，
     静默丢情报；
  ② 检索召回受损（标题是索引字段，标题残缺等于丢掉全部区分特征）。

修法：按 `short_title(id, desc)` 重算标题。判定条件刻意保守，只命中真正的
  遗留坏数据 —— 要求 **标题是 desc 的字面前缀**（正确标题必带 "CVE-x " 前缀，
  不可能是 desc 的前缀），且重算结果与现值不同。绝不碰正常标题。

用法：
    python tools/修复截断标题.py            # 修 corpus.json
    python tools/修复截断标题.py --check    # 只报告
副作用：标题参与索引，改完必须让引擎重建索引（文件大小会变 → .idxcache 的
  缓存键自动失效；下一次启动全量重建，实测约 13 分钟）。
"""
import gc
import io
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "core"))

from fetch_corpus import short_title  # noqa: E402

CORPUS_FP = os.path.join(ROOT, "data", "corpus.json")


def find_bad(arr):
    """挑出「标题是 desc 字面前缀且与 short_title 重算结果不同」的记录。"""
    bad = []
    for r in arr or []:
        if not isinstance(r, dict):
            continue
        cid = str(r.get("id") or "")
        t = str(r.get("title") or "").strip()
        d = str(r.get("desc") or "").strip()
        if not (cid.startswith("CVE-") and t and d):
            continue
        core = t.rstrip("…").strip()
        if d.startswith(core) and t != short_title(cid, d):
            bad.append(r)
    return bad


def main():
    dry = "--check" in sys.argv[1:]
    if not os.path.isfile(CORPUS_FP):
        print("找不到", CORPUS_FP)
        return 1
    t0 = time.time()
    with open(CORPUS_FP, encoding="utf-8") as f:
        corpus = json.load(f)
    print("载入语料 %.1fs" % (time.time() - t0))

    total = 0
    for key in ("records", "knowledge", "papers"):
        for r in find_bad(corpus.get(key)):
            old = r.get("title")
            r["title"] = short_title(r.get("id"), r.get("desc"))
            total += 1
            print("  [%s] %s\n      旧: %s\n      新: %s" % (key, r.get("id"), old, r["title"][:110]))
    if not total:
        print("没有需要重算的标题（语料已是干净的）")
        return 0
    print("\n共需重算 %d 条。" % total)
    if dry:
        print("--check：未写盘。")
        return 0

    stamp = time.strftime("%Y%m%d")
    bak = "%s.bak-title-%s" % (CORPUS_FP, stamp)
    if not os.path.isfile(bak):
        shutil.copy2(CORPUS_FP, bak)
        print("已备份 →", os.path.basename(bak))
    tmp = CORPUS_FP + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(corpus, f, ensure_ascii=False, separators=(",", ":"))
    del corpus
    gc.collect()
    # 校验 tmp 是合法 JSON 再原子替换（corpus 是引擎加载源，写坏=服务起不来）
    with open(tmp, encoding="utf-8") as f:
        check = json.load(f)
    n = sum(len(find_bad(check.get(k))) for k in ("records", "knowledge", "papers"))
    del check
    if n:
        os.remove(tmp)
        print("校验未通过：仍有 %d 条坏标题，已放弃写盘（原文件未动）" % n)
        return 1
    os.replace(tmp, CORPUS_FP)
    print("已写回 %s（校验通过，残留 0 条）" % CORPUS_FP)
    print("★ 标题参与索引：下次启动会重建 .idxcache（实测约 13 分钟），"
          "建议重启前先告知用户。")
    return 0


if __name__ == "__main__":
    sys.exit(main())