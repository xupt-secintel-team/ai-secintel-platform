# -*- coding: utf-8 -*-
"""
harvest_nvd.py —— NVD 全量收割（全库 CVE，按发布时间季度窗口）
================================================================
关键词采集只能覆盖命中词的子集；本脚本按 pubStartDate/pubEndDate 季度窗口
（NVD 单窗上限 120 天）遍历 1999 至今的全部 CVE，作为 20 万级语料的主体。

特性：
  · 断点续跑：每个完成的季度窗口记录在 data/nvd_full/_state.json，
    原始 CVE 以 JSONL 追加写入 data/nvd_full/{year}Q{n}.jsonl
  · 无 API Key 限速：每次请求间隔 6.5s（NVD 匿名 5 req/30s）
  · 失败重试：复用 fetch_corpus.http_get（tries=5，429/503 退避）

产出：data/nvd_full/*.jsonl（每行一个 NVD 原始 cve 对象），供 merge_full.py 使用。
"""

import io
import json
import os
import sys
import time
import urllib.parse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_corpus as F  # noqa: E402
# —— 模块化结构：数据目录统一由 core/paths.py 解析（本文件可独立运行）——
import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import paths  # noqa: E402


HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = paths.data_path("nvd_full")
STATE = os.path.join(OUT_DIR, "_state.json")
os.makedirs(OUT_DIR, exist_ok=True)

SLEEP = 6.5
PAGE = 2000


def quarters(start_year=1999):
    now = datetime.now()
    for y in range(start_year, now.year + 1):
        for q, (m1, m2) in enumerate(((1, 3), (4, 6), (7, 9), (10, 12)), 1):
            if y == now.year and m1 > now.month:
                return
            # 末月日期
            if m2 == 12:
                d2 = 31
            elif m2 in (3,):
                d2 = 31
            elif m2 in (6, 9):
                d2 = 30
            else:
                d2 = 31
            yield y, q, f"{y}-{m1:02d}-01", f"{y}-{m2:02d}-{d2}"


def fetch_window(d1, d2, start):
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?pubStartDate={urllib.parse.quote(d1 + 'T00:00:00.000', safe='')}"
           f"&pubEndDate={urllib.parse.quote(d2 + 'T23:59:59.999', safe='')}"
           f"&resultsPerPage={PAGE}&startIndex={start}&noRejected=")
    return json.loads(F.http_get(url, tries=5).decode("utf-8"))


def load_state():
    if os.path.isfile(STATE):
        with open(STATE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"done": []}


def save_state(st):
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f)
    os.replace(tmp, STATE)


def main():
    t0 = time.time()
    st = load_state()
    done = set(st["done"])
    qs = list(quarters())
    total_new = 0
    for y, q, d1, d2 in qs:
        key = f"{y}Q{q}"
        if key in done:
            continue
        fp = os.path.join(OUT_DIR, f"{key}.jsonl")
        n = 0
        start = 0
        try:
            while True:
                d = fetch_window(d1, d2, start)
                total = d.get("totalResults", 0)
                vs = d.get("vulnerabilities", []) or []
                if not vs:
                    break
                with open(fp, "a", encoding="utf-8") as f:
                    for v in vs:
                        c = v.get("cve")
                        if c:
                            f.write(json.dumps(c, ensure_ascii=False) + "\n")
                            n += 1
                start += len(vs)
                print(f"[nvd] {key} page @{start}/{total} (+{len(vs)})", flush=True)
                if start >= total:
                    break
                time.sleep(SLEEP)
        except Exception as e:  # noqa: BLE001
            print(f"[nvd] {key} FAILED: {str(e)[:120]} —— 保留断点，下次续跑", flush=True)
            # 部分写入的文件作废（避免半截窗口被当成完成）
            if os.path.isfile(fp) and n == 0:
                os.remove(fp)
            save_state(st)
            raise
        done.add(key)
        st["done"] = sorted(done)
        save_state(st)
        total_new += n
        print(f"[nvd] {key} done: {n} 条（累计本轮 {total_new}，"
              f"总耗时 {round(time.time()-t0)}s）", flush=True)
        time.sleep(SLEEP)
    print(f"[nvd] 全部窗口完成，本轮新增 {total_new} 条，总耗时 {round(time.time()-t0)}s")


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    main()
