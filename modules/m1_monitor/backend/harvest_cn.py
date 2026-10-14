# -*- coding: utf-8 -*-
"""
harvest_cn.py —— 中文安全语料大规模收割
================================================
三个中文社区源（API 化，稳定可断点续跑）：

  1. CSDN      —— 55 组检索词 × 深翻页（p1..8），安全词门控
  2. 安全客     —— api.anquanke.com 全站分页（50 条/页），资讯/知识分类
  3. 先知社区   —— xz.aliyun.com/api/v2/news 分页（15 条/页，含官方摘要 subject）

产出：data/cn/{csdn,anquanke,xz}.json —— skeleton 知识条目列表
状态：data/cn/_state.json —— 各源游标，中断后从断点继续
"""

import io
import json
import os
import re
import sys
import time
import urllib.parse
import datetime
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extra_sources as X  # noqa: E402
# —— 模块化结构：数据目录统一由 core/paths.py 解析（本文件可独立运行）——
import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import paths  # noqa: E402


HERE = os.path.dirname(os.path.abspath(__file__))
CN_DIR = paths.data_path("cn")
STATE = os.path.join(CN_DIR, "_state.json")
os.makedirs(CN_DIR, exist_ok=True)

CSDN_PAGES = 8
AQK_CAP_PAGES = 400          # 50 条/页 → 最多 2 万篇
XZ_CAP_PAGES = 500           # 15 条/页 → 最多 7500 篇

# 全量收割的重跑间隔（天）。快车道（live.py，15s 一轮）只补「最新一页」，
# 历史语料的兜底补漏靠这里。设 AISEC_HARVEST_INTERVAL_DAYS=0 表示每次都重爬。
HARVEST_INTERVAL_DAYS = int(os.environ.get("AISEC_HARVEST_INTERVAL_DAYS", "15"))


def log(*a):
    print("[cn]", *a, flush=True)


def load_state():
    if os.path.isfile(STATE):
        with open(STATE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_state(st):
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f)
    os.replace(tmp, STATE)


# ==========================================================================
# 1. CSDN（深翻页）
# ==========================================================================
def _csdn_page(args):
    q, p = args
    url = ("https://so.csdn.net/api/v3/search?q=" + urllib.parse.quote(q) +
           f"&t=blog&p={p}")
    try:
        d = X.get_json(url, tries=2)
        return q, p, d.get("result_vos") or []
    except Exception as e:  # noqa: BLE001
        log(f"  CSDN '{q}' p{p} 失败: {str(e)[:50]}")
        return q, p, []


def harvest_csdn(st):
    fp = os.path.join(CN_DIR, "csdn.json")
    if st.get("csdn_done"):
        log("CSDN 已完成，跳过")
        return
    seen, out = set(), []
    if os.path.isfile(fp):
        with open(fp, "r", encoding="utf-8") as f:
            out = json.load(f)
        seen = {r["article_url"] for r in out}
        log(f"CSDN 断点续跑：已有 {len(out)} 篇")
    done_q = set(st.get("csdn_queries", []))
    todo = [q for q in X.CSDN_QUERIES if q not in done_q]
    log(f"CSDN：{len(todo)} 组检索词待抓（已完成 {len(done_q)}）")
    for qi, q in enumerate(todo, 1):
        args = [(q, p) for p in range(1, CSDN_PAGES + 1)]
        with ThreadPoolExecutor(max_workers=2) as ex:
            results = list(ex.map(_csdn_page, args))
        add = 0
        for _, _, items in sorted(results, key=lambda x: x[1]):
            for it in items:
                if (it.get("type") or "") != "blog":
                    continue
                url = (it.get("url") or "").split("?")[0]
                title = X._clean(it.get("title"))
                desc = X._clean(it.get("description") or it.get("digest"))
                if not title or not url or url in seen:
                    continue
                blob = title + " " + desc
                if not X.CSDN_GATE.search(blob) or X.CSDN_BAD_TITLE.search(title):
                    continue
                if len(desc) < 60:
                    continue
                created = X._clean(str(it.get("created_at") or ""))[:10] or "2024-01-01"
                if created < "2022-01-01":
                    continue
                seen.add(url)
                aid = it.get("articleid") or str(abs(hash(url)))
                rec = X._skeleton(
                    rid="CSDN:" + str(aid), rtype="article", kind="CSDN 社区文章",
                    title=title, desc=title + "。" + desc,
                    published=created, sources=["CSDN"],
                    category=X._guess_category(blob),
                    reason="中文社区技术文章（CSDN 检索 + 安全关键词门控通过）",
                    tags=["社区文章"],
                )
                rec["author"] = X._clean(it.get("nickname") or it.get("username") or "")
                rec["views"] = X._to_int(it.get("view") if it.get("view") is not None else it.get("view_num"))
                rec["article_url"] = url
                rec["advisory_links"] = [url]
                out.append(rec)
                add += 1
        done_q.add(q)
        st["csdn_queries"] = sorted(done_q)
        save_state(st)
        if qi % 5 == 0 or qi == len(todo):
            log(f"  CSDN [{qi}/{len(todo)}] '{q}' +{add}（累计 {len(out)}）")
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False)
        time.sleep(0.8)
    st["csdn_done"] = True
    save_state(st)
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
    log(f"CSDN 完成：{len(out)} 篇")


# ==========================================================================
# 2. 安全客（全站分页）
# ==========================================================================
AQK_SKIP_SLUG = {"activity", "job", "recruitment"}


def harvest_anquanke(st):
    fp = os.path.join(CN_DIR, "anquanke.json")
    if st.get("aqk_done"):
        log("安全客 已完成，跳过")
        return
    out, seen = [], set()
    if os.path.isfile(fp):
        with open(fp, "r", encoding="utf-8") as f:
            out = json.load(f)
        seen = {r["id"] for r in out}
        log(f"安全客 断点续跑：已有 {len(out)} 篇")
    page = int(st.get("aqk_page", 1))
    empty = 0
    while page <= AQK_CAP_PAGES:
        url = f"https://api.anquanke.com/data/v1/posts?size=50&page={page}"
        try:
            d = X.get_json(url, tries=3)
        except Exception as e:  # noqa: BLE001
            log(f"  安全客 p{page} 失败: {str(e)[:60]}，等待重试")
            time.sleep(6)
            try:
                d = X.get_json(url, tries=2)
            except Exception:  # noqa: BLE001
                break
        items = d.get("data") or []
        if not items:
            empty += 1
            if empty >= 2:
                break
        else:
            empty = 0
        add = 0
        for it in items:
            slug = it.get("category_slug") or ""
            if slug in AQK_SKIP_SLUG:
                continue
            rid = "AQK:" + str(it.get("id"))
            if rid in seen:
                continue
            title = " ".join((it.get("title") or "").split())
            if len(title) < 8:
                continue
            tags = [t for t in (it.get("tags") or []) if t][:6]
            blob = title + " " + " ".join(tags)
            if not X.CSDN_GATE.search(blob):
                continue
            seen.add(rid)
            cat_name = it.get("category_name") or "安全资讯"
            desc = title + "。" + (f"分类：{cat_name}。" if cat_name else "") + \
                   (("标签：" + "、".join(tags) + "。") if tags else "") + \
                   (it.get("desc") or "")
            rec = X._skeleton(
                rid=rid, rtype="article", kind=f"安全客{cat_name}",
                title=title, desc=desc,
                published=(it.get("date") or "")[:10], sources=["安全客"],
                category=X._guess_category(blob),
                reason=f"中文安全社区文章（安全客 · {cat_name}）",
                tags=["社区文章"] + tags[:3],
            )
            rec["author"] = (it.get("author") or {}).get("nickname") or ""
            rec["views"] = it.get("pv") or 0
            rec["article_url"] = f"https://www.anquanke.com/post/id/{it.get('id')}"
            rec["advisory_links"] = [rec["article_url"]]
            out.append(rec)
            add += 1
        if page % 20 == 0 or add:
            log(f"  安全客 p{page} +{add}（累计 {len(out)}）")
        if page % 20 == 0:
            st["aqk_page"] = page + 1
            save_state(st)
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False)
        page += 1
        time.sleep(0.4)
    st["aqk_page"] = page
    st["aqk_done"] = True
    save_state(st)
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
    log(f"安全客 完成：{len(out)} 篇")


# ==========================================================================
# 3. 先知社区（含官方摘要）
# ==========================================================================
def harvest_xz(st):
    fp = os.path.join(CN_DIR, "xz.json")
    if st.get("xz_done"):
        log("先知 已完成，跳过")
        return
    out, seen = [], set()
    if os.path.isfile(fp):
        with open(fp, "r", encoding="utf-8") as f:
            out = json.load(f)
        seen = {r["id"] for r in out}
        log(f"先知 断点续跑：已有 {len(out)} 篇")
    page = int(st.get("xz_page", 1))
    empty = 0
    while page <= XZ_CAP_PAGES:
        url = f"https://xz.aliyun.com/api/v2/news?page={page}"
        try:
            items = X.get_json(url, tries=3)
        except Exception as e:  # noqa: BLE001
            log(f"  先知 p{page} 失败: {str(e)[:60]}，等待重试")
            time.sleep(6)
            try:
                items = X.get_json(url, tries=2)
            except Exception:  # noqa: BLE001
                break
        if not isinstance(items, list) or not items:
            empty += 1
            if empty >= 2:
                break
            page += 1
            continue
        empty = 0
        add = 0
        for it in items:
            rid = "XZ:" + str(it.get("id"))
            if rid in seen:
                continue
            title = " ".join((it.get("title") or "").split())
            if len(title) < 6:
                continue
            subj = " ".join((it.get("subject") or "").split())[:800]
            blob = title + " " + subj
            if not X.CSDN_GATE.search(blob):
                continue
            seen.add(rid)
            rec = X._skeleton(
                rid=rid, rtype="article", kind="先知社区技术文章",
                title=title,
                desc=(title + "。" + subj).strip("。"),
                published=(it.get("created_at") or "")[:10], sources=["先知社区"],
                category=X._guess_category(blob),
                reason="中文安全社区深度技术文章（先知社区，含官方摘要）",
                tags=["社区文章", "深度分析"],
            )
            rec["author"] = it.get("author") or ""
            rec["views"] = it.get("hits") or 0
            rec["article_url"] = f"https://xz.aliyun.com/news/{it.get('id')}"
            rec["advisory_links"] = [rec["article_url"]]
            out.append(rec)
            add += 1
        if page % 25 == 0 or add:
            log(f"  先知 p{page} +{add}（累计 {len(out)}）")
        if page % 25 == 0:
            st["xz_page"] = page + 1
            save_state(st)
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False)
        page += 1
        time.sleep(0.5)
    st["xz_page"] = page
    st["xz_done"] = True
    save_state(st)
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
    log(f"先知 完成：{len(out)} 篇")


def due_for_rerun(st):
    """全量收割是否到期重跑。

    没有这层判定的话，_state.json 里 csdn_done / aqk_done / xz_done 一旦置成 true
    就永远是 true —— 脚本再跑只会各打印一行「已完成，跳过」，语料从此不再更新
    （表现为「社区文章停在几个月前」）。

    重跑是安全的：三个 harvest 函数都按 id / url 去重，重爬只会补进新增文章，
    不会重复入库。
    """
    if not all(st.get(k) for k in ("csdn_done", "aqk_done", "xz_done")):
        return True, "上次未跑完，继续断点续跑"
    last = str(st.get("last_done") or "")
    if not last:
        return True, "状态里没有上次完成日期，重跑一遍以补齐"
    try:
        days = (datetime.date.today() - datetime.date.fromisoformat(last[:10])).days
    except Exception:  # noqa: BLE001
        return True, "上次完成日期无法解析，重跑一遍"
    if days >= HARVEST_INTERVAL_DAYS:
        return True, f"距上次全量收割已 {days} 天（间隔 {HARVEST_INTERVAL_DAYS} 天）"
    return False, f"距上次全量收割仅 {days} 天，未到 {HARVEST_INTERVAL_DAYS} 天"


def main(force=False):
    t0 = time.time()
    st = load_state()
    due, why = (True, "--force 强制重跑") if force else due_for_rerun(st)
    if due:
        log(f"清理游标准备重爬：{why}")
        for k in ("csdn_done", "aqk_done", "xz_done",
                  "csdn_queries", "aqk_page", "xz_page"):
            st.pop(k, None)
        save_state(st)
    harvest_csdn(st)
    harvest_anquanke(st)
    harvest_xz(st)
    if all(st.get(k) for k in ("csdn_done", "aqk_done", "xz_done")):
        st["last_done"] = datetime.date.today().isoformat()
        save_state(st)
    log(f"全部完成，耗时 {round(time.time()-t0)}s")


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    main(force="--force" in sys.argv)
