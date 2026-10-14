# -*- coding: utf-8 -*-
"""
_test_live_atom_content.py —— Atom `<content>` 正文提取回归（2026-10-08）
====================================================================
现象：实时监测里"Ollama 版本发布 / vLLM 版本发布"两条源，点开检查器"几乎没有信息"。

根因：GitHub `releases.atom` 把发布说明放在 `<content type="html">` 里，而
      `_rss_items` 的正文正则只认 `description|summary|content:encoded`
      —— 实测缓存快照里 `<content>` 有 8529 字符正文，那三个标签全是 0 匹配，
      正文被整段丢弃，`desc` 退化成标题（"v0.40.1"，7 个字）。

断言：
  A. 用真实缓存快照跑 `_rss_items`，每条都必须拿到非空且足够长的正文
  B. 同一快照里 RSS 的 `description` 通道没被这次改动破坏（防顾此失彼）
  C. 静态：正文正则里 `content:encoded` 必须排在 `content` 之前
     （否则会先匹配 `<content` 再找 `</content>`，遇到 `</content:encoded>` 失配）
  D. 数据级：live_feed.jsonl 里不再有"desc 与 title 完全相同"的资讯条目
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m1_monitor", "backend"))

PASS = FAIL = 0


def ok(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [OK] %s" % msg)
    else:
        FAIL += 1
        print("  [!!] %s" % msg)


import live as L  # noqa: E402

CACHE = L.CACHE_DIR
SNAPS = ["Ollama_____.xml", "vLLM_____.xml"]

print("=== A/B. 真实缓存快照：Atom <content> 必须能取出正文 ===")
for fn in SNAPS:
    fp = os.path.join(CACHE, fn)
    if not os.path.isfile(fp):
        ok(False, "缺少快照 %s（先跑一轮采集才有）" % fn)
        continue
    xml = io.open(fp, encoding="utf-8", errors="replace").read()
    # 快照里必须真的有 <content>，否则这条断言没有意义
    n_content = len(re.findall(r"<content[^>]*>", xml))
    items = L._rss_items(xml, "测试源")
    rich = [it for it in items if len(it.get("summary") or "") >= 40]
    empty = [it for it in items if not (it.get("summary") or "").strip()]
    ok(n_content > 0, "%s 快照含 %d 个 <content>（前提成立）" % (fn, n_content))
    ok(bool(items), "%s 解析出 %d 条" % (fn, len(items)))
    # 不要求每条都 ≥40 字：真实发布说明长度差异极大（proto/rc 预发布常常只有一行），
    # 但**绝不允许为空** —— 空正文正是这次 bug 的症状（desc 退化成标题）。
    ok(not empty, "%s 无空正文条目（空 %d / 共 %d）" % (fn, len(empty), len(items)))
    for t in [it["title"][:30] for it in empty][:3]:
        print("      正文为空: %s" % t)
    ok(len(rich) >= len(items) * 0.9,
       "%s 正文 ≥40 字占 %d/%d（≥90%%，个别 rc/proto 预发布天然很短）"
       % (fn, len(rich), len(items)))
    thin = [it["title"][:30] for it in items if 0 < len(it.get("summary") or "") < 40]
    for t in thin[:3]:
        print("      正文偏短(合法): %s" % t)
    if items:
        s = items[0].get("summary") or ""
        ok("<" not in s and ">" not in s, "正文已剥 HTML 标签（首条 %d 字）" % len(s))

print("\n=== C. 静态：content:encoded 必须排在 content 之前 ===")
src = io.open(os.path.join(ROOT, "modules", "m1_monitor", "backend", "live.py"),
              encoding="utf-8").read()
i = src.find("def _rss_items(")
seg = src[i: src.find("\ndef ", i + 1)]
m = re.search(r"description\|summary\|([\w:]+)\|content", seg)
ok(bool(m), "正则在 _rss_items 内且含 content 分支")
if m:
    ok(m.group(1) == "content:encoded",
       "content:encoded 排在 content 之前（实际顺序: …|%s|content）" % m.group(1))

print("\n=== D. 数据级：快照里有正文却没落库的条目必须为 0 ===")
# 诚实边界：实测约 15% 的实时条目其**源 feed 本身只有标题、没有正文**
# （Google DeepMind 等博客的 <item> 里根本没有 <description>）。
# 这类条目任何代码都变不出正文 —— 不能拿标题冒充正文，也不该在断言里假装它们
# 是 bug。所以这里断言的是**可修未修**：快照里明明有正文，库里却是空的。
feed = L.FEED_FP
cache_dir = L.CACHE_DIR
if os.path.isfile(feed) and os.path.isdir(cache_dir):
    import glob
    import json
    snap = {}
    for fp in glob.glob(os.path.join(cache_dir, "*.xml")):
        try:
            x = io.open(fp, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        try:
            for it in L._rss_items(x, os.path.basename(fp)):
                s = (it.get("summary") or "").strip()
                if it.get("link") and len(s) >= 40:
                    snap[it["link"]] = s
        except Exception:  # noqa: BLE001
            continue
    thin = fixable = no_source_body = 0
    bad = []
    with io.open(feed, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            t = str(r.get("title") or "").strip()
            d = str(r.get("desc") or "").strip()
            if not t or not (d == t or len(d) < 40):
                continue
            thin += 1
            if len(snap.get(r.get("link") or "") or "") > len(d):
                fixable += 1
                if len(bad) < 5:
                    bad.append("%s | %s | 库内 %d 字" % (r.get("id", "")[:34], t[:26], len(d)))
            else:
                no_source_body += 1
    ok(fixable == 0,
       "可回填却未回填 = %d 条（应为 0）；正文过薄共 %d 条，其中 %d 条源本身无正文"
       % (fixable, thin, no_source_body))
    for b in bad:
        print("      %s" % b)
else:
    ok(False, "缺少 live_feed.jsonl 或缓存快照目录")

print("\n=== 结果：%d 通过 / %d 失败 ===" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)