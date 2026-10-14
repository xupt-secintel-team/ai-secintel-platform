# -*- coding: utf-8 -*-
"""提交链接即时收录 · 回归测试（不依赖外网，mock http_get）

覆盖：
  · 平台识别（安全客/先知/CSDN/其他）
  · 原生 id 解析（CSDN / 安全客 / 先知 与自动采集去重）
  · HTML 正文/标题/日期/作者解析
  · 相关性软判定（通用安全 → high，无关 → low 仍收录）
  · 落盘 data/cn（含去重，同链接不重复写）
"""
import sys, os, json, tempfile, types

# 避免 live 顶层重依赖：先塞一个假的 monitor 模块
_mon = types.ModuleType("monitor")
_mon.fetch_nvd_window = lambda *a, **k: None
sys.modules.setdefault("monitor", _mon)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "modules", "m1_monitor", "backend"))
sys.path.insert(0, os.path.join(ROOT, "core"))

import live as L  # noqa: E402
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

# 临时 data/cn 目录，避免污染真实语料
TMP = tempfile.mkdtemp(prefix="cn_submit_test_")
L.CN_DIR = TMP

HTML_SEC = """<html><head>
<meta property="og:title" content="SQL注入实战与防御">
<meta property="article:published_time" content="2026-09-30T10:00:00Z">
<meta name="author" content="Lolcat">
</head><body>
<h1>SQL注入实战与防御</h1>
<p>本文讲解 SQL 注入的原理、常见 payload 与防护方案，包含 WAF 绕过与预编译实践。</p>
<p>关键词：sql注入、xss、命令执行、护网。</p>
</body></html>"""

HTML_FOOD = "<html><head><title>做草莓蛋糕</title></head><body>" \
            "<h1>做草莓蛋糕</h1><p>今天教大家做草莓蛋糕，步骤很简单。</p></body></html>"


def _run():
    # 1) 平台识别
    assert L._plat_of("https://www.anquanke.com/post/id/999")[0] == "anquanke"
    assert L._plat_of("https://xz.aliyun.com/article/id/77")[0] == "xz"
    assert L._plat_of("https://blog.csdn.net/u/article/details/555")[0] == "csdn"
    assert L._plat_of("https://blog.example.com/p/1")[0] == "other"
    # 原生 id 去重（与自动采集 src_csdn_authors 同口径）
    assert L._submit_rid("https://blog.csdn.net/u/article/details/555", "csdn") == "CSDN:555"
    assert L._submit_rid("https://www.anquanke.com/post/id/999", "anquanke") == "AQK:999"
    assert L._submit_rid("https://xz.aliyun.com/article/id/77", "xz") == "XZ:77"
    assert L._submit_rid("https://blog.example.com/p/1", "other").startswith("SUB:")

    # 2) 安全文章：解析 + 高相关性 + 落盘
    L.http_get = lambda url, **kw: HTML_SEC.encode("utf-8")
    url = "https://blog.example.com/p/12345"
    rec, info = L.submit_article(url)
    assert rec["id"].startswith("SUB:"), rec["id"]
    assert rec["title"] == "SQL注入实战与防御", rec["title"]
    assert rec["link"] == url
    assert rec["published"] == "2026-09-30", rec["published"]
    assert rec["author"] == "Lolcat"
    assert rec["relevance"] == "high", info          # CSDN_GATE 命中 sql注入
    assert "用户投稿" in rec["tags"]
    assert info["source"] == "其他平台"

    files = os.listdir(TMP)
    assert "submitted.json" in files, files
    with open(os.path.join(TMP, "submitted.json"), encoding="utf-8") as f:
        data = json.load(f)
    assert any(x["id"] == rec["id"] for x in data), "未落盘"

    # 3) 去重：同链接再提交不重复写
    L.submit_article(url)
    with open(os.path.join(TMP, "submitted.json"), encoding="utf-8") as f:
        data2 = json.load(f)
    assert len([x for x in data2 if x["id"] == rec["id"]]) == 1, "重复落盘"

    # 4) 低相关性（非安全内容）：仍收录，但标 low
    L.http_get = lambda url, **kw: HTML_FOOD.encode("utf-8")
    rec3, info3 = L.submit_article("https://food.blog/x/1")
    assert rec3["relevance"] == "low", info3

    # 5) 非法链接报错
    try:
        L.submit_article("not-a-url")
        raise AssertionError("应拒绝非法链接")
    except ValueError as _sw_e:
        _swallow("tools/_test_submit.py:89", _sw_e)

    # 6) 质量分类：安全文章应给出合法分级且非质量极差
    q = rec.get("quality") or {}
    assert q.get("tier") in ("优", "良", "中", "差"), q
    assert q.get("extremely_poor") is False, q
    assert "score" in q and "signals" in q, q

    # 7) persist=False 不应落盘（api 层用于「先过滤后落盘」）
    with open(os.path.join(TMP, "submitted.json"), encoding="utf-8") as f:
        before = len(json.load(f))
    L.submit_article("https://blog.example.com/p/no-persist", persist=False)
    with open(os.path.join(TMP, "submitted.json"), encoding="utf-8") as f:
        after = len(json.load(f))
    assert after == before, "persist=False 不应落盘 (%d->%d)" % (before, after)

    # 8) 质量极差（重度广告）：extremely_poor=True 且分级 差
    L.http_get = lambda url, **kw: ("<html><head><title>优惠</title></head><body>"
        "<h1>优惠</h1><p>扫码加微信领优惠券，加好友免费领取，推广返利。</p></body></html>").encode("utf-8")
    rec_poor, info_poor = L.submit_article("https://spam.blog/x/9")
    assert rec_poor["quality"]["extremely_poor"] is True, rec_poor["quality"]
    assert rec_poor["quality"]["tier"] == "差", rec_poor["quality"]

    print("TEST SUBMIT OK")


if __name__ == "__main__":
    _run()
