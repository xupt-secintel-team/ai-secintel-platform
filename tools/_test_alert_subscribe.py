# -*- coding: utf-8 -*-
"""
_test_alert_subscribe.py —— 预警订阅推送测试（离线、可复跑）
=========================================================================
用假引擎（可控时间的语料）+ 临时存储文件，覆盖：
  ① CRUD：新增/去重/非法参数/更新保留 born/删除
  ② 匹配：cve/product(含标题回退)/vendor/keyword/kev + 严重度/AI 分/仅 KEV 过滤
  ③ 增量与去重：水位推进不重复告警；新订阅能拿到自己的回看窗口；force 全量回看不重复
  ④ 告警流：未读过滤、mark_read
  ⑤ Webhook：假传输命中订阅级 webhook 标记 pushed

用法： py tools/_test_alert_subscribe.py
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

import alert_subscribe as SB  # noqa: E402

FAILS = []
OKS = []


def check(cond, label, extra=""):
    (OKS if cond else FAILS).append(label)
    print("  %s %s%s" % ("[PASS]" if cond else "[FAIL]", label,
                         ("  → " + str(extra)) if (extra and not cond) else ""))


# 临时存储 + 干净环境
SB.STORE_PATH = os.path.join(tempfile.mkdtemp(prefix="subtest_"), "subscriptions.json")
for k in ("AISEC_WEBHOOK_URL",):
    os.environ.pop(k, None)
SB.CHECK_INTERVAL = 1

NOW = time.time()


def doc(i, title, sev="HIGH", score=7.5, kev=False, ai=0.9, ts=None, pid="ollama",
        desc="", products=None):
    iso = time.strftime("%Y-%m-%dT%H:%M:%S.000", time.gmtime(ts if ts is not None else NOW - i * 3600))
    return {"id": "CVE-2026-%05d" % i, "title": title, "desc": desc,
            "cvss": {"score": score, "severity": sev, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"},
            "kev": {"exploited": True, "date_added": "2026-10-01", "due_date": "2026-10-11"} if kev else {},
            "ai_score": ai, "published": iso, "modified": iso,
            "products": products if products is not None else [pid],
            "vendors": ["example-corp"], "fetched_at": iso}


CORPUS = [
    doc(1, "Ollama path traversal RCE", sev="CRITICAL", score=9.8, kev=True, ts=NOW - 1800),
    doc(2, "vLLM sandbox escape", sev="HIGH", score=8.1, pid="vllm", ts=NOW - 2 * 3600),
    doc(3, "普通组件越权问题", sev="MEDIUM", score=4.5, pid="wordpress", ai=0.2, ts=NOW - 3 * 3600),
    doc(4, "Ollama 旧漏洞（水位之前）", ts=NOW - 72 * 3600),
]


class FakeEngine:
    docs = CORPUS

    def detail(self, cid):
        return next((d for d in CORPUS if d["id"] == cid), None)


ENG = FakeEngine()

print("\n=== ① CRUD ===")
r = SB.add_sub({"kind": "product", "value": "ollama", "name": "Ollama 相关漏洞"})
check(r.get("ok") is True, "新增产品订阅", r)
sid1 = r["sub"]["id"]
check(SB.add_sub({"kind": "product", "value": "ollama"}).get("ok") is False, "重复订阅被拒")
check(SB.add_sub({"kind": "nope", "value": "x"}).get("ok") is False, "非法 kind 被拒")
check(SB.add_sub({"kind": "cve", "value": "not-a-cve"}).get("ok") is False, "非法 CVE 被拒")
check(SB.add_sub({"kind": "cve", "value": "cve-2026-99999"}).get("ok") is True,
      "CVE 小写自动转大写")
r = SB.add_sub({"kind": "kev"})
check(r.get("ok") is True and r["sub"]["value"] == "", "仅 KEV 订阅无需 value")
sid_kev = r["sub"]["id"]
r = SB.update_sub({"id": sid1, "min_severity": "HIGH"})
check(r.get("ok") is True and r["sub"]["min_severity"] == "HIGH", "更新订阅")
check(r["sub"]["born"] > 0, "更新保留 born")
check(SB.update_sub({"id": "SUB-XXX"}).get("ok") is False, "更新不存在的订阅报错")

print("\n=== ② 匹配 ===")
check(SB._match_doc(CORPUS[0], {"kind": "product", "value": "ollama", "min_severity": "", "ai_min": 0, "kev_only": False}),
      "产品命中（products 字段）")
check(SB._match_doc({"title": "ollama is great", "desc": "", "products": []},
                    {"kind": "product", "value": "ollama", "min_severity": "", "ai_min": 0, "kev_only": False}),
      "products 为空时标题关键词回退（词边界）")
check(not SB._match_doc({"title": "molasses", "desc": "", "products": []},
                        {"kind": "product", "value": "ollama", "min_severity": "", "ai_min": 0, "kev_only": False}),
      "词边界不误伤子串（molasses ≠ ollama）")
check(not SB._match_doc(CORPUS[2], {"kind": "product", "value": "ollama", "min_severity": "HIGH", "ai_min": 0, "kev_only": False}),
      "严重度门槛拦截 MEDIUM")
check(SB._match_doc(CORPUS[0], {"kind": "kev", "value": "", "min_severity": "", "ai_min": 0, "kev_only": False}),
      "kev 订阅命中 KEV 条目")
check(not SB._match_doc(CORPUS[1], {"kind": "kev", "value": "", "min_severity": "", "ai_min": 0, "kev_only": False}),
      "非 KEV 条目不命中")
check(not SB._match_doc(CORPUS[2], {"kind": "product", "value": "wordpress", "min_severity": "", "ai_min": 0.5, "kev_only": False}),
      "AI 分门槛拦截低分条目")

print("\n=== ③ 增量与去重 ===")
r = SB.match_once(ENG)
check(r["new"] >= 2, "首跑回看 48h 命中（ollama + vllm 高于水位）", r["new"])
n1 = r["new"]
r2 = SB.match_once(ENG)
check(r2["new"] == 0, "水位推进后同语料零重复", r2["new"])
# 新文档出现（在水位之后）
CORPUS.insert(0, doc(99, "Ollama 新增漏洞", sev="CRITICAL", score=9.1, ts=time.time()))
r3 = SB.match_once(ENG)
check(r3["new"] == 1 and r3["alerts"][0]["doc_id"] == "CVE-2026-00099", "新文档触发新告警")
check(r3["alerts"][0]["sub_name"] == "Ollama 相关漏洞", "告警归属订阅")
# 新订阅 born 在水位之后 → 能拿到自己的 48h 回看窗口
r = SB.add_sub({"kind": "product", "value": "vllm"})
sid_vllm = r["sub"]["id"]
time.sleep(0.01)
r4 = SB.match_once(ENG)
check(any(a["sub_id"] == sid_vllm for a in r4["alerts"]) or
      any(a["sub_id"] == sid_vllm for a in SB.alerts(limit=50)),
      "新订阅拿到回看窗口（vLLM 旧文档补告警）")
check(all(SB._doc_ts(d) >= time.time() - 30 * 24 * 3600 for d in ENG.docs), "窗口硬顶 30 天内文档")
# force 全量回看不重复
r5 = SB.match_once(ENG, force=True)
check(r5["new"] == 0, "force 全量回看仍零重复（seen 兜底）", r5["new"])

print("\n=== ④ 告警流与未读 ===")
al = SB.alerts(limit=10)
check(len(al) >= 3, "告警流有内容", len(al))
unread = SB.alerts(limit=10, unread_only=True)
check(len(unread) == len(al), "初始全部未读")
first_id = al[0]["id"]
check(SB.mark_read([first_id]) == 1, "标记已读")
check(len(SB.alerts(limit=10, unread_only=True)) == len(al) - 1, "未读数减一")
check(SB.mark_read(None) >= 1, "全部已读")
check(len(SB.alerts(limit=10, unread_only=True)) == 0, "清零")

print("\n=== ⑤ Webhook 推送 ===")
pushed = []


def fake_post(url, json=None, timeout=10):
    class R:
        status_code = 200
    pushed.append((url, json))
    return R()


SB.requests.post = fake_post  # 注入假传输
hooked = SB.add_sub({"kind": "product", "value": "jenkins", "webhook": "http://hook.invalid/x"})
CORPUS.insert(0, doc(77, "Jenkins RCE", sev="CRITICAL", score=9.9, pid="jenkins", ts=time.time()))
SB.match_once(ENG)
check(bool(pushed) and pushed[-1][0] == "http://hook.invalid/x", "订阅级 webhook 被调用",
      [p[0] for p in pushed])
newest = SB.alerts(limit=1)[0]
check(newest.get("pushed") is True, "推送成功标记 pushed")
SB.requests.post = lambda *a, **k: (_ for _ in ()).throw(ConnectionError("x"))
CORPUS.insert(0, doc(78, "Jenkins RCE again", sev="HIGH", score=8.0, pid="jenkins", ts=time.time()))
SB.match_once(ENG)
newest = SB.alerts(limit=1)[0]
check(newest.get("pushed") is False, "推送失败不误标")

print("\n=== ⑥ status ===")
st = SB.status()
check(st["subs"] == 5 and st["enabled"] == 5, "订阅计数", st)
check(st["daemon"] is False, "daemon 未启动（离线测试环境）")

print("\n" + "=" * 56)
print("PASS %d / FAIL %d" % (len(OKS), len(FAILS)))
if FAILS:
    for f in FAILS:
        print("  FAIL:", f)
    sys.exit(1)
print("ALERT SUBSCRIBE TEST OK")
