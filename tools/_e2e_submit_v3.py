# 端到端自测：提交链接即时收录（v3.1，含并发稳定性 + 质量分类 + 双过滤验证）
# 覆盖：① 秒级收录 + feed 置顶可见 + 质量分级  ② 去重  ③ 非法链接 400
#       ④ 并发提交 + 15s 快车道轮询不崩（无 500）
#       ⑤ 「质量极差」过滤（重度广告软文不收录）
#       ⑥ 「过分相同」过滤（同正文不同链接 → 疑转载/雷同，不收录）
import json, threading, time, urllib.request, urllib.error, sys

BASE = "http://127.0.0.1:8848"
FAKE = "http://127.0.0.1:8892"   # 可控假文章服务器 v2：默认=优质安全文 / /spam=广告软文 / /dup_a·/dup_b=同正文雷同
RUN = int(time.time())
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 绕过代理，直连 127.0.0.1
_results = []

def post(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(BASE + url, data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with OPENER.open(req, timeout=60) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except Exception:
            body = {}
        return e.code, body
    except Exception as e:
        return -1, {"error": str(e)}

def get(path):
    req = urllib.request.Request(BASE + path)
    try:
        with OPENER.open(req, timeout=60) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}

def check(name, cond, extra=""):
    _results.append((name, cond, extra))
    print(("PASS " if cond else "FAIL ") + name + (("  :: " + extra) if extra else ""))

# ---------- ① 秒级收录 + 置顶 ----------
# t = 标题轮次 token：让本轮标题与上一轮残留区分开，否则「首次收录」会被自己
# 上一轮的数据判为 duplicate（脚本不幂等，非产品缺陷）。dup_a/dup_b 必须共用
# 同一 token，才能构造出「同正文不同链接」的近重对。
T = str(RUN)
u = f"{FAKE}/?r={RUN}_add&t={T}"
st, body = post("/api/m1/submit_article", {"url": u, "force": False})
check("submit fresh -> 200", st == 200, f"status={st} body={body}")
check("submit fresh -> ok & added", body.get("ok") is True and (body.get("added") or 0) >= 1,
      f"added={body.get('added')} id={body.get('id')}")
my_id = body.get("id")

st2, feed = get("/api/latest?n=8")
check("latest -> 200", st2 == 200, f"status={st2}")
items = (feed or {}).get("items", [])
ids = [it["id"] for it in items]
# 置顶不变量：所有 submitted 项必须排在非 submitted 项之前
sub_idx = [i for i, it in enumerate(items) if it.get("submitted")]
non_idx = [i for i, it in enumerate(items) if not it.get("submitted")]
pinned_ok = (not sub_idx) or (not non_idx) or (max(sub_idx) < min(non_idx))
check("feed 置顶不变量(投稿在前)", pinned_ok, f"sub_idx={sub_idx[:5]} non_idx={non_idx[:5]}")
check("我的投稿出现在 feed", my_id in ids, f"my_id={my_id} in={my_id in ids}")
if my_id in ids:
    pos = ids.index(my_id)
    it = items[pos]
    check("我的投稿 submitted=True", it.get("submitted") is True, f"pos={pos}")
    check("我的投稿位于置顶块内", (not sub_idx) or pos <= max(sub_idx), f"pos={pos} maxsub={max(sub_idx) if sub_idx else None}")

# ---------- ② 去重 ----------
# 同一 URL 二次提交必须被挡下。服务端统一用 {filtered:True, filter:"duplicate"}
# 表达（不存在 "duplicated" 字段），此前断言引用了不存在的字段导致恒定失败。
st3, body3 = post("/api/m1/submit_article", {"url": u, "force": False})
dup_hit = (body3.get("filtered") is True and body3.get("filter") == "duplicate") \
    or body3.get("duplicated") is True
check("重复提交 -> duplicate 拦截", st3 == 200 and dup_hit,
      f"status={st3} filter={body3.get('filter')} filtered={body3.get('filtered')}")

# ---------- ③ 非法链接 400 ----------
st4, body4 = post("/api/m1/submit_article", {"url": "ftp://example.com/x", "force": False})
check("非法链接 -> 400", st4 == 400, f"status={st4} body={body4}")
st5, body5 = post("/api/m1/submit_article", {"url": "not a url", "force": False})
check("空/乱码链接 -> 400", st5 == 400, f"status={st5}")

# ---------- ④ 并发稳定性：16 路并发提交 + 持续读 feed，跨越 15s 快车道轮询 ----------
print("\n--- 并发压力（16 路提交 + 读 feed，约 22s，跨越一次 15s 快车道轮询）---")
lock = threading.Lock()
submit_codes = []
reader_errors = []

def worker(i):
    uu = f"{FAKE}/?r={RUN}_b{i}&t={T}_{i}"
    s, b = post("/api/m1/submit_article", {"url": uu, "force": False})
    with lock:
        submit_codes.append((i, s, b.get("duplicated", False)))

def reader():
    for _ in range(44):  # ~22s @ 0.5s
        s, _ = get("/api/latest?n=20")
        if s not in (200,):
            with lock:
                reader_errors.append(s)
        time.sleep(0.5)

threads = []
t0 = time.time()
rd = threading.Thread(target=reader, daemon=True); rd.start()
for i in range(16):
    t = threading.Thread(target=worker, args=(i,)); t.start(); threads.append(t)
    time.sleep(1.3)   # 拉长到 >15s，保证撞上至少一次快车道 apply_new_docs→add_documents
for t in threads:
    t.join()
rd.join()
elapsed = time.time() - t0

with lock:
    five_hundreds = [c for c in submit_codes if c[1] == 500]
    non_http = [c for c in submit_codes if c[1] < 0]
    ok_or_dup = [c for c in submit_codes if c[1] == 200]
check("并发提交无 500", len(five_hundreds) == 0, f"500s={five_hundreds}")
check("并发提交无异常(<0)", len(non_http) == 0, f"errs={non_http}")
check("并发提交全部 200(含去重)", len(ok_or_dup) == 16, f"ok={len(ok_or_dup)} codes={submit_codes}")
check("并发读 feed 无 500", len(reader_errors) == 0, f"reader_errs={reader_errors}")
check("压力时长跨越 15s 轮询", elapsed > 15, f"elapsed={elapsed:.1f}s")

# ---------- ⑤ 质量过滤：重度广告软文应被「质量极差」过滤、不收录 ----------
u_spam = f"{FAKE}/spam?r={RUN}_spam"
st6, body6 = post("/api/m1/submit_article", {"url": u_spam, "force": False})
check("广告软文 -> 200", st6 == 200, f"status={st6} body={body6}")
check("广告软文 -> filtered:quality", body6.get("filtered") is True and body6.get("filter") == "quality",
      f"filter={body6.get('filter')} quality={body6.get('quality')}")
q6 = body6.get("quality") or {}
check("广告软文 -> extremely_poor=True", q6.get("extremely_poor") is True, f"quality={q6}")
check("广告软文 -> 分级=差", q6.get("tier") == "差", f"tier={q6.get('tier')}")
# 未被收录：feed 里不应出现该链接
st6b, feed6 = get("/api/latest?n=50")
items6 = (feed6 or {}).get("items", [])
check("广告软文未进入 feed", not any((it.get("link") or "") == u_spam for it in items6),
      f"link_in_feed={[it.get('link') for it in items6 if (it.get('link') or '').endswith('_spam')]}")

# ---------- ⑥ 过分相同过滤：dup_a 收录，dup_b（同正文不同链接）应被「过分相同」过滤 ----------
u_dupa = f"{FAKE}/dup_a?r={RUN}_dupa&t={T}_dup"
st7, body7 = post("/api/m1/submit_article", {"url": u_dupa, "force": False})
check("dup_a -> 200", st7 == 200, f"status={st7} body={body7}")
check("dup_a -> 正常收录(ok & added)", body7.get("ok") is True and (body7.get("added") or 0) >= 1,
      f"added={body7.get('added')} filtered={body7.get('filtered')}")
check("dup_a -> 带质量分级", (body7.get("quality") or {}).get("tier") in ("优", "良", "中", "差"),
      f"tier={(body7.get('quality') or {}).get('tier')}")

u_dupb = f"{FAKE}/dup_b?r={RUN}_dupb&t={T}_dup"
st8, body8 = post("/api/m1/submit_article", {"url": u_dupb, "force": False})
check("dup_b -> 200", st8 == 200, f"status={st8} body={body8}")
check("dup_b -> filtered:duplicate", body8.get("filtered") is True and body8.get("filter") == "duplicate",
      f"filter={body8.get('filter')} similar={body8.get('similar')}")
sim8 = body8.get("similar") or {}
check("dup_b -> 包含率/标题相似 触发阈值",
      (sim8.get("content_containment") or 0) >= 0.6 or (sim8.get("title_sim") or 0) >= 0.9,
      f"similar={sim8}")
# dup_b 未被收录
st8b, feed8 = get("/api/latest?n=50")
items8 = (feed8 or {}).get("items", [])
check("dup_b 未进入 feed", not any((it.get("link") or "") == u_dupb for it in items8),
      f"dupb_in_feed={[it.get('link') for it in items8 if (it.get('link') or '').endswith('_dupb')]}")

# ---------- 收尾：清掉本轮写进真实库的测试稿 ----------
# e2e 直接跑在真实 data 目录上，不清理的话这些投稿会留在 live_feed.jsonl 里；
# 下次启动「回放最新情报」会把它们加载到 feed 顶部并置顶，表现为
# 「实时监测台的最新情报全是某个月的测试文章」——真实情报被压在下面。
# 识别依据：链接指向本机假服务器（127.0.0.1）。
def _cleanup():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    n_feed = n_sub = 0
    fp = os.path.join(root, "data", "live_feed.jsonl")
    if os.path.isfile(fp):
        keep = []
        with open(fp, "r", encoding="utf-8") as f:
            for ln in f:
                s = ln.strip()
                if not s:
                    continue
                try:
                    r = json.loads(s)
                except Exception:  # noqa: BLE001
                    keep.append(s)
                    continue
                if "127.0.0.1" in (r.get("link") or ""):
                    n_feed += 1
                    continue
                keep.append(s)
        if n_feed:
            with open(fp, "w", encoding="utf-8") as f:
                for s in keep:
                    f.write(s + "\n")
    sp = os.path.join(root, "data", "cn", "submitted.json")
    if os.path.isfile(sp):
        try:
            with open(sp, "r", encoding="utf-8") as f:
                cur = json.load(f)
            kept = [x for x in cur
                    if "127.0.0.1" not in ((x.get("link") or x.get("url") or ""))]
            n_sub = len(cur) - len(kept)
            if n_sub:
                tmp = sp + ".clean.tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(kept, f, ensure_ascii=False)
                os.replace(tmp, sp)
        except Exception:  # noqa: BLE001 —— 清理失败不该把测试判成失败
            pass
    return n_feed, n_sub


_cf, _cs = _cleanup()
print(f"[cleanup] 已清除本轮测试稿：live_feed {_cf} 条 / submitted {_cs} 条"
      f"（服务内存里的副本会在下次重启时消失）")

# 汇总
fails = [r for r in _results if not r[1]]
print("\n================ 结果 ================")
print(f"总计 {len(_results)} 项，通过 {len(_results)-len(fails)}，失败 {len(fails)}")
if fails:
    for n, _, e in fails:
        print("  ✗", n, e)
    sys.exit(1)
print("E2E SUBMIT OK —— 提交链接即时收录功能全绿")
