# -*- coding: utf-8 -*-
"""② POC **覆盖率**对比（离线武器化源 vs 完整源）

「评测POC.py」回答的是「排序好不好」（precision@k）；本脚本回答的是「**能拿到多少货**」（覆盖）：

  1. CVE 级覆盖 —— 有结果的 CVE / 取样 CVE
  2. 条数覆盖 —— 抓到的候选总数、来源种类
  3. 真 POC 覆盖 —— 判据命中的真利用材料条数（性能天花板在这里，不在排序）
  4. 武器化库覆盖 —— 相对**本地已知真值**（`data/exploitdb_files.csv` 的 Exploit-DB 条目、
     `data/metasploit_modules_metadata.json` 的模块）覆盖到多少条

两条模式对应「有没有 GitHub 凭据」这件事本身：
  · `quick=1` 离线武器化源（无需 Token，恒可用）
  · `quick=0` 完整源（含 GitHub 仓库搜索 + 代码抓取，**需要 `AISEC_GITHUB_TOKEN`**）

判据**直接复用** `评测POC.py` 的 `judge()` / `products_of()` —— 同一把尺子，避免自证。

用法：
  py -3 tools/评测POC覆盖率.py                       # 默认 6 个经典 CVE，两种模式都跑
  py -3 tools/评测POC覆盖率.py --cves CVE-2021-44228  # 单个 CVE（先小样验证）
  py -3 tools/评测POC覆盖率.py --reuse               # 不重新抓，用现有 JSON 重出报告
"""
import argparse
import csv
import importlib.util
import json
import os
import re
import sys
import time
import urllib.parse

BASE = (os.environ.get("AISEC_EVAL_BASE") or os.environ.get("AISEC_MAIN_SERVER")
        or "http://127.0.0.1:8848")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 本机回环强制不走系统代理（设过 HTTP_PROXY 的机器上会 502，症状像"服务坏了"）
try:
    sys.path.insert(0, os.path.join(ROOT, "core"))
    import loopback
    loopback.enable()
except Exception:  # noqa: BLE001
    pass
OUT_MD = os.path.join(ROOT, "测试报告", "POC覆盖率对比.md")
OUT_JSON = os.path.join(ROOT, "测试报告", "POC覆盖率对比.json")
DATA_DIR = os.path.join(ROOT, "data")

CURATED_SOURCES = {"metasploit", "nuclei-templates", "exploit-db", "packetstorm"}


def load_ruler():
    """复用「评测POC.py」的判据（文件名含中文，用 spec_from_file_location 加载）。"""
    path = os.path.join(ROOT, "tools", "评测POC.py")
    spec = importlib.util.spec_from_file_location("poc_eval_ruler", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RULER = load_ruler()


# ---------------------------------------------------------------- 本地真值（分母）
def truth_counts():
    """本地已知的武器化条目：CVE -> {'exploitdb': n, 'metasploit': n}。"""
    truth = {}

    def bump(cve, key):
        truth.setdefault(cve.upper(), {"exploitdb": 0, "metasploit": 0})[key] += 1

    csv_path = os.path.join(DATA_DIR, "exploitdb_files.csv")
    if os.path.isfile(csv_path):
        with open(csv_path, encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                for cve in set(re.findall(r"CVE-\d{4}-\d{4,7}", row.get("codes") or "", re.I)):
                    bump(cve, "exploitdb")

    msf_path = os.path.join(DATA_DIR, "metasploit_modules_metadata.json")
    if os.path.isfile(msf_path):
        with open(msf_path, encoding="utf-8", errors="replace") as f:
            mods = json.load(f)
        items = mods.values() if isinstance(mods, dict) else mods
        for m in items:
            text = " ".join(str(v) for v in (m or {}).values()) if isinstance(m, dict) else str(m)
            for cve in set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)):
                bump(cve, "metasploit")
    return truth


# ---------------------------------------------------------------- 抓取
def http_json(url, payload=None, timeout=180):
    import urllib.request
    req = urllib.request.Request(url, method="POST" if payload is not None else "GET")
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode()
        req.add_header("Content-Type", "application/json; charset=utf-8")
    with urllib.request.urlopen(req, data=data, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _as_bool(v):
    return str(v).lower() not in ("0", "false", "", "none")


def run_one(cve, quick, wait_s=600):
    """触发一次 POC 搜索并等它跑完。

    **必须带 `force=1`**：服务端默认对「已完成的 CVE」直接返回缓存而不重抓，
    那样两种模式会拿到同一批旧结果，覆盖率对比就完全失去意义（首版实测踩到：
    第二个模式 0.0s 返回、条数与第一个模式一模一样）。同时在完成后校验实际跑的模式，
    不一致就把这条标为 invalid，不参与统计。
    """
    q = "1" if quick else "0"
    trig = http_json(f"{BASE}/api/poc?id={urllib.parse.quote(cve)}&quick={q}&force=1", payload={"id": cve})
    t0 = time.time()
    st = {"error": "超时未完成", "results": []}
    while time.time() - t0 < wait_s:
        st = http_json(f"{BASE}/api/poc?id={urllib.parse.quote(cve)}")
        if st.get("done") and not st.get("running"):
            break
        time.sleep(5)
    st["_started"] = bool(trig.get("started"))
    st["_ran_quick"] = _as_bool(st.get("quick"))
    st["_want_quick"] = bool(quick)
    st["_invalid"] = (not st["_started"]) or (st["_ran_quick"] != st["_want_quick"])
    return st


def measure(cve, products, st):
    """把一次抓取结果折算成「覆盖」指标。"""
    rs = st.get("results") or []
    judge = lambda r: RULER.judge(r, cve, products)  # noqa: E731
    srcs = {}
    relevant = 0
    weaponized = 0
    for r in rs:
        s = str(r.get("source") or "?").lower()
        srcs[s] = srcs.get(s, 0) + 1
        if judge(r):
            relevant += 1
            if s in CURATED_SOURCES:
                weaponized += 1
    return {
        "n": len(rs),
        "relevant": relevant,
        "weaponized": weaponized,
        "sources": srcs,
        "tiers": st.get("tiers") or {},
        "error": st.get("error"),
        "invalid": bool(st.get("_invalid")),
        "warn": ("缓存命中/模式不符：本次未真正重跑" if st.get("_invalid") else ""),
        "titles": [r.get("title") or r.get("url") for r in rs],
    }


def main():
    global BASE          # 必须放函数第一行：后面 default=BASE 会先用到它
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--cves", default="CVE-2024-37032,CVE-2021-44228,CVE-2022-22965,"
                                     "CVE-2023-22515,CVE-2022-1388,CVE-2021-41773")
    ap.add_argument("--reuse", action="store_true", help="不重新抓取，用现有 JSON 重出报告")
    ap.add_argument("--out", default=OUT_MD)
    ap.add_argument("--json", default=OUT_JSON)
    args = ap.parse_args()
    BASE = args.base
    cves = [c.strip().upper() for c in args.cves.split(",") if c.strip()]

    if not args.reuse:
        # 先探活再干活：服务没起（或刚起、语料与向量库还在加载）时给人话提示，
        # 而不是甩一屏 ConnectionRefusedError traceback。
        try:
            http_json(BASE + "/api/qa/status", timeout=8)
        except Exception as e:
            print(f"[覆盖率] ✗ 连不上服务 {BASE} —— {type(e).__name__}: {e}")
            print("       请先启动服务：双击项目根目录 `启动服务.bat`，首屏要等约 2 分钟把语料/向量库加载完，")
            print("       看到 `[AI-SecIntel] 已就绪` 之后再重跑本脚本。")
            print("       服务不在默认端口时用 `--base http://127.0.0.1:<端口>`。")
            return 2

    if args.reuse:
        with open(args.json, encoding="utf-8") as f:
            old = json.load(f)
        rows = old.get("rows") or []
        print(f"[覆盖率] 复用 {args.json}（{len(rows)} 个 CVE，抓取时间 {old.get('at')}）")
    else:
        rows = []
        print(f"[覆盖率] 服务 {BASE}　CVE {len(cves)} 个　两种模式：离线武器化源 / 完整源（含 GitHub）")
        for cve in cves:
            products = RULER.products_of(cve)
            rec = {"cve": cve, "products": products}
            for label, quick in (("full", False), ("quick", True)):
                t0 = time.time()
                st = run_one(cve, quick)
                m = measure(cve, products, st)
                m["elapsed"] = round(time.time() - t0, 1)
                rec[label] = m
                print(f"  {cve:18s} [{'离线源' if quick else '完整源'}] 候选 {m['n']:3d} 条 · "
                      f"真 POC {m['relevant']:3d} 条 · 来源 {len(m['sources'])} 类 · {m['elapsed']}s"
                      + (f" · 错误={m['error']}" if m.get("error") else ""))
            rows.append(rec)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"at": time.strftime("%Y-%m-%d %H:%M:%S"), "base": BASE,
                       "cves": cves, "rows": rows}, f, ensure_ascii=False, indent=2)

    truth = truth_counts()

    def tot(scope, key):
        return sum((r.get(scope) or {}).get(key, 0) for r in rows)

    bad = [r["cve"] for r in rows
           if (r.get("full") or {}).get("invalid") or (r.get("quick") or {}).get("invalid")]
    ok_full = [r for r in rows if (r.get("full") or {}).get("n") and not (r.get("full") or {}).get("invalid")]
    ok_quick = [r for r in rows if (r.get("quick") or {}).get("n") and not (r.get("quick") or {}).get("invalid")]
    src_full = sorted({s for r in rows for s in ((r.get("full") or {}).get("sources") or {})})
    src_quick = sorted({s for r in rows for s in ((r.get("quick") or {}).get("sources") or {})})

    L = []
    A = L.append
    A("# POC 覆盖率对比（离线武器化源 vs 完整源）")
    A("")
    A(f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}　·　服务：{BASE}")
    A(f"- 样本：{len(rows)} 个 CVE（经典富 POC 集）"
      + ("　·　⚠️ 模式校验未通过（结果可能来自缓存，已剔除）：" + "、".join(bad) if bad
         else "　·　✅ 每条都带 `force=1` 真实重跑，且实际模式与请求一致"))
    A("- 两个模式差的就是「有没有 GitHub 凭据」：离线源无需 Token 恒可用；完整源含 GitHub 仓库搜索")
    A("  与代码抓取，**依赖 `AISEC_GITHUB_TOKEN`**（无 Token 时该路自动降级为离线源）。")
    A("")
    A("## 一、结论（同一批 CVE、同一套外部判据）")
    A("")
    A("| 覆盖指标 | 离线武器化源 | 完整源（含 GitHub） | 变化 |")
    A("|---|---|---|---|")
    A(f"| CVE 级覆盖（有结果的 CVE） | {len(ok_quick)}/{len(rows)} | **{len(ok_full)}/{len(rows)}** | "
      f"{len(ok_full) - len(ok_quick):+d} |")
    A(f"| 候选条数（抓到多少条） | {tot('quick', 'n')} | **{tot('full', 'n')}** | "
      f"{tot('full', 'n') - tot('quick', 'n'):+d} |")
    A(f"| **真 POC 条数**（判据命中） | {tot('quick', 'relevant')} | **{tot('full', 'relevant')}** | "
      f"{tot('full', 'relevant') - tot('quick', 'relevant'):+d} |")
    A(f"| 其中来自武器化源 | {tot('quick', 'weaponized')} | {tot('full', 'weaponized')} | "
      f"{tot('full', 'weaponized') - tot('quick', 'weaponized'):+d} |")
    A(f"| 来源种类数 | {len(src_quick)} | **{len(src_full)}** | {len(src_full) - len(src_quick):+d} |")
    A("")
    A(f"- 离线源来源：{'、'.join(src_quick) or '—'}")
    A(f"- 完整源来源：{'、'.join(src_full) or '—'}")
    A("")
    A("> 读法：**排序优化改的是「先看到什么」，覆盖率改的是「最终能拿到多少」**。")
    A("> 上面这张表回答「配了 GitHub Token 之后多拿到多少货」——这也是评委问「你的 POC 从哪来、")
    A("> 拿全了吗」时最直接的数字；`测试报告/POC精度评测.md` 回答另一半（同一批货里排序对不对）。")
    A("")
    A("## 二、逐 CVE 明细")
    A("")
    A("| CVE | 受影响组件 | 离线源候选/真POC | 完整源候选/真POC | 真POC 增量 | 已知武器化条目（本地真值） | 命中的武器化条目 |")
    A("|---|---|---|---|---|---|---|")
    for r in rows:
        f_, q_ = r.get("full") or {}, r.get("quick") or {}
        t = truth.get(r["cve"].upper()) or {}
        known = (t.get("exploitdb") or 0) + (t.get("metasploit") or 0)
        prods = ", ".join((r.get("products") or [])[:3]) or "—"
        A(f"| {r['cve']} | {prods} | {q_.get('n', 0)} / {q_.get('relevant', 0)} | "
          f"**{f_.get('n', 0)} / {f_.get('relevant', 0)}** | "
          f"{f_.get('relevant', 0) - q_.get('relevant', 0):+d} | {known or '—'} | "
          f"{f_.get('weaponized', 0)} |")
    A("")
    A("## 三、口径与局限（别当成「全网覆盖率」）")
    A("")
    A("- **分母不是「全网真实 POC 总数」** —— 那个数没人能穷举。本表给的是三件可复现的事：")
    A("  ① 离线源 vs 完整源（= 有/无 GitHub 凭据）的**抓取量增量**；② 抓来的东西里**真利用材料的条数**；")
    A("  ③ 相对**本地已知真值**（Exploit-DB 条目 / Metasploit 模块）的覆盖条数。")
    A("- 真值来源：`data/exploitdb_files.csv`（Exploit-DB 全量镜像，按 `codes` 列的 CVE 号计数）与")
    A("  `data/metasploit_modules_metadata.json`（按模块元信息里的 CVE 号计数）。上游镜像本身可能不全，")
    A("  所以「已知武器化条目」是**下限**，不是全部。")
    A("- 判据复用 `评测POC.py` 的 `judge()`（来源属于武器化/模板库、仓库名或代码含目标 CVE、")
    A("  仓库名带 PoC 关键词且提到受影响组件），**不读模块自己给的 `match_tier`**，因此不是自证。")
    A("- 抓取量受 GitHub 速率限制影响，重复运行会波动；同一轮内的两模式对比才是结论依据。")
    A("")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"\n[覆盖率] 报告 {args.out}")
    print(f"[覆盖率] 数据 {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
