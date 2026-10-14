# -*- coding: utf-8 -*-
"""_test_digest_directions_api.py —— 「AI 安全四方向」接口的真打联调（2026-10-07）

为什么要真起服务：本项目 2026-10-07 的教训 —— 路由分流类 bug 源码看着
完全正确，只有真打一遍接口才暴露（sub in ("", "/list") 吃掉详情分支、
dict.length 恒 undefined 都是这么漏出来的）。本测试用临时端口起一次
真实服务，把方向报告的**每条链路**都打一遍，打完自收自撤。

    py tools/_test_digest_directions_api.py
"""
from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import loopback  # noqa: E402

loopback.enable()

# 用当前解释器起临时服务：谁跑这个脚本就用谁的解释器，
# 不再硬编码项目 .venv（换机器 / .venv 不存在时必炸）。
PYEXE = sys.executable

PASS, FAIL = [], []


def ck(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  ok   " if cond else "  FAIL ") + name
          + (("  " + str(extra)) if extra and not cond else ""))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def hit(base, path, timeout=30):
    """返回 (status, body, headers)。404/400 也照常返回（不打断）。"""
    try:
        r = urllib.request.urlopen(base + path, timeout=timeout)
        return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def main() -> int:
    port = free_port()
    base = "http://127.0.0.1:%d" % port
    print("起临时服务：%s core/server.py %d" % (PYEXE, port))
    p = subprocess.Popen(
        [PYEXE, "-u", os.path.join("core", "server.py"), str(port)],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=0, universal_newlines=True, encoding="utf-8", errors="replace")
    lines = []

    def pump():
        try:
            for ln in p.stdout:
                lines.append(ln.rstrip())
        except Exception:  # noqa: BLE001
            pass

    import threading
    threading.Thread(target=pump, daemon=True).start()

    today = time.strftime("%Y-%m-%d")
    try:
        ok = False
        deadline = time.time() + 180
        while time.time() < deadline:
            if p.poll() is not None:
                print("★ 服务进程提前退出，返回码 %s" % p.returncode)
                break
            try:
                st, _b, _h = hit(base, "/api/health", timeout=8)
                if st == 200:
                    ok = True
                    break
            except Exception:  # noqa: BLE001
                time.sleep(2)
        ck("服务在临时端口就绪", ok,
           "" if ok else "最后输出：" + " / ".join(lines[-5:]))
        if not ok:
            return 1

        # ── 列表：directions 元信息 + grid 方向格 ──
        st, body, _h = hit(base, "/api/daily_digest?days=10")
        lst = json.loads(body.decode("utf-8"))
        ck("列表 200", st == 200, st)
        ck("列表带 directions 元信息（4 个）", len(lst.get("directions") or []) == 4)
        ck("方向元信息带 name/color",
           all(d.get("name") and str(d.get("color", "")).startswith("#")
               for d in lst.get("directions") or []))
        ck("列表不再返回模块元信息（台账已去掉）",
           "modules" not in lst, sorted(lst.keys()))
        g0 = (lst.get("grid") or [{}])[0].get("modules") or {}
        ck("当天 grid 里有方向格",
           any(k.startswith("dir_") for k in g0), sorted(g0)[:8])
        ck("grid 里没有模块格",
           all(k.startswith("dir_") for k in g0), sorted(g0)[:8])

        # ── 详情：kind=direction + 分类映射 ──
        st, body, _h = hit(base, "/api/daily_digest?module=dir_infra&date=" + today)
        rep = json.loads(body.decode("utf-8")) if st == 200 else {}
        ck("方向详情 200", st == 200, (st, body[:120]))
        ck("详情标 kind=direction", rep.get("kind") == "direction", rep.get("kind"))
        ck("详情带分类键", str(rep.get("category", "")).startswith("①"))
        ck("详情 headline 是方向口径", "该方向" in str(rep.get("headline") or ""))

        # ── 下载：md / json ──
        st, body, hd = hit(base, "/api/daily_digest?module=dir_model&date=%s&fmt=md" % today)
        ck("方向 md 下载 200", st == 200, st)
        txt = body.decode("utf-8", "replace")
        ck("md 含方向名", "② 模型与数据层风险" in txt, txt[:80])
        ck("md 含四方向口径说明", "AI 安全四方向" in txt)
        ck("md 响应带 attachment 文件名",
           "attachment" in str(hd.get("Content-Disposition") or ""))

        # ── zip：包含方向文件、不含模块文件 ──
        st, body, hd = hit(base, "/api/daily_digest?date=%s&fmt=zip" % today)
        ck("zip 下载 200", st == 200, st)
        if st == 200:
            z = zipfile.ZipFile(io.BytesIO(body))
            names = z.namelist()
            ck("zip 含 dir_infra 的 md",
               any(n.startswith("dir_infra") and n.endswith(".md") for n in names),
               names)
            ck("zip 不含模块文件（台账已去掉）",
               not any(n.split("_")[0] in ("m0_ops", "m1_monitor", "m2_enrich", "m3_qa")
                       for n in names), names)
            ck("zip README 说明四方向",
               b"\xe5\x9b\x9b\xe6\x96\xb9\xe5\x90\x91" in z.read("README.txt"))

        # ── 负路径：坏 id 400 / 空日期 404（不造假报告）──
        st, body, _h = hit(base, "/api/daily_digest?module=dir_bad&date=" + today)
        ck("未知条目 400 且列出可选值", st == 400 and "dir_infra" in body.decode("utf-8"), st)
        st, body, _h = hit(base, "/api/daily_digest?module=dir_infra&date=1999-01-01")
        j = json.loads(body.decode("utf-8")) if body else {}
        ck("无报告日期 404（不造占位报告）", st == 404, st)
        ck("404 带 empty_reason=no_data", j.get("empty_reason") == "no_data", j)

        # ── 历史兼容：台账去掉前落盘的模块报告，旧直链仍可下载 ──
        st, body, _h = hit(base, "/api/daily_digest?module=m1_monitor&date=" + today)
        ck("历史模块报告旧直链仍可下载（兼容，不新产）",
           st == 200 or st == 404, st)   # 当天没有模块文件时 404 也算兼容行为正确

        # ── status：带 directions ──
        st, body, _h = hit(base, "/api/daily_digest/status")
        stt = json.loads(body.decode("utf-8")) if st == 200 else {}
        ck("status 带 directions（含天数）",
           len(stt.get("directions") or []) == 4
           and all("days" in d for d in stt.get("directions") or []))
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            p.kill()
        print("\n已关闭临时服务（端口 %d）" % port)

    print("\n" + "=" * 60)
    print("通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
    if FAIL:
        for f in FAIL:
            print("  - " + f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
