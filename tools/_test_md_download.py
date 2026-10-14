# -*- coding: utf-8 -*-
"""_test_md_download.py —— Markdown 导出必须**真的触发下载**（Content-Disposition）

## 背景（真实用户截图 2026-10-07）
点「⬇ 下载七章制 Markdown」，浏览器**跳转**到一个 Markdown 纯文本页面
（地址栏 `127.0.0.1:8848/api/cmdb_scan?id=CMDB-...&md=1`），文件没落盘。

## 根因
`req.send(...)` 只有传了 `filename=` 才会写 `Content-Disposition: attachment`
（见 `core/server.py:_send`）。`?md=1` 的导出分支只设了
`ctype="text/markdown"`、**漏了 filename** → 浏览器按 text/markdown
**内联渲染**，于是"下载"变成了"跳转预览"。
`/api/cmdb_scan/tickets` 一直是对的（它传了 filename），所以只有 md 入口坏。

## 这个测试钉什么
真起一次服务，打 md 导出接口，断言响应头里**确实有 attachment**。
不真打接口就抓不到 —— 源码层面"设了 ctype"看着完全正常。

用法： py tools/_test_md_download.py [端口]
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8907
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable

PASS = 0
FAIL = 0


def check(cond, label, extra=None):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] " + label)
    else:
        FAIL += 1
        print("  [FAIL] " + label + (("  →  " + str(extra)) if extra is not None else ""))


def section(t):
    print("\n=== " + t + " ===")


def get(path, timeout=30):
    """返回 (status, headers, body)。4xx/5xx 也不抛，方便断言错误路径。"""
    try:
        r = urllib.request.urlopen(BASE + path, timeout=timeout)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def main() -> int:
    section("起真实服务实例（后台，测完主动关闭）")
    p = subprocess.Popen([PYEXE, "-u", os.path.join("core", "server.py"), str(PORT)],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logs = []

    def pump():
        for line in p.stdout:
            logs.append(line.decode("utf-8", "replace"))
    threading.Thread(target=pump, daemon=True).start()

    ok = False
    for _ in range(90):
        if p.poll() is not None:
            break
        try:
            st, _, _ = get("/api/health", timeout=3)
            if st in (200, 503):
                ok = True
                break
        except Exception:
            time.sleep(0.5)
    check(ok, "服务在 45s 内起来并响应 /api/health")
    if not ok:
        print("---- 服务日志尾部 ----")
        print("".join(logs[-40:]))
        try:
            p.kill()
        except Exception:
            pass
        return 1

    try:
        section("① 没有报告 id 时：md 入口必须给出人话错误，而不是空白下载")
        st, h, b = get("/api/cmdb_scan?id=NOT-EXIST&md=1")
        check(st == 404, "不存在的 id 返回 404（实际 %s）" % st, st)
        try:
            j = json.loads(b.decode("utf-8", "replace"))
            check(bool(j.get("error")), "404 体里带 error 说明", b[:120])
        except Exception:
            check(False, "404 体是 JSON（前端才能读出原因）", b[:120])

        section("② 取一份真实报告，验证 md=1 的响应头")
        st, _, b = get("/api/cmdb_scan")
        items = []
        if st == 200:
            try:
                items = (json.loads(b.decode("utf-8")) or {}).get("items") or []
            except Exception:
                items = []
        check(st == 200, "GET /api/cmdb_scan 列表可用（实际 %s）" % st, st)
        if not items:
            print("  [SKIP] 本机没有 CMDB 报告样本 —— 无法打真实 md 导出。")
            print("         （跑一次 CMDB 分析后再执行本测试即可覆盖）")
            section("③ 静态兜底：源码层确认所有 md 分支都走了 _md_response")
            api = open(os.path.join(ROOT, "modules", "m2_enrich", "api.py"),
                       encoding="utf-8").read()
            check("def _md_response" in api, "api.py 定义了 _md_response 单一入口")
            # 所有 md=1 分支都应调 _md_response，不再裸调 req.send(ctype=text/markdown)
            nude = re.findall(r'req\.send\([^)]*text/markdown', api)
            check(not nude, "没有裸调 req.send(ctype=text/markdown) 的地方（都会内联渲染）",
                  nude)
            check(api.count("_md_response(") >= 4,
                  "_md_response 被 4 处调用（1 定义 + 3 导出点），实际 %d" % api.count("_md_response("))
            check("filename=" in api, "_md_response 里传了 filename（attachment 的唯一开关）")
            print("\n结果：通过 %d / 失败 %d" % (PASS, FAIL))
            return 0 if FAIL == 0 else 1

        rid = items[0].get("id")
        st, h, b = get("/api/cmdb_scan?id=%s&md=1" % urllib.parse.quote(str(rid)))
        check(st == 200, "md=1 导出返回 200（实际 %s）" % st, st)
        cd = h.get("Content-Disposition") or h.get("content-disposition") or ""
        ct = h.get("Content-Type") or h.get("content-type") or ""
        check(bool(cd), "★ 响应带 Content-Disposition（缺了就会内联渲染=不下载）", dict(h))
        check(cd.lower().startswith("attachment"),
              "Content-Disposition 是 attachment（实际 %r）" % cd, cd)
        check(".md" in cd, "文件名以 .md 结尾（实际 %r）" % cd, cd)
        check(cd.count("filename*=") == 1 and "filename=" in cd,
              "中文名走 RFC 5987（同时有 filename= 与 filename*=）", cd)
        check("charset=utf-8" in ct.lower(), "Content-Type 声明 UTF-8（实际 %r）" % ct, ct)
        check(b.startswith(b"\xef\xbb\xbf") or b[:1] != b"<",
              "响应体是文本内容而非 HTML 错误页", b[:60])

        section("③ asset_scan 的 md 导出同样要 attachment")
        st2, _, b2 = get("/api/asset_scan")
        items2 = []
        if st2 == 200:
            try:
                items2 = (json.loads(b2.decode("utf-8")) or {}).get("items") or []
            except Exception:
                items2 = []
        if items2:
            st3, h3, _ = get("/api/asset_scan?id=%s&md=1"
                             % urllib.parse.quote(str(items2[0].get("id"))))
            cd3 = h3.get("Content-Disposition") or h3.get("content-disposition") or ""
            check(st3 == 200 and cd3.lower().startswith("attachment"),
                  "asset_scan md=1 也是 attachment（实际 %s / %r）" % (st3, cd3))
        else:
            print("  [SKIP] 本机没有 asset_scan 样本")

        section("④ tickets 一直是正确的（对照组）")
        st4, h4, _ = get("/api/cmdb_scan/tickets?id=%s" % urllib.parse.quote(str(rid)))
        cd4 = h4.get("Content-Disposition") or h4.get("content-disposition") or ""
        check(cd4.lower().startswith("attachment"),
              "tickets 仍带 attachment（没被本次改动破坏）", cd4 or st4)

    finally:
        try:
            p.terminate()
            p.wait(timeout=8)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass

    print("\n结果：通过 %d / 失败 %d" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    import urllib.parse  # noqa: E402  （上面用到，放在这里避免 lint 抱怨顺序）
    sys.exit(main())
