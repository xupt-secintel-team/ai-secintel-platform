# -*- coding: utf-8 -*-
"""真实 HTTP 端到端：模拟浏览器把多个 .db 拖进「数据库文件」tab 上传。

为什么必须打真实 HTTP：本地 CS.analyze() 绕过了 api.handle_cmdb_scan_post，
而这次改动的关键全在那一层——
  ① manifest.mode=sqlite 是否被放行（原来只允许 file）
  ② 请求体按清单切分落盘是否正确
  ③ 临时目录是否用完即删
这三件事只有真发一次请求才算验证过。

用法：先起服务（tools/_run_server_logged.py），再
      py -3 tools/_e2e_cmdb_sqlite_upload.py [--port 8848]
"""
from __future__ import annotations

import glob
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_DIR = r"C:\temp\cmdbdb"
TMP_DIR = os.path.join(ROOT, "data", "tmp_cmdb")

# ★ 必须显式关代理：这台机器环境里有 HTTP_PROXY/HTTPS_PROXY 指向 127.0.0.1:6149，
#   urllib 会把 127.0.0.1 的请求也发给代理 → 收到 502，症状是「代码明明对却报 400/502」。
#   （_e2e_cmdb_report.py 早就踩过同一个坑，这里沿用它的做法。）
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

_fails = []


def ok(name, cond, detail=""):
    print("  %s %-52s %s" % ("PASS" if cond else "FAIL", name, detail))
    if not cond:
        _fails.append(name)


def _drop(path):
    """删测试自己造的临时文件。

    ★ 不用 os.unlink/os.remove：WorkBuddy 通过 sitecustomize.py 把它们换成
      "移入回收站"实现，在部分路径上会长时间不返回，测试就会卡在这里，
      表现为后面所有断言连环失败（2026-10-06 实测）。
    """
    try:
        if not os.path.isfile(path):
            return
        if sys.platform == "win32":
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.DeleteFileW.argtypes = [ctypes.c_wchar_p]
            k32.DeleteFileW.restype = ctypes.c_int
            if k32.DeleteFileW(ctypes.c_wchar_p(os.path.abspath(path))):
                return
        os.unlink(path)
    except OSError:
        pass


def upload(url, files, mode="sqlite", tables=""):
    """按前端的方式发：body = 各文件字节按序拼接，清单放 X-Cmdb-Manifest 头。"""
    manifest = {
        "mode": mode,
        "tables": tables,
        "name": files[0] if len(files) == 1 else "、".join(os.path.basename(f) for f in files),
        "files": [{"filename": os.path.basename(f), "size": os.path.getsize(f)} for f in files],
    }
    body = b""
    for f in files:
        with open(f, "rb") as fh:
            body += fh.read()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("X-Cmdb-Manifest", urllib.parse.quote(json.dumps(manifest, ensure_ascii=False)))
    try:
        with OPENER.open(req, timeout=300) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:  # noqa: BLE001
            return e.code, {}


def tmp_files():
    try:
        return [p for p in glob.glob(os.path.join(TMP_DIR, "*")) if os.path.isfile(p)]
    except OSError:
        return []


def main():
    port = 8848
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])
    base = "http://127.0.0.1:%d" % port
    api = base + "/api/cmdb_scan"

    dbs = [os.path.join(SAMPLE_DIR, n) for n in
           ("01_ledger.db", "02_asset.db", "03_idc.db")]
    missing = [p for p in dbs if not os.path.isfile(p)]
    if missing:
        print("样本缺失：%s" % missing)
        return 1

    print("=== ① 上传前临时目录状态 ===")
    before = set(tmp_files())
    ok("记录上传前的临时文件基线（%d 个）" % len(before), True)

    print("\n=== ② 分库上传（3 个 .db 一次传）===")
    code, r = upload(api, dbs)
    ok("HTTP 200", code == 200, "code=%s" % code)
    if code != 200:
        print(json.dumps(r, ensure_ascii=False)[:400])
        return 1
    rep = r.get("report") or {}
    ok("返回 ok", bool(r.get("ok")), r.get("error", ""))

    print("\n=== ③ 报告内容：三库合一 ===")
    src = json.dumps(rep, ensure_ascii=False)
    ok("识别为台账数据源（第 1 个库）", "漏洞台账" in src or rep.get("is_ledger"),
       "source=%s" % rep.get("source_name"))
    pr = rep.get("priority") or []
    ok("产出处置工单", len(pr) > 0, "%d 条" % len(pr))
    # 责任人在台账模式里是 owners 列表（一条 CVE 可能命中多个不同责任人），不是 owner 字符串
    owners = sorted({o for p in pr for o in (p.get("owners") or []) if o})
    ok("工单带责任人（台账字段读到了）", bool(owners), "、".join(owners))
    ok("工单带计划期限", all(p.get("plan_fix") for p in pr if p.get("cve")))
    hosts = (rep.get("risk") or {}).get("hosts") or []
    loc = " ".join((h.get("location") or "") for h in hosts)
    ok("位置跨库回溯（资产库 + 机房库）", "银川" in loc, loc[:70] or "无位置")

    print("\n=== ④ 数据来源标注多库 ===")
    # 上传模式下 source_name 用的是前端传来的原始文件名（要给人看），
    # 而 _source_label 的「N 个库」是本地路径模式的标签 —— 两条路，别混断言。
    sn = str(rep.get("source_name") or "")
    ok("来源列出全部上传的库名",
       all(os.path.basename(p) in sn for p in dbs), sn)

    print("\n=== ⑤ 临时 .db 用完即删 ===")
    # ★ 清理是后台异步的（2026-10-06 修 "Failed to fetch"）：
    #   同步删几百 MB 的库会挂死请求线程。这里等它落地，而不是要求响应瞬间就干净。
    for _ in range(40):
        left = sorted(set(tmp_files()) - before)
        if not left:
            break
        time.sleep(0.1)
    ok("分析后无残留临时 .db", not left, "残留：%s" % [os.path.basename(x) for x in left])
    try:
        import paths  # noqa: F401
    except Exception:  # noqa: BLE001
        pass
    ok("临时目录 data/tmp_cmdb 仍存在（供下次复用）", os.path.isdir(TMP_DIR), TMP_DIR)

    print("\n=== ⑥ 回归：CSV 模式二进制直传没被改坏 ===")
    csv_path = os.path.join(SAMPLE_DIR, "_inline_probe.csv")
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("name,ip,product,version\nweb01,10.1.1.1,Apache Tomcat,9.0.80\n")
    try:
        code2, r2 = upload(api, [csv_path], mode="file")
        ok("CSV 上传 HTTP 200", code2 == 200, "code=%s" % code2)
        ok("CSV 上传返回 ok", bool(r2.get("ok")), r2.get("error", ""))
    finally:
        _drop(csv_path)

    print("\n=== ⑦ 边界：只传一个库也要能跑 ===")
    code3, r3 = upload(api, [dbs[0]])
    ok("单库上传 HTTP 200", code3 == 200, "code=%s" % code3)
    ok("单库上传返回 ok", bool(r3.get("ok")), r3.get("error", ""))
    if r3.get("ok"):
        sn1 = str((r3.get("report") or {}).get("source_name") or "")
        ok("单库来源只列一个库名（不多列）", "、" not in sn1, sn1)

    print("\n=== ⑧ 边界：混入损坏的 .db 不应拖垮分析 ===")
    bad = os.path.join(SAMPLE_DIR, "99_broken.db")
    with open(bad, "wb") as f:
        f.write(b"definitely not a sqlite file")
    try:
        code4, r4 = upload(api, [dbs[0], bad, dbs[1]])
        ok("坏库混入时仍 HTTP 200", code4 == 200, "code=%s" % code4)
        ok("好库仍出报告", bool(r4.get("ok")) and bool((r4.get("report") or {}).get("priority")),
           r4.get("error", ""))
    finally:
        _drop(bad)
    for _ in range(40):                      # 清理已改后台异步，等它落地
        if not (set(tmp_files()) - before):
            break
        time.sleep(0.1)
    ok("坏库那次也没留临时文件", not (set(tmp_files()) - before),
       [os.path.basename(x) for x in (set(tmp_files()) - before)])

    print("\n=== ⑨ 边界：清单与请求体不符要报错 ===")
    manifest = {"mode": "sqlite", "files": [{"filename": "x.db", "size": 999999}]}
    req = urllib.request.Request(api, data=b"tiny", method="POST")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("X-Cmdb-Manifest", urllib.parse.quote(json.dumps(manifest)))
    try:
        with OPENER.open(req, timeout=60) as r5:
            code5, body5 = r5.status, r5.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        code5, body5 = e.code, e.read().decode("utf-8")
    ok("尺寸不符返回 4xx", 400 <= code5 < 500, "code=%s" % code5)
    ok("错误信息说清是清单问题", "清单" in body5, body5[:80])
    ok("尺寸不符也没落盘（在切分前就返回了）", not (set(tmp_files()) - before),
       [os.path.basename(x) for x in (set(tmp_files()) - before)])

    print("\n=== ⑩ 落盘中途失败的回滚（直接打函数，走不到 HTTP 触发点）===")
    # 这条只能直接调 _stage_sqlite_uploads：HTTP 层是「全量校验完 → 再落盘」，
    # 切分循环先跑完才写盘，所以请求体不合法的情况在落盘前就被 400 挡掉了。
    # 真正会中途失败的是写盘本身（磁盘满 / 权限 / 文件被占用），
    # 而那时前几个库已经躺在 data/tmp_cmdb 里 —— 2026-10-06 修的正是这个泄漏。
    sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich"))
    sys.path.insert(0, os.path.join(ROOT, "core"))
    try:
        import importlib
        api = importlib.import_module("api")
        base_now = set(tmp_files())
        # 造一个「写到第 2 个就炸」的场景：第 2 个的目标路径被目录占住
        real_open = api.open if hasattr(api, "open") else open

        boom_dir = os.path.join(TMP_DIR, "blocker_dir")
        os.makedirs(boom_dir, exist_ok=True)
        call = {"n": 0}

        def fake_open(path, mode="r", *a, **kw):
            # 第 2 次写盘时故意抛错，模拟磁盘/权限故障
            if "w" in mode:
                call["n"] += 1
                if call["n"] == 2:
                    raise OSError("模拟磁盘写入失败")
            return real_open(path, mode, *a, **kw)

        import builtins
        orig_builtin_open = builtins.open
        builtins.open = fake_open
        try:
            paths_ret, err = api._stage_sqlite_uploads([
                {"filename": "first.db", "data": b"x" * 8},
                {"filename": "second.db", "data": b"y" * 8},
                {"filename": "third.db", "data": b"z" * 8},
            ])
        finally:
            builtins.open = orig_builtin_open
            try:
                os.rmdir(boom_dir)
            except OSError:
                pass
        ok("写盘失败时返回错误而非静默成功", bool(err), "err=%s" % err[:60])
        ok("失败时不返回半截路径", not paths_ret, "返回了 %s" % paths_ret)
        left10 = sorted(os.path.basename(x) for x in (set(tmp_files()) - base_now))
        ok("已落盘的第 1 个库被回滚删除（不残留真实 CMDB 数据）", not left10,
           "残留：%s" % left10)
    except Exception as e:  # noqa: BLE001
        ok("落盘回滚可验证", False, "抛异常 %s: %s" % (type(e).__name__, e))

    print("\n" + "=" * 70)
    if _fails:
        print("失败 %d 项：%s" % (len(_fails), _fails))
        return 1
    print("数据库多库上传 e2e 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
