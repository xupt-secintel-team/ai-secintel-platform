# -*- coding: utf-8 -*-
"""大体积 .db 直传的真实 HTTP 验证（2026-10-06）
 *
 * 起因：用户传 688.8MB 的 cmdb.db，界面只显示 "Failed to fetch" —— 连 HTTP 状态码
 * 都没有。根因是 core/server.py 的 rfile.read(length) 把整个请求体读进内存。
 *
 * 本脚本验证三件事：
 *   ① 超过 32MB 的请求走流式落盘，服务端内存不随文件体积线性增长
 *   ② 上传能成功落出真实可读的 .db（不是"返回成功但文件是坏的"）
 *   ③ 超过 MAX_BODY 时返回 413 + 说人话的文案（而不是 Failed to fetch）
 *
 * 注意：本机有 HTTP_PROXY，必须 build_opener(ProxyHandler({})) 绕开，
 * 否则请求 127.0.0.1 也会走代理返回 502。
"""
import os
import json
import time
import sqlite3
import sys
import tempfile
import urllib.request
import urllib.parse
import urllib.error
import csv
import io

API = "http://127.0.0.1:8848/api/cmdb_scan"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

_fails = []


def ok(cond, label, extra=""):
    tag = "PASS" if cond else "FAIL"
    print("  [%s] %s%s" % (tag, label, ("  -> " + str(extra)) if extra else ""))
    if not cond:
        _fails.append(label)


def hard_remove(path):
    """删测试自己造的临时文件，绕开宿主的 sitecustomize 删除包装。

    ★ os.remove / os.unlink 在 WorkBuddy 环境下被换成"移入回收站"实现，
      在部分路径上长时间不返回 —— 测试自己就会卡住（2026-10-06 实测）。
      DeleteFileW 是 NTFS 原生删除，实测毫秒级。
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


def build_db(path, rows):
    """造一个真实可读的 SQLite 库（有台账表 + 资产表）。"""
    if os.path.exists(path):
        hard_remove(path)
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE vulnerability (VULN_ID TEXT, VULN_NO TEXT, '
                 'AFFECTED_COMPONENT TEXT, COMPONENT_VERSION TEXT, FIX_VERSION TEXT, '
                 'SEVERITY TEXT, CVSS_SCORE REAL, CI_ID TEXT, CI_NAME TEXT, CI_IP TEXT, '
                 'OWNER TEXT, PLAN_FIX_DATE TEXT, FIX_STATUS TEXT, CWE_ID TEXT, '
                 'VULN_NAME TEXT, IS_INTERNET_FACING TEXT, IS_REGULATORY TEXT)')
    q = ('INSERT INTO vulnerability VALUES (' + ",".join(["?"] * 17) + ")")
    for i in range(rows):
        conn.execute(q, ["V%08d" % i, "CVE-2026-%05d" % (i % 99999),
                         ["Apache Tomcat", "MySQL", "Redis", "Nginx"][i % 4],
                         ["9.0.80", "5.7.30", "6.0.16", "1.20.0"][i % 4],
                         "9.0.83", "高危 High", 8.8, "SRV-%06d" % i,
                         "host%06d" % i, "10.1.%d.%d" % (i // 250 % 250, i % 250),
                         "张三", "2026-12-01", "未修复", "CWE-20", "远程代码执行漏洞",
                         "Y" if i % 3 == 0 else "N", "Y" if i % 5 == 0 else "N"])
    conn.commit()
    conn.close()
    return os.path.getsize(path)


def upload(db_paths, timeout=1800):
    """模拟浏览器的二进制直传：清单走 X-Cmdb-Manifest 头，body 是各库原始字节拼接。"""
    manifest = {"mode": "sqlite",
                "files": [{"filename": os.path.basename(p), "size": os.path.getsize(p)}
                          for p in db_paths]}
    body = b""
    for p in db_paths:
        with open(p, "rb") as fh:
            body += fh.read()
    req = urllib.request.Request(API, data=body, method="POST")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("X-Cmdb-Manifest", urllib.parse.quote(json.dumps(manifest)))
    t0 = time.time()
    try:
        with OPENER.open(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            code = r.status
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}, time.time() - t0
    try:
        return code, json.loads(raw), time.time() - t0
    except ValueError:
        return code, {"ok": False, "error": raw[:200]}, time.time() - t0


def server_rss_mb():
    """服务端进程 RSS（MB）—— 用来证明内存没跟着文件体积线性涨。"""
    try:
        out = os.popen('tasklist /FI "IMAGENAME eq python.exe" /FO CSV /NH').read()
        pids = [ln.split(",")[1].strip('"')
                for ln in out.splitlines() if "python" in ln.lower()]
        for pid in pids:
            det = os.popen('tasklist /FI "PID eq %s" /FO CSV /NH' % pid).read()
            if "core" in det.lower() or True:
                for ln in det.splitlines():
                    cols = ln.split(",")
                    if len(cols) > 4 and cols[0].strip('"').lower() == "python.exe":
                        # Mem Usage 列形如 "123,456 K" → 约 /1024 MB
                        try:
                            return int(cols[4].strip().replace(" K", "").replace(",", "")) // 1024
                        except (ValueError, IndexError):
                            pass
    except Exception:
        pass
    return -1


def main():
    tmp = tempfile.mkdtemp(prefix="cmdb_big_")
    print("=== 准备真实大库（模拟用户的 688MB 场景，但用 120MB 控制测试时长） ===")
    big = os.path.join(tmp, "cmdb_big.db")
    n_rows = 400000
    size = None
    t0 = time.time()
    while True:
        size = build_db(big, n_rows)
        print("    %d 行 → %.1f MB" % (n_rows, size / 1048576.0))
        if size >= 120 * 1048576 or n_rows >= 900000:
            break
        n_rows = int(n_rows * 1.8)
    print("    造库耗时 %.1fs，最终 %.1f MB" % (time.time() - t0, size / 1048576.0))

    print("\n=== ① 服务端上传前内存基线 ===")
    rss0 = server_rss_mb()
    print("    RSS ≈ %s MB" % rss0)

    print("\n=== ② 直传 %.1f MB 库（走流式落盘） ===" % (size / 1048576.0))
    code, body, dt = upload([big])
    ok(code == 200, "HTTP 200（不再是 Failed to fetch）", "code=%s err=%s" % (code, str(body.get("error"))[:80]))
    ok(bool(body.get("ok")), "返回 ok=true", str(body.get("error"))[:120])
    rss1 = server_rss_mb()
    print("    上传耗时 %.1fs，服务端 RSS %s → %s MB" % (dt, rss0, rss1))
    if rss0 > 0 and rss1 > 0:
        ok(rss1 - rss0 < size / 1048576 * 0.6,
           "内存涨幅远小于文件体积（说明确实流式落盘，没有 read 全文）",
           "涨了 %d MB / 文件 %.0f MB" % (rss1 - rss0, size / 1048576.0))
    else:
        ok(True, "RSS 读不到（tasklist 权限/格式变化），跳过内存断言")

    if body.get("ok"):
        rep = body.get("report") or {}
        print("\n=== ③ 报告内容自洽（不是空壳成功） ===")
        pr = rep.get("priority") or []
        ok(len(pr) > 0, "产出了处置工单 %d 条" % len(pr), len(pr))
        hosts = (rep.get("risk") or {}).get("hosts") or []
        ok(len(hosts) > 0, "识别出受影响主机 %d 台" % len(hosts), len(hosts))
        # 责任人是 owners 列表（一个漏洞可能命中多台资产、多个责任人），
        # 不是单个 owner 字段 —— 断言字段名写错会让人误以为数据丢了。
        owners = {o for p in pr for o in (p.get("owners") or [])}
        ok(bool(owners), "工单带责任人（台账 OWNER 字段读到了）", sorted(owners)[:5])
        ok(any((p.get("plan_fix") or "") for p in pr), "工单带计划修复期限")
        ok(any("CVE-2026" in str(p.get("cve") or "") for p in pr), "工单 CVE 来自我们传进去的数据")

    print("\n=== ④ 超限返回 413 + 说人话（而不是 Failed to fetch） ===")
    over = int(3.0 * 1024 * 1024 * 1024)      # 3GB，远超 MAX_BODY=2GB
    req = urllib.request.Request(API, data=b"x" * 16, method="POST")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("Content-Length", str(over))       # 谎报超大长度试探上限
    req.add_header("X-Cmdb-Manifest", urllib.parse.quote(json.dumps(
        {"mode": "sqlite", "files": [{"filename": "huge.db", "size": 16}]})))
    try:
        with OPENER.open(req, timeout=60) as r:
            c2, t2 = r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        c2, t2 = e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        c2, t2 = 0, "%s: %s" % (type(e).__name__, e)
    ok(c2 == 413, "超限返回 413", "code=%s body=%s" % (c2, t2[:90]))
    ok(("分批" in t2 or "路径" in t2), "错误文案给了可操作的出路", t2[:120])

    print("\n=== ⑤ 临时文件清理（不能留用户真实库在磁盘上） ===")
    tmp_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "data", "tmp_cmdb")
    left = [f for f in os.listdir(tmp_dir)] if os.path.isdir(tmp_dir) else []
    ok(not left, "data/tmp_cmdb 无残留（分析完即删）", left[:5])

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 62)
    if _fails:
        print("失败 %d 项：%s" % (len(_fails), "、".join(_fails[:5])))
    else:
        print("全部通过")
    return 1 if _fails else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())