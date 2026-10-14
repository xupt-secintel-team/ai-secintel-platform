# -*- coding: utf-8 -*-
"""端口测绘 + 项目成分扫描 回归（2026-10-08，离线可复跑）。

覆盖：
  A. port_scan：host 校验 / 端口解析 / 真扫回环端口（开与不开）
  B. project_scan：9 类清单解析器单元测试
  C. zip 集成：内存构造项目 zip → 解析 → 真引擎匹配 → 报告结构
  D. zip 安全：路径穿越拒收 / 条目数超限拒收
  E. markdown 报告可渲染（CMDB 七章制要素齐）
端口扫描真实 socket 打本机回环（127.0.0.1 上临时起一个 listener），无外网依赖。
"""
from __future__ import annotations

import io
import json
import os
import socket
import sys
import threading
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (os.path.join(ROOT, "core"),
          os.path.join(ROOT, "modules", "m2_enrich", "backend")):
    if p not in sys.path:
        sys.path.insert(0, p)
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

import port_scan as PS  # noqa: E402
import project_scan as PJ  # noqa: E402
import paths  # noqa: E402

OKS, FAILS = [], []


def check(cond, label, extra=""):
    (OKS if cond else FAILS).append(label)
    print("  %s %s%s" % ("[PASS]" if cond else "[FAIL]", label,
                         ("  → " + str(extra)) if (extra and not cond) else ""))


# ── A. 端口测绘 ────────────────────────────────────────────────────
def test_a_port_scan():
    print("[A] port_scan 基础")
    check(PS.valid_host("www.deepseek.com") == "www.deepseek.com", "域名通过")
    check(PS.valid_host("http://www.deepseek.com:8080/x") == "www.deepseek.com",
          "URL/端口/路径剥离", PS.valid_host("http://www.deepseek.com:8080/x"))
    check(PS.valid_host("10.0.0.256") == "", "非法 IPv4 拒收")
    check(PS.valid_host("$(whoami)") == "", "注入载荷拒收")
    check(PS.valid_host("") == "", "空串拒收")

    check(PS.parse_ports("") == PS.TOP_PORTS, "缺省用 TOP100")
    check(PS.parse_ports("80,443") == [80, 443], "逗号列表")
    check(PS.parse_ports("8000-8003") == [8000, 8001, 8002, 8003], "区间")
    check(PS.parse_ports("70000,abc") == PS.TOP_PORTS, "非法回退 TOP100")
    check(len(PS.parse_ports("1-999999")) <= PS.MAX_PORTS, "区间超限截断")

    # 真扫回环：起一个临时 listener
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port_open = 0
    while port_open < 20000:
        port_open = 0
        srv_try = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            srv_try.bind(("127.0.0.1", 0))
            port_open = srv_try.getsockname()[1]
        except OSError:
            pass
        srv_try.close()
        if port_open:
            break
    srv.bind(("127.0.0.1", port_open))
    srv.listen(5)
    t = threading.Thread(target=_accept_once, args=(srv,), daemon=True)
    t.start()
    try:
        res = PS.scan("127.0.0.1", ports="%d,%d" % (port_open, port_open + 1),
                      timeout=1.0, max_workers=10)
        check(res.get("ok"), "扫描成功", res.get("error"))
        check(res.get("ip") == "127.0.0.1", "IP 解析", res.get("ip"))
        opened = {p["port"] for p in res.get("open_ports") or []}
        check(port_open in opened, "开放端口检出", str(opened))
        check((port_open + 1) not in opened, "关闭端口不误报")
        check(res.get("closed") == 1, "closed 计数", str(res.get("closed")))
        check(res.get("elapsed_ms", 0) < 10000, "耗时 < 10s", str(res.get("elapsed_ms")))
        check("授权" in (res.get("disclaimer") or ""), "免责声明在位")
    finally:
        srv.close()

    bad = PS.scan("nonexistent-host-xyz.invalid", ports="80")
    check(not bad.get("ok") and "DNS" in (bad.get("error") or ""), "DNS 失败如实报错",
          str(bad.get("error")))


def _accept_once(srv):
    try:
        srv.accept()
    except OSError:
        pass


# ── B. 清单解析器 ──────────────────────────────────────────────────
def test_b_parsers():
    print("[B] 清单解析器")
    reqs = PJ.parse_requirements(
        "flask==2.3.2\nrequests>=2.31.0\n# comment\nurllib3~=2.0\n"
        "django[argon2]==4.2\nnumpy 1.24.0\n")
    names = {n: v for n, v, _ in reqs}
    check(names.get("flask") == "2.3.2", "requirements ==", str(names))
    check(names.get("requests") == "2.31.0", "requirements >=")
    check(names.get("urllib3") == "2.0", "requirements ~=")
    check(names.get("django") == "4.2", "requirements extras 剥离")
    check("comment" not in names, "注释剔除")

    pkg = PJ.parse_package_json(json.dumps({
        "dependencies": {"express": "^4.18.2", "lodash": "~4.17.21"},
        "devDependencies": {"jest": "^29.0.0"}}))
    names = {n: v for n, v, s in pkg}
    check(names.get("express") == "4.18.2", "package.json ^ver")
    check(names.get("lodash") == "4.17.21", "package.json ~ver")
    check(names.get("jest") == "29.0.0", "package.json devDeps")

    lock = PJ.parse_package_lock(json.dumps({
        "packages": {
            "": {"name": "root", "version": "1.0.0"},
            "node_modules/express": {"name": "express", "version": "4.18.2"},
            "node_modules/lodash": {"version": "4.17.21"}}}))
    names = {n: v for n, v, _ in lock}
    check(names.get("express") == "4.18.2", "package-lock v2 树")
    check("root" not in names, "根包剔除")

    pom = PJ.parse_pom(
        "<dependency><groupId>org.apache.logging.log4j</groupId>"
        "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>"
        "<dependency><groupId>x</groupId><artifactId>y</artifactId>"
        "<version>${proj.ver}</version></dependency>")
    check(any(n.endswith("log4j-core") and v == "2.14.1" for n, v, _ in pom), "pom 解析")
    check(any(n.endswith(":y") and v == "" for n, v, _ in pom), "pom 占位符→空版本")

    gomod = PJ.parse_go_mod("module x\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n")
    check(any(n == "github.com/gin-gonic/gin" and v == "1.9.1" for n, v, _ in gomod), "go.mod")

    cs = PJ.parse_csproj('<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />')
    check(any(n == "Newtonsoft.Json" and v == "13.0.3" for n, v, _ in cs), "csproj")

    comp = PJ.parse_composer(json.dumps({"require": {"monolog/monolog": "^3.0", "php": ">=8.0"}}))
    check(any(n == "monolog/monolog" and v == "3.0" for n, v, _ in comp), "composer")
    check(not any(n == "php" for n, v, _ in comp), "composer 语言依赖剔除")

    gem = PJ.parse_gemfile('source "https://rubygems.org"\ngem "rails", "7.1.0"\ngem "puma"\n')
    names = {n: v for n, v, _ in gem}
    check(names.get("rails") == "7.1.0" and names.get("puma") == "", "Gemfile")

    pyproj = PJ.parse_pyproject('dependencies = ["fastapi>=0.100", "uvicorn==0.23.2"]\n')
    names = {n: v for n, v, _ in pyproj}
    check(names.get("fastapi") == "0.100" and names.get("uvicorn") == "0.23.2", "pyproject pep621")

    grad = PJ.parse_gradle("implementation 'org.springframework:spring-core:5.3.30'\n")
    check(any(n == "org.springframework:spring-core" and v == "5.3.30" for n, v, _ in grad), "gradle")


# ── C. zip 集成（真引擎匹配） ──────────────────────────────────────
def test_c_zip_engine():
    print("[C] zip → 引擎匹配 → 报告")
    from engine import SearchEngine
    eng = SearchEngine(paths.CORPUS_FP)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("demo-app/requirements.txt",
                    "flask==2.3.2\nrequests>=2.31.0\nloguru==0.7.0\n")
        zf.writestr("demo-app/frontend/package.json",
                    json.dumps({"dependencies": {"axios": "^1.6.0"}}))
        zf.writestr("demo-app/server/pom.xml",
                    "<dependency><groupId>org.apache.logging.log4j</groupId>"
                    "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>")
        zf.writestr("demo-app/app/main.py", "print('not a manifest')\n")
    rep = PJ.build_report("demo-project.zip", buf.getvalue(), eng, persist=False)
    check(rep.get("ok"), "报告构建成功", rep.get("error"))
    if not rep.get("ok"):
        return
    names = {c["name"]: c for c in rep.get("components") or []}
    check("flask" in names, "flask 识别")
    check("axios" in names, "axios 识别（package.json）")
    # pom 组件名是 "group:artifact"（Maven 坐标），按 artifact 尾部匹配
    lg_key = next((k for k in names if k.endswith("log4j-core")), None)
    check(lg_key is not None, "log4j-core 识别（pom）", str(list(names)[:10]))
    check(rep.get("summary", {}).get("components", 0) >= 4, "组件计数", str(rep.get("summary")))
    check(rep.get("summary", {}).get("scanned_docs", 0) > 1000, "引擎参与比对", str(rep.get("summary", {}).get("scanned_docs")))
    # log4j-core 2.14.1 必须命中 CVE-2021-44228（语料必收，KEV 在野）
    lg = names.get(lg_key) or {}
    fids = [f["id"] for f in lg.get("findings") or []]
    check("CVE-2021-44228" in fids, "log4shell 命中（版本区间判定）", str(fids[:5]))
    check(lg.get("kev_count", 0) >= 1, "log4shell KEV 标记")
    check(rep.get("files_scanned") == 4, "文件计数", str(rep.get("files_scanned")))

    md = PJ.report_to_markdown(rep)
    for kw in ("报告编号", "执行摘要", "组件风险明细", "处置建议", "口径与边界"):
        check(kw in md, "报告含「%s」" % kw)
    check("CVE-2021-44228" in md, "报告正文含命中编号")


# ── D. zip 安全 ────────────────────────────────────────────────────
def test_d_zip_safety():
    print("[D] zip 安全")
    # 路径穿越条目：zipfile 不允许直接写 ../ 名？可以（名字只是字符串）
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil/requirements.txt", "flask==2.3.2\n")
        zf.writestr("ok/requirements.txt", "flask==2.3.2\n")
    r = PJ.parse_zip(buf.getvalue(), "t.zip")
    check(not r.get("error"), "穿越 zip 不炸")
    files = [m["file"] for m in r.get("manifests") or []]
    check("ok/requirements.txt" in files, "正常清单解析")
    check(not any("../" in f for f in files), "穿越路径拒收", str(files))

    # 条目数超限（monkeypatch 上限到 10：上限放开到 1e5 后造 10 万条目太慢）
    _orig_max = PJ.MAX_ZIP_ENTRIES
    try:
        PJ.MAX_ZIP_ENTRIES = 10
        buf2 = io.BytesIO()
        with zipfile.ZipFile(buf2, "w") as zf:
            for i in range(PJ.MAX_ZIP_ENTRIES + 10):
                zf.writestr("f%d.txt" % i, "x")
        r2 = PJ.parse_zip(buf2.getvalue(), "big.zip")
        check("超上限" in (r2.get("error") or ""), "条目数超限拒收", str(r2.get("error")))
    finally:
        PJ.MAX_ZIP_ENTRIES = _orig_max

    # 非 zip
    r3 = PJ.parse_zip(b"not a zip", "x.zip")
    check("不是有效的 zip" in (r3.get("error") or ""), "坏 zip 拒收")

    # 无清单项目
    buf3 = io.BytesIO()
    with zipfile.ZipFile(buf3, "w") as zf:
        zf.writestr("readme.md", "hello")
    rep = PJ.build_report("empty.zip", buf3.getvalue(), None, persist=False)
    check(not rep.get("ok") and "未在项目中识别到" in (rep.get("error") or ""), "无清单如实报错")


def main():
    t0 = time.time()
    test_a_port_scan()
    test_b_parsers()
    test_d_zip_safety()
    test_c_zip_engine()
    dt = time.time() - t0
    print("\n== %d passed, %d failed（%.1fs）==" % (len(OKS), len(FAILS), dt))
    if FAILS:
        for f in FAILS:
            print("  FAILED:", f)
        sys.exit(1)


if __name__ == "__main__":
    main()
