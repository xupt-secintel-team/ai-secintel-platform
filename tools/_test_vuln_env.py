# -*- coding: utf-8 -*-
"""vuln_env 离线回归（不跑 Docker，只验生成物）。"""
import base64
import io
import os
import sys
import zipfile

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules", "m2_enrich", "backend"))

import vuln_env as VE  # noqa: E402

N = [0]


def check(cond, msg):
    N[0] += 1
    if not cond:
        raise AssertionError("FAIL #%d: %s" % (N[0], msg))


DOC_NGINX = {
    "id": "CVE-2021-23017", "title": "nginx DNS 解析器Off-by-one",
    "cpe": [{"vendor": "f5", "product": "nginx", "version": "1.20.0"}],
}
DOC_TOMCAT = {
    "id": "CVE-2020-1938", "title": "Tomcat AJP Ghostcat",
    "cpe": [{"vendor": "apache", "product": "tomcat", "version": "9.0.30"}],
}
DOC_LOG4J = {
    "id": "CVE-2021-44228", "title": "Log4Shell",
    "cpe": [{"vendor": "apache", "product": "log4j",
             "start_incl": "2.0", "end_excl": "2.15.0"}],
}
DOC_NOCP = {"id": "CVE-2026-00001", "title": "无 CPE 条目"}
DOC_STAR = {"id": "CVE-2026-00002", "title": "通配版本",
            "cpe": [{"vendor": "ollama", "product": "ollama", "version": "*"}]}

# ---------- plan ----------
p = VE.plan(DOC_NGINX, poc_urls=["https://example.invalid/poc1"])
check(p["ok"] and p["image"] == "nginx:1.20.0" and p["port"] == 80, "nginx 镜像与端口")
check(p["probe"] == "http" and not p["warnings"], "nginx 无警告")
pt = VE.plan(DOC_TOMCAT)
check(pt["image"] == "tomcat:9.0.30" and pt["port"] == 8080, "tomcat 映射")
pl = VE.plan(DOC_LOG4J)
check(pl["product"] == "log4j" and any("log4j2 场景" in w for w in pl["warnings"]), "库组件显式降级")
check(pl["image"] == "<vendor>/log4j:2.0" and pl["version"] == "2.0", "库组件取 start_incl 当代表版本")
pn = VE.plan(DOC_NOCP)
check(pn["ok"] and any("没有 CPE" in w for w in pn["warnings"]), "无 CPE 警告")
check(pn["version"] == "latest" and any("latest" in w for w in pn["warnings"]), "缺版本 → latest+警告")
ps = VE.plan(DOC_STAR)
check(ps["version"] == "latest" and ps["image"] == "ollama/ollama:latest",
      "CPE version='*' 视为无版本（不能当镜像 tag）")
pv = VE.plan(DOC_NGINX)
check(pv["poc_urls"] == [], "未给 POC → 空列表")
check(any("未提供 POC" in w for w in pv["warnings"]), "未给 POC 有提示")
p2 = VE.plan(DOC_NGINX, poc_urls=["", " ", "https://a.b/c", "https://d.e/f"])
check(p2["poc_urls"] == ["https://a.b/c", "https://d.e/f"], "POC 去空清洗")

# ---------- build_zip ----------
z = VE.build_zip(DOC_NGINX, poc_urls=["https://example.invalid/poc1"])
check(z["ok"] and z["filename"] == "CVE-2021-23017-env.zip", "zip 文件名")
raw = base64.b64decode(z["b64"])
zf = zipfile.ZipFile(io.BytesIO(raw))
names = set(zf.namelist())
check(names == {"docker-compose.yml", "verify.py", "README.md", "poc_urls.txt"}, "zip 四件套")
comp = zf.read("docker-compose.yml").decode("utf-8")
check("image: nginx:1.20.0" in comp and "18080:80" in comp, "compose 镜像与端口映射")
check("docker compose up -d" in comp, "compose 用法注释")
vr = zf.read("verify.py").decode("utf-8")
check("CVE-2021-23017" in vr and "TARGET" in vr and "nginx:1.20.0" in vr, "verify 骨架")
check("urllib" in vr and "import requests" not in vr, "verify 零第三方依赖")
check("不执行攻击载荷" in vr or "不执行攻击" in vr, "verify 无害声明")
rm = zf.read("README.md").decode("utf-8")
check("授权" in rm and "vulhub" in rm, "README 授权边界与 vulhub 互链")
check("https://example.invalid/poc1" in zf.read("poc_urls.txt").decode("utf-8"), "POC 线索落盘")
zl = VE.build_zip(DOC_LOG4J)
raw2 = base64.b64decode(zl["b64"])
z2 = zipfile.ZipFile(io.BytesIO(raw2))
rm2 = z2.read("README.md").decode("utf-8")
check("vulhub 的 log4j2 场景" in rm2, "库组件 README 有替代方案")
check("image: <vendor>/log4j:2.0" in z2.read("docker-compose.yml").decode("utf-8"), "库组件 compose 模板占位")

# ---------- 确定性 ----------
z2b = VE.build_zip(DOC_NGINX, poc_urls=["https://example.invalid/poc1"])
check(z2b["b64"] == z["b64"], "同输入同 zip（确定性）")

# ---------- preview_json ----------
import json  # noqa: E402

j = json.loads(VE.preview_json(DOC_TOMCAT))
check(j["cve"] == "CVE-2020-1938" and j["port"] == 8080, "preview JSON")

print("VULN ENV TEST OK (%d checks)" % N[0])
