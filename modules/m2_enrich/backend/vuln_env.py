r"""漏洞复现环境一键生成 —— 成员B · m2_enrich 情报富化

「对有 POC 的漏洞，自动生成 Docker Compose 文件，一键启动漏洞环境」的**生成器**：
本模块只产出离线可复现的 docker-compose.yml + verify 验证脚本 + README 打包 zip，
**不在本机执行 Docker**（答辩环境零依赖，也避免了"为每个 CVE 维护环境"的成本 ——
正是改造建议第三档 #9 里标注的坑）。

生成逻辑（确定性，同一输入永远同一 zip）：
- 从语料条目的 NVD CPE 结构取 vendor/product/版本（含 start_incl 等区间首版）；
- 按产品族映射到官方镜像（nginx→nginx:<v>、tomcat、ollama、httpd、wordpress…），
  库组件（openssl/log4j 这类没有独立服务的）显式给 warning 并给替代方案（vulhub）；
- POC 线索：调用方传入 poc_urls（前端详情页已抓到的 POC 结果里勾选/默认第一条），
  写进 verify 脚本与 poc_urls.txt；
- verify.py 是"骨架 + 明确断言"：目标地址从 TARGET 环境变量读，默认指向 compose
  起来的本地服务，产物只做版本指纹与无害探测，不内嵌攻击代码 —— 答辩口径安全。

对外接口（api.py 薄封装）：
    GET  /api/vuln_env?id=CVE-xxx        预览（不打包）：镜像/端口/warnings/POC 线索
    POST /api/vuln_env  {id, poc_urls?}  生成并打包 → {ok, filename, b64, files}
"""

import base64
import io
import json
import os
import time
import zipfile
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------- 产品族映射

# product(CPE 规范名) -> 镜像模板 / 端口 / 探测方式 / 备注
_FAMILY: Dict[str, Dict[str, Any]] = {
    "nginx":         {"image": "nginx:{v}", "port": 80, "probe": "http", "banner": "Server 头"},
    "http_server":   {"image": "httpd:{v}", "port": 80, "probe": "http", "banner": "Server 头"},
    "tomcat":        {"image": "tomcat:{v}", "port": 8080, "probe": "http", "banner": "首页指纹"},
    "ollama":        {"image": "ollama/ollama:{v}", "port": 11434, "probe": "http", "banner": "/api/version"},
    "wordpress":     {"image": "wordpress:{v}", "port": 80, "probe": "http", "banner": "wp-meta"},
    "drupal":        {"image": "drupal:{v}", "port": 80, "probe": "http", "banner": "X-Generator"},
    "jenkins":       {"image": "jenkins/jenkins:{v}", "port": 8080, "probe": "http", "banner": "X-Jenkins"},
    "gitlab":        {"image": "gitlab/gitlab-ce:{v}", "port": 80, "probe": "http", "banner": "首页指纹"},
    "confluence":    {"image": "atlassian/confluence:{v}", "port": 8090, "probe": "http", "banner": "首页指纹"},
    "minio":         {"image": "minio/minio:{v}", "port": 9000, "probe": "http", "banner": "Server 头"},
    "elasticsearch": {"image": "elasticsearch:{v}", "port": 9200, "probe": "http", "banner": "cluster 信息"},
    "redis":         {"image": "redis:{v}", "port": 6379, "probe": "tcp", "banner": "RESP 协议"},
    "mysql":         {"image": "mysql:{v}", "port": 3306, "probe": "tcp", "banner": "握手包"},
    "postgres":      {"image": "postgres:{v}", "port": 5432, "probe": "tcp", "banner": "握手包"},
}

# 库组件：没有"一个容器起服务"的形态 → 显式降级说明，不硬造镜像
_LIB_PRODUCTS = {
    "openssl": "加密库，随上游服务镜像存在；建议直接用 vulhub 对应场景（见 README）",
    "log4j": "Java 日志库，需要含漏洞版本依赖的业务应用；建议用 vulhub 的 log4j2 场景复现",
    "spring_framework": "框架库，需要承载它的应用；建议用 vulhub 的 spring 场景复现",
    "struts": "Struts2 需要示例应用承载；建议用 vulhub 的 struts2 场景复现",
    "shiro": "Shiro 需要承载应用；建议用 vulhub 的 shiro 场景复现",
    "curl": "客户端库，随上游服务存在；本生成器不提供独立环境",
    "zlib": "压缩库，随上游服务存在；本生成器不提供独立环境",
}


def _nz(v: Any) -> str:
    return str(v).strip() if v is not None else ""


def _first_version(cpe: List[dict]) -> Optional[str]:
    """从 CPE 区间里拿一个可拉起环境的"代表版本"：精确 > start_incl > start_excl。
    NVD 的 "*" / "-" 是通配/缺失语义，不能当镜像 tag —— 视为无版本。"""
    bad = ("-", "*", "")
    for e in cpe:
        v = _nz(e.get("version"))
        if v not in bad:
            return v
    for k in ("start_incl", "start_excl"):
        for e in cpe:
            v = _nz(e.get(k))
            if v not in bad:
                return v
    return None


def plan(doc: dict, poc_urls: Optional[List[str]] = None) -> Dict[str, Any]:
    """生成方案预览（不打包）。"""
    cve = _nz(doc.get("id")) or "CVE-UNKNOWN"
    cpe = [e for e in (doc.get("cpe") or []) if isinstance(e, dict)]
    prod, vendor = "", ""
    if cpe:
        prod = _nz(cpe[0].get("product"))
        vendor = _nz(cpe[0].get("vendor"))
    fam = _FAMILY.get(prod)
    ver = _first_version(cpe)
    warnings: List[str] = []
    files_plan: List[Dict[str, str]] = []

    if not cpe:
        warnings.append("语料条目没有 CPE 结构，无法确定受影响组件 —— 请先在 NVD 页面确认组件与版本")
    elif fam is None and prod in _LIB_PRODUCTS:
        warnings.append("「%s」是库组件：%s" % (prod, _LIB_PRODUCTS[prod]))
    elif fam is None:
        warnings.append("「%s」暂无镜像映射：compose 将以注释模板给出，需自行替换镜像名" % prod)

    if not ver:
        ver = "latest"
        warnings.append("语料未给出具体版本，镜像 tag 用 latest —— 复现请自行固定到受影响版本")
    if fam and "{v}" in fam["image"] and ver == "latest":
        pass

    image = fam["image"].format(v=ver) if fam else "<vendor>/%s:%s" % (prod or "app", ver)
    port = fam["port"] if fam else 8080
    probe = fam["probe"] if fam else "http"

    pocs = [_nz(p) for p in (poc_urls or []) if _nz(p)][:5]
    if not pocs:
        warnings.append("未提供 POC 线索：verify 脚本只做版本指纹确认，不做漏洞利用验证")

    files_plan = [
        {"name": "docker-compose.yml", "note": "服务编排（漏洞版本镜像 + 端口映射）"},
        {"name": "verify.py", "note": "无害验证脚本（版本指纹 / 服务可达性）"},
        {"name": "README.md", "note": "使用步骤、授权边界、teardown"},
        {"name": "poc_urls.txt", "note": "POC / 分析文章线索"},
    ]
    return {"ok": True, "cve": cve, "product": prod, "vendor": vendor,
            "image": image, "port": port, "probe": probe, "version": ver,
            "warnings": warnings, "poc_urls": pocs, "files": files_plan,
            "title": _nz(doc.get("title"))[:140]}


def build_zip(doc: dict, poc_urls: Optional[List[str]] = None) -> Dict[str, Any]:
    """生成 zip（base64）。文件内容完全由输入决定，可复现。"""
    p = plan(doc, poc_urls)
    if not p["ok"]:
        return p
    cve, image, port = p["cve"], p["image"], p["port"]
    prod, ver = p["product"], p["version"]
    service = (prod or "vulnapp").replace("_", "-")[:30] or "vulnapp"
    pocs = p["poc_urls"]

    compose = """# {cve} 漏洞复现环境（由 aisec-D 富化台自动生成，仅供授权环境使用）
# 组件：{prod}:{ver}   探测方式：{probe}
services:
  {service}:
    image: {image}
    ports:
      - "18080:{port}"
    restart: "no"
# 用法：docker compose up -d        # 拉起漏洞环境
#       docker compose down -v     # 销毁
""".format(cve=cve, prod=prod or "<component>", ver=ver, probe=p["probe"],
           service=service, image=image, port=port)
    if p["warnings"]:
        compose += "# 注意：\n" + "".join("# - %s\n" % w for w in p["warnings"])

    verify = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""{cve} 无害验证脚本（aisec-D 生成）
用法：
    docker compose up -d
    set TARGET=http://127.0.0.1:18080   # Linux: export TARGET=...
    python verify.py
只做版本指纹与可达性确认，不执行攻击载荷；POC 利用请阅读 poc_urls.txt 的参考资料，
在**授权**环境中手工进行。
"""
import os
import sys
import urllib.request

TARGET = os.environ.get("TARGET", "http://127.0.0.1:18080")
CVE = "{cve}"
COMPONENT = "{prod}:{ver}"


def _get(url, timeout=6):
    req = urllib.request.Request(url, headers={{"User-Agent": "aisec-D-verify/1.0"}})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read(65536)


def main():
    print("[*] 目标:", TARGET, "| 组件:", COMPONENT)
    try:
        status, headers, body = _get(TARGET + "/")
    except Exception as e:  # noqa: BLE001
        print("[-] 服务不可达：", e)
        return 2
    print("[+] HTTP %s" % status)
    server = headers.get("Server") or headers.get("X-Jenkins") or headers.get("X-Powered-By") or "-"
    print("[*] 指纹头:", server)
    text = body.decode("utf-8", "ignore")
    for kw in ("{ver}", "{prod}"):
        if kw and kw.lower() in text.lower():
            print("[+] 响应体中包含组件关键字: %r" % kw)
    print("[i] 结论：环境已启动、指纹已采集。是否真实受影响请对照 poc_urls.txt 中的分析文章/POC 描述，")
    print("[i] 在隔离的授权环境中验证；如需利用验证，请使用你组织批准的工具链。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''.format(cve=cve, prod=prod or "component", ver=ver)

    readme = """# {cve} 复现环境

> 由 aisec-D 情报富化台自动生成。**只允许在你拥有书面授权的隔离环境中运行。**

- 漏洞：{cve} {title}
- 组件：{prod}{ver}
- 镜像：`{image}`（端口 {port} → 宿主机 18080）

## 步骤

```bash
docker compose up -d
python verify.py          # 无害验证（版本指纹 / 可达性）
docker compose down -v    # 用完即毁
```

{warn_block}
## POC / 参考资料

{poc_list}

## 没有现成镜像？

[vulhub](https://github.com/vulhub/vulhub) 收录了大量"开箱即用"的漏洞场景，
按 CVE 号检索可直接获得带 POC 的环境，与本生成器互补。
""".format(cve=cve, title=p["title"], prod=prod or "<组件>",
           ver=(" " + ver) if ver else "", image=image, port=port,
           warn_block=("## 自动生成的警告\n\n" +
                       "".join("- %s\n" % w for w in p["warnings"]) + "\n") if p["warnings"] else "",
           poc_list="\n".join("- %s" % u for u in pocs) or "-（未提供，建议先用富化台 POC 搜索）")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("docker-compose.yml", compose)
        z.writestr("verify.py", verify)
        z.writestr("README.md", readme)
        z.writestr("poc_urls.txt", "\n".join(pocs) if pocs else "(no poc urls)\n")
    data = buf.getvalue()
    return {"ok": True, "cve": cve, "plan": p, "filename": "%s-env.zip" % cve,
            "b64": base64.b64encode(data).decode("ascii"),
            "bytes": len(data), "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}


def preview_json(doc: dict, poc_urls: Optional[List[str]] = None) -> str:
    return json.dumps(plan(doc, poc_urls), ensure_ascii=False, indent=1)
