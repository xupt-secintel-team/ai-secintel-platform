# -*- coding: utf-8 -*-
"""port_scan.py —— 端口测绘（授权资产探测）
================================================================
为什么做（2026-10-08 用户需求）：情报系统的"资产测绘"此前只生成
FOFA/Shodan 语法（asset_search），缺一个**本机直接探测**的通道：
输入域名/IP → 并发 TCP 连接扫描常见端口 → 开放端口 + 服务猜测 + banner。

定位与边界（重要，答辩会被问）：
1. 这是**资产测绘的最基础手段**（TCP connect 扫描），与 nmap 的
   `-sT` 同级：不发畸形包、不做 OS 指纹、不暴力破解，纯粹"这个端口
   能不能建立 TCP 连接"。教学/竞赛场景用于演示"情报 → 主动验证"闭环。
2. **仅限授权目标**：扫描未授权的第三方主机可能违反《网络安全法》
   第二十七条（对计算机信息系统功能进行删除、修改、增加、干扰）。
   UI 与报告都带授权提示；本模块不做任何隐蔽伪装（不代表防御方视角）。
3. banner 只被动接收（ recv 一次，超时 1.2s），**不主动发送探测载荷**——
   HTTP 这类不主动推 banner 的服务拿不到 banner 是正常行为，如实标注。

实现要点（踩过才知道）：
- connect_ex() 而不是 connect()：后者对拒绝连接会抛异常，海量并发下
  异常开销显著；connect_ex 返回错误码，快且干净。
- getaddrinfo 一次解析、多端口复用：有些代码每个端口解析一次 DNS，
  100 端口 = 100 次 DNS 查询，既慢又给 DNS 服务器找麻烦。
- 线程池并发（默认 120）：串行扫 100 端口 × 1.5s 超时最坏 150s；
  并发后 1~3s 出全量结果。
"""
from __future__ import annotations

import json
import os
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import paths
except Exception:  # pragma: no cover
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    import paths

# ── 常见端口 → 服务名（nmap top-100 精选；覆盖 Web/远程管理/数据库/中间件）──
TOP_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 113, 123, 135, 137, 138,
    139, 143, 161, 162, 389, 443, 445, 465, 514, 587, 623, 636, 873, 990,
    993, 995, 1080, 1099, 1194, 1433, 1521, 1723, 2049, 2082, 2083, 2181,
    2375, 2376, 2379, 2380, 3000, 3128, 3268, 3306, 3389, 3690, 4444, 4505,
    4506, 4848, 5000, 5432, 5555, 5601, 5900, 5901, 5984, 6379, 6443, 6660,
    6667, 7001, 7002, 7077, 8000, 8008, 8009, 8010, 8020, 8080, 8081, 8088,
    8089, 8090, 8161, 8443, 8500, 8649, 8888, 9000, 9042, 9080, 9090, 9092,
    9200, 9300, 9418, 9999, 10000, 11211, 15672, 27017, 28017, 50000, 50070,
]

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
    69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "syslog", 587: "submission", 623: "ipmi",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
    1099: "java-rmi", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
    2379: "etcd", 3000: "node/dev", 3128: "squid", 3306: "mysql",
    3389: "rdp", 4444: "metasploit-default", 4505: "salt", 4848: "glassfish",
    5000: "flask/registry", 5432: "postgresql", 5555: "adb", 5601: "kibana",
    5900: "vnc", 5984: "couchdb", 6379: "redis", 6443: "kubernetes-api",
    7001: "weblogic", 7077: "spark", 8000: "http-alt", 8009: "ajp",
    8080: "http-proxy", 8081: "http-alt", 8161: "activemq", 8443: "https-alt",
    8500: "consul", 8888: "http-alt", 9000: "sonar/php-fpm", 9042: "cassandra",
    9090: "prometheus", 9092: "kafka", 9200: "elasticsearch",
    9418: "git-daemon", 10000: "webmin", 11211: "memcached",
    15672: "rabbitmq-mgmt", 27017: "mongodb", 28017: "mongodb-web",
    50000: "sap", 50070: "hadoop-namenode",
}

HOST_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_-])?\.)*"
    r"[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_-])?\.?$")

MAX_PORTS = 1024          # 单次最多扫多少端口（防误填 1-65535 拖死线程池）
MAX_WORKERS = 120         # 并发线程数
CONNECT_TIMEOUT = 1.5     # 单端口连接超时（秒）
BANNER_TIMEOUT = 1.2      # banner 被动接收超时（秒）
BANNER_CAP = 120          # banner 最长保存字节
STORE_MAX = 50            # 历史最多留多少份

_BANNER_RE = re.compile(r"[^\x20-\x7e\r\n\t]")


def _now_ms():
    return int(time.time() * 1000)


def valid_host(s: str) -> str:
    """主机名校验：域名 / IPv4。返回规范化串，非法返回 ""。"""
    s = str(s or "").strip().lower()
    if not s or len(s) > 253:
        return ""
    if s.startswith(("http://", "https://")):
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if not HOST_RE.match(s):
        return ""
    # IPv4 简单校验
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
        if any(int(x) > 255 for x in s.split(".")):
            return ""
    return s


def parse_ports(spec: str) -> list:
    """端口表达式：'80,443,8000-8010' → 有序列表。空 → TOP_PORTS。"""
    if not str(spec or "").strip():
        return list(TOP_PORTS)
    out = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"^(\d+)-(\d+)$", part)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if a > b:
                a, b = b, a
            out.update(range(max(1, a), min(65535, b) + 1))
        elif part.isdigit():
            p = int(part)
            if 1 <= p <= 65535:
                out.add(p)
    out = sorted(out)[:MAX_PORTS]
    return out or list(TOP_PORTS)


def resolve(host: str) -> dict:
    """DNS 解析。返回 {ok, ip, error, all}。"""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "ip": "", "error": "DNS 解析失败: %s" % str(e)[:120], "all": []}
    ips = []
    for fam, _typ, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip and ip not in ips:
            ips.append(ip)
    if not ips:
        return {"ok": False, "ip": "", "error": "DNS 解析无结果", "all": []}
    # 优先 IPv4（教学环境 v6 常不可达）
    v4 = [x for x in ips if ":" not in x]
    return {"ok": True, "ip": (v4 or ips)[0], "error": "", "all": ips[:6]}


def _grab_banner(sock: socket.socket) -> str:
    """被动收 banner：服务不主动推就为空（HTTP 常见），如实标注。"""
    try:
        sock.settimeout(BANNER_TIMEOUT)
        data = sock.recv(BANNER_CAP)
        return _BANNER_RE.sub(".", data.decode("utf-8", "ignore")).strip()[:BANNER_CAP]
    except Exception:  # noqa: BLE001 —— 没有banner是常态，不是错误
        return ""


def _probe(args):
    """探一个端口：connect_ex 判开闭；开放的抓 banner。"""
    ip, port, timeout = args
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((ip, port))
    except OSError:
        s.close()
        return port, False, ""
    if rc != 0:
        s.close()
        return port, False, ""
    banner = _grab_banner(s)
    try:
        s.close()
    except OSError:
        pass
    return port, True, banner


def scan(host: str, ports=None, timeout: float = CONNECT_TIMEOUT,
         max_workers: int = MAX_WORKERS) -> dict:
    """扫描主机。返回 {ok, host, ip, ports, open_ports, closed, elapsed_ms, ...}"""
    host = valid_host(host)
    if not host:
        return {"ok": False, "error": "主机名不合法（支持域名 / IPv4）"}
    plist = parse_ports(ports if isinstance(ports, list) else (ports or ""))
    if not plist:
        return {"ok": False, "error": "端口列表为空"}

    dns = resolve(host)
    if not dns.get("ok"):
        return {"ok": False, "host": host, "error": dns.get("error") or "DNS 解析失败"}
    ip = dns["ip"]

    t0 = time.time()
    open_ports = []
    workers = max(10, min(int(max_workers or MAX_WORKERS), 256))
    timeout = max(0.3, min(float(timeout or CONNECT_TIMEOUT), 5.0))
    tasks = [(ip, p, timeout) for p in plist]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_probe, t): t[0] for t in tasks}
        for fut in as_completed(futs):
            try:
                port, opened, banner = fut.result()
            except Exception:  # noqa: BLE001
                continue
            if opened:
                open_ports.append({"port": port,
                                   "service": SERVICE_NAMES.get(port, "unknown"),
                                   "banner": banner})
    open_ports.sort(key=lambda x: x["port"])
    return {
        "ok": True,
        "host": host,
        "ip": ip,
        "dns_all": dns.get("all") or [],
        "scanned": len(plist),
        "open_count": len(open_ports),
        "open_ports": open_ports,
        "closed": len(plist) - len(open_ports),
        "timeout": timeout,
        "workers": workers,
        "elapsed_ms": int((time.time() - t0) * 1000),
        "note": "TCP connect 扫描（nmap -sT 同级）：仅端口可达性与被动 banner，"
                "不发探测载荷；banner 为空 = 服务不主动推送（HTTP 常见）。",
        "disclaimer": "仅限对已授权资产使用；扫描未授权主机可能违法。",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


# ── 持久化（data/port_scans.json，与 asset_scans 同模式） ──────────
_STORE_LOCK = threading.Lock()     # 模块级锁：save_result 并发互斥（不能每次 new 锁）


def _store_fp():
    return os.path.join(paths.DATA_DIR, "port_scans.json")


def _load_store():
    fp = _store_fp()
    if not os.path.isfile(fp):
        return []
    try:
        with open(fp, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def _save_store(items):
    fp = _store_fp()
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    tmp = "%s.%d.tmp" % (fp, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(items[:STORE_MAX], f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, fp)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


def save_result(res: dict) -> None:
    """扫描结果入库（模块级锁；只留轻量索引字段）。"""
    if not res.get("ok"):
        return
    corr = res.get("correlation") or {}
    with _STORE_LOCK:
        items = _load_store()
        items.insert(0, {
            "host": res.get("host"), "ip": res.get("ip"),
            "open_count": res.get("open_count"), "scanned": res.get("scanned"),
            "open_ports": [{"port": p["port"], "service": p["service"]}
                           for p in (res.get("open_ports") or [])[:24]],
            # 2026-10-08 晚：关联摘要进历史索引（列表页直接显示风险，不用逐份点开）
            "cve_hits": corr.get("cve_hits"), "critical": corr.get("critical"),
            "high": corr.get("high"), "exploited": corr.get("exploited"),
            "elapsed_ms": res.get("elapsed_ms"), "ts": res.get("ts"),
        })
        _save_store(items)


def history(host: str = "", limit: int = 20):
    items = _load_store()
    if host:
        host = valid_host(host)
        items = [x for x in items if x.get("host") == host]
    return items[:max(1, min(int(limit or 20), 50))]


def _last_fp() -> str:
    """最近一次（含关联结果的）扫描全量落盘 —— GET ?md=1 直接出工单报告。"""
    return os.path.join(paths.DATA_DIR, "port_scan_last.json")


def save_last(res: dict) -> None:
    try:
        fp = _last_fp()
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        tmp = "%s.%d.tmp" % (fp, os.getpid())
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, fp)
    except OSError:
        pass


def load_last():
    fp = _last_fp()
    if not os.path.isfile(fp):
        return None
    try:
        with open(fp, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# ════════════════════════════════════════════════════════════════
# 二、服务指纹识别 + 情报库关联 + 工单化报告（2026-10-08 晚新增）
# ════════════════════════════════════════════════════════════════
# 用户需求原文："端口测绘功能要求扫描后分析其有没有相关在检测模块中
# 符合的 bug，最后得出一个类似 CMDB风险评估报告 可作为工单下发"。
#
# 三层识别策略（置信度递减）：
#   ① banner/HTTP Server 头里的 产品+版本 → 高置信（CPE 版本区间判定）
#   ② 端口 → 服务家族映射（redis/mysql/...）→ 低置信（产品级全区间，
#      报告里如实标「版本未知，需人工确认后派单」）
#   ③ 识别不出产品 → 只列服务名，不硬凑 CVE
#
# HTTP 主动探测说明：被动 banner 对 HTTP 类服务拿不到任何指纹
# （HTTP 不主动推 banner）。这里对 Web 端口发一个**最小化 HEAD 请求**
# （nmap -sV 的极小子集），只为取 Server / X-Powered-By 两个响应头；
# 不带任何攻击载荷。UI 与报告均已注明该方法边界。

_HTTP_PROBE_PORTS = {80, 443, 591, 3000, 5000, 7001, 8000, 8008, 8009, 8010,
                     8080, 8081, 8088, 8090, 8443, 8899, 9000, 9080, 9090,
                     9200, 10000}
_HTTPS_PORTS = {443, 8443}
_HTTP_TIMEOUT = 2.5

# 指纹正则（按可靠性排序，首个命中即用）。产物统一小写产品名 + 版本。
_FINGERPRINTS = [
    (re.compile(r"OpenSSH[_ ]v?([0-9][\w.\-]*)", re.I), "openssh"),
    (re.compile(r"SSH-[\d.]+-OpenSSH[_ ]v?([0-9][\w.\-]*)", re.I), "openssh"),
    (re.compile(r"\bvsftpd[/ ]v?([0-9][\w.\-]*)", re.I), "vsftpd"),
    (re.compile(r"ProFTPD[/ ]v?([0-9][\w.\-]*)", re.I), "proftpd"),
    (re.compile(r"\bnginx[/ ]v?([0-9][\w.\-]*)", re.I), "nginx"),
    (re.compile(r"\bApache[/ ]v?([0-9][\w.\-]*)", re.I), "apache_http_server"),
    (re.compile(r"Microsoft-IIS[/ ]v?([0-9][\w.\-]*)", re.I), "microsoft_iis"),
    (re.compile(r"\bLiteSpeed[/ ]v?([0-9][\w.\-]*)", re.I), "litespeed"),
    (re.compile(r"\bCaddy[/ ]v?([0-9][\w.\-]*)", re.I), "caddy"),
    (re.compile(r"Apache-Coyote[/ ]v?([0-9][\w.\-]*)", re.I), "apache_tomcat"),
    (re.compile(r"\bTomcat[/ ]v?([0-9][\w.\-]*)", re.I), "apache_tomcat"),
    (re.compile(r"\bJetty[/ ]v?([0-9][\w.\-]*)", re.I), "jetty"),
    (re.compile(r"\bWebLogic[/ ]v?([0-9][\w.\-]*)", re.I), "oracle_weblogic"),
    (re.compile(r"\bRedis[_ ]v?([0-9][\w.\-]*)", re.I), "redis"),
    (re.compile(r"\bMySQL([ ,]|v?([0-9][\w.\-]*))", re.I), "mysql"),
    (re.compile(r"\bMariaDB[/ ]v?([0-9][\w.\-]*)", re.I), "mariadb"),
    (re.compile(r"\bPostgreSQL[/ ]v?([0-9][\w.\-]*)", re.I), "postgresql"),
    (re.compile(r"\bMongoDB[/ ]v?([0-9][\w.\-]*)", re.I), "mongodb"),
    (re.compile(r"\bElasticsearch[/ ]v?([0-9][\w.\-]*)", re.I), "elasticsearch"),
    (re.compile(r"\bRabbitMQ[/ ]v?([0-9][\w.\-]*)", re.I), "rabbitmq"),
    (re.compile(r"\bMemcached[/ ]v?([0-9][\w.\-]*)", re.I), "memcached"),
    (re.compile(r"\bDovecot[/ ]v?([0-9][\w.\-]*)", re.I), "dovecot"),
    (re.compile(r"\bPostfix", re.I), "postfix"),
    (re.compile(r"\bExim[/ ]v?([0-9][\w.\-]*)", re.I), "exim"),
    (re.compile(r"220-?(?:[\w.\- ]*?)Microsoft FTP Service", re.I), "microsoft_ftp"),
    (re.compile(r"\bPure-FTPd[/ ]v?([0-9][\w.\-]*)", re.I), "pure-ftpd"),
]
# 兜底：通用 Product/1.2.3 形态（banner 中段，避免匹配到 IP 片段）
_GENERIC_FP_RE = re.compile(r"(?<![0-9.])([A-Za-z][A-Za-z0-9_.\-]{2,28})/([0-9][\w.\-]*)")

# 端口/服务名 → 产品家族（识别不出版本时的低置信匹配对象）
_SERVICE_FAMILY = {
    "ssh": "openssh", "ftp": "ftp", "http": "", "https": "",
    "smtp": "postfix", "dns": "", "pop3": "dovecot", "imap": "dovecot",
    "mysql": "mysql", "mssql": "microsoft_sql_server", "postgresql": "postgresql",
    "redis": "redis", "mongodb": "mongodb", "elasticsearch": "elasticsearch",
    "memcached": "memcached", "rabbitmq-mgmt": "rabbitmq", "http-proxy": "",
    "http-alt": "", "vnc": "vnc", "smb": "samba", "rdp": "",
}


def _http_probe(ip: str, port: int, timeout: float = _HTTP_TIMEOUT) -> str:
    """Web 端口最小化 HEAD 请求，取 Server / X-Powered-By 响应头。

    只为服务指纹；不带攻击载荷、不解析 body。失败返回 ""（常态，不是错误）。
    """
    try:
        raw_req = ("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: aisec-portscan/1.0"
                   "\r\nConnection: close\r\n\r\n" % ip).encode("ascii")
        if port in _HTTPS_PORTS:
            import ssl
            ctx = ssl._create_unverified_context()   # noqa: SLF001 指纹探测不做证书校验
            s = ctx.wrap_socket(socket.create_connection((ip, port), timeout=timeout),
                                server_hostname=ip)
        else:
            s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(raw_req)
        buf = b""
        while len(buf) < 4096:
            try:
                chunk = s.recv(1024)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                break
        try:
            s.close()
        except OSError:
            pass
        head = buf.decode("utf-8", "ignore")
        m = re.search(r"^server:\s*(.+)$", head, re.I | re.M)
        mp = re.search(r"^x-powered-by:\s*(.+)$", head, re.I | re.M)
        return " ".join(x.strip() for x in (m.group(1) if m else "",
                                            mp.group(1) if mp else "") if x)
    except Exception:  # noqa: BLE001 —— 拿不到指纹是常态
        return ""


def _identify(p: dict) -> tuple:
    """端口条目 → (产品名, 版本, 置信度, 识别来源)。置信 ∈ 高/低/无。"""
    hay = "%s %s" % (p.get("banner") or "", p.get("http_server") or "")
    for rx, name in _FINGERPRINTS:
        m = rx.search(hay)
        if not m:
            continue
        ver = ""
        for g in m.groups() or ():
            if g and re.match(r"^[0-9]", g):
                ver = g
                break
        if not ver and name in ("postfix", "microsoft_ftp"):
            ver = ""                              # 这些指纹本身不带版本
        return (name, ver, "高" if ver else "低", "banner/Server头")
    m = _GENERIC_FP_RE.search(hay)
    if m and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", m.group(2)):
        return (m.group(1).lower(), m.group(2), "高", "banner 通用指纹")
    fam = _SERVICE_FAMILY.get(p.get("service") or "") or \
        _SERVICE_FAMILY.get(SERVICE_NAMES.get(p.get("port") or 0, ""))
    if fam:
        return (fam, "", "低", "端口号推断（版本未知）")
    return ("", "", "无", "")


def correlate(engine, res: dict, http_probe: bool = True) -> dict:
    """扫描结果 × 本地情报库交叉验证（就地写回，返回同一 dict）。

    每个开放端口：识别产品指纹 → AssetRiskScanner.match（CPE 版本区间判定，
    与资产体检/项目扫描同一套判据）→ 端口级风险 + 汇总 + 可派单工单清单。
    """
    from asset_scan import AssetRiskScanner, _risk_of
    if not res.get("ok"):
        return res
    ip = res.get("ip") or ""
    sc = AssetRiskScanner(engine)
    for p in res.get("open_ports") or []:
        if http_probe and (p.get("port") in _HTTP_PROBE_PORTS):
            p["http_server"] = _http_probe(ip, p["port"])
        prod, ver, conf, src = _identify(p)
        p["product"] = prod
        p["version"] = ver
        p["ident_conf"] = conf
        p["ident_src"] = src
        fs = sc.match({"name": prod, "version": ver}) if prod else []
        level, kev, cnt = _risk_of(fs, bool(ver))
        p.update({"risk_level": level if fs else ("待确认" if conf == "低" else "无已知风险"),
                  "kev_count": kev, "cve_count": cnt,
                  "findings": fs[:8],
                  "top": fs[0]["id"] if fs else "",
                  "max_score": max([f.get("score") or 0 for f in fs], default=0)})
    ops = res.get("open_ports") or []
    all_f = [f for p in ops for f in (p.get("findings") or [])]
    kev_ids = sorted({f["id"] for f in all_f if f.get("exploited")})
    res["correlation"] = {
        "scanned_docs": len(sc.docs),
        "identified": sum(1 for p in ops if p.get("product")),
        "cve_hits": len({f["id"] for f in all_f}),
        "critical": len({f["id"] for f in all_f if f.get("severity") == "CRITICAL"}),
        "high": len({f["id"] for f in all_f if f.get("severity") == "HIGH"}),
        "medium": len({f["id"] for f in all_f if f.get("severity") == "MEDIUM"}),
        "exploited": len(kev_ids),
        "kev_ids": kev_ids[:20],
        "risk_ports": sum(1 for p in ops if p.get("cve_count")),
    }
    return res


_SLAS = (("严重", "7 天（KEV/CRITICAL，按应急预案）"),
         ("高", "30 天（纳入版本迭代）"),
         ("中", "90 天（常规排期）"),
         ("低", "纳入例行巡检"),
         ("待确认", "人工确认版本后派单"),
         ("无已知风险", "跟踪即可"))


def _sla_of(level: str) -> str:
    return dict((k, v) for k, v in _SLAS).get(level, "评估后定")


def workorder_markdown(res: dict) -> str:
    """CMDB 风格七章制工单报告（对齐 CMDB风险评估报告 的版式与措辞）。

    与 result_to_markdown 的区别：这是**给运维派单用**的完整报告 ——
    带报告编号（=工单编号前缀）、检测范围边界、执行摘要、端口风险明细、
    逐条处置工单（SLA/验收标准）与复测计划。
    """
    from asset_scan import _risk_of   # noqa: F401  仅保证同源判据可见
    corr = res.get("correlation") or {}
    s = res.get("summary") or corr
    ops = res.get("open_ports") or []
    kev_ids = corr.get("kev_ids") or []
    crit, high = corr.get("critical") or 0, corr.get("high") or 0
    if corr.get("exploited") or crit:
        level = "严重"
    elif high:
        level = "高"
    elif corr.get("medium"):
        level = "中"
    elif corr.get("cve_hits"):
        level = "低"
    elif corr.get("identified"):
        level = "待确认"
    else:
        level = "无已知风险"
    rid = "PORT-%s-%s" % (time.strftime("%Y%m%d-%H%M%S"),
                          os.urandom(2).hex())

    L = []
    L.append("# 端口测绘与漏洞关联评估报告（工单版）")
    L.append("")
    L.append("- **报告编号**：%s（同时作为处置工单编号前缀）" % rid)
    L.append("- **被测目标**：%s（解析 IP：%s）" % (res.get("host"), res.get("ip")))
    L.append("- **生成时间**：%s" % res.get("ts"))
    L.append("- **数据口径**：TCP connect 端口测绘 × 服务指纹识别 × 本地情报库 CPE 版本区间交叉验证")
    L.append("- **判定依据**：模块 1 情报库（NVD CPE 版本区间 / CISA KEV 在野利用 / CVSS / "
             "官方补丁 / 处置建议），参与比对情报 %s 条" % corr.get("scanned_docs", 0))
    L.append("- **方法声明**：TCP connect（nmap -sT 同级）+ Web 端口最小化 HEAD 探测（仅取 "
             "Server/X-Powered-By 头）；离线匹配、不外发；不做 OS 指纹、不做漏洞利用验证")
    L.append("- **合规提示**：%s" % res.get("disclaimer"))
    L.append("- **保密等级**：内部秘密（Internal Confidential）")
    L.append("")
    L.append("## 一、检测范围与边界")
    L.append("")
    L.append("| 项 | 内容 |")
    L.append("|---|---|")
    L.append("| 扫描端口数 | %d（TCP connect，并发 %d，超时 %.1fs） |"
             % (res.get("scanned") or 0, res.get("workers") or 0, res.get("timeout") or 0))
    L.append("| 开放端口 | %d |" % (res.get("open_count") or 0))
    L.append("| 识别到产品指纹 | %d 个端口（banner/Server头/端口推断） |" % corr.get("identified", 0))
    L.append("| 扫描耗时 | %s ms |" % res.get("elapsed_ms"))
    L.append("")
    L.append("**明确不在本次范围内**（不做推测、不按「无风险」处理）：")
    L.append("")
    L.append("- 非公开服务：仅扫常见端口与用户指定端口，未做 1-65535 全端口扫描")
    L.append("- Web 应用层漏洞（SQL 注入/XSS 等）、弱口令、TLS 配置——需专用扫描器")
    L.append("- 漏洞可利用性验证（PoC 实打）——本报告只做「指纹 × 情报库」匹配")
    L.append("- 未在情报库登记的产品漏洞无法命中（漏报可能存在）")
    L.append("")
    L.append("## 二、执行摘要")
    L.append("")
    L.append("> **整体风险等级：%s**。" % level)
    L.append("")
    L.append("- 开放端口 %d 个，识别产品指纹 %d 个，命中 CVE %d 个"
             "（CRITICAL %d / HIGH %d / 中危 %d）"
             % (res.get("open_count") or 0, corr.get("identified") or 0,
                corr.get("cve_hits") or 0, crit, high, corr.get("medium") or 0))
    if kev_ids:
        L.append("- **其中 %d 个在 CISA KEV 在野利用清单：%s**"
                 % (len(kev_ids), "、".join(kev_ids[:8])))
    if not corr.get("cve_hits") and not corr.get("identified"):
        L.append("- 未识别出产品指纹且未命中已知漏洞（常见于全端口过滤或非通用服务），"
                 "建议对关键业务端口做人工确认。")
    L.append("")
    L.append("### 2.1 端口风险分布")
    L.append("")
    L.append("| 风险等级 | 端口数 | SLA |")
    L.append("|---|---:|---|")
    for lv, _sla in _SLAS:
        n = sum(1 for p in ops if p.get("risk_level") == lv)
        if n:
            L.append("| %s | %d | %s |" % (lv, n, _sla_of(lv)))
    L.append("")
    L.append("## 三、端口与服务风险明细")
    L.append("")
    risky = [p for p in ops if p.get("cve_count")]
    if risky:
        L.append("| 端口 | 服务 | 产品指纹 | 版本 | 置信 | 风险 | CVE 数 | 最高 CVSS | KEV | 最高风险编号 |")
        L.append("|---|---|---|---|:-:|---|---:|---:|:-:|---|")
        for p in risky:
            L.append("| **%d** | %s | %s | %s | %s | **%s** | %d | %s | %s | %s |"
                     % (p["port"], p.get("service") or "-",
                        p.get("product") or "-", p.get("version") or "版本未知",
                        p.get("ident_conf") or "-", p.get("risk_level") or "-",
                        p["cve_count"], p.get("max_score") or "—",
                        ("⚠ %d" % p["kev_count"]) if p.get("kev_count") else "",
                        p.get("top") or "—"))
    else:
        L.append("所有开放端口均未命中已知 CVE。")
    L.append("")
    no_ident = [p for p in ops if not p.get("product")]
    if no_ident:
        L.append("> 未识别出产品指纹的端口：%s（服务名 %s）——不硬凑 CVE，"
                 "建议人工确认服务类型后再评估。"
                 % ("、".join(str(p["port"]) for p in no_ident[:12]),
                    "、".join(sorted({p.get("service") or "?" for p in no_ident}))))
        L.append("")
    L.append("## 四、处置工单（按风险降序，可直接下发）")
    L.append("")
    wo = 0
    for p in risky:
        for f in (p.get("findings") or [])[:4]:
            if f.get("severity") not in ("CRITICAL", "HIGH") and not f.get("exploited"):
                continue
            wo += 1
            acts = []
            if f.get("exploited"):
                acts.append("**已在野利用（CISA KEV %s），按应急预案立即处置**"
                            % (f.get("kev_added") or "日期未知"))
            if (f.get("score") or 0) >= 9:
                acts.append("CVSS %.1f，SLA 7 天内完成修复" % f["score"])
            elif (f.get("score") or 0) >= 7:
                acts.append("CVSS %.1f，SLA 30 天内纳入版本迭代" % f["score"])
            rem = (f.get("remediation") or [])
            if rem:
                acts.append(str(rem[0])[:140])
            if not acts:
                acts.append("列入跟踪")
            L.append("### WO-%s-%02d　%s：%d（%s %s）— %s"
                     % (rid[-13:], wo, res.get("host"), p["port"],
                        p.get("product") or "未知服务",
                        p.get("version") or "版本未知", f.get("severity") or ""))
            L.append("")
            L.append("- **命中**：%s（CVSS %s，%s）%s"
                     % (f.get("id"), f.get("score") or "—", f.get("severity") or "",
                        "　**KEV 在野利用**" if f.get("exploited") else ""))
            if f.get("title"):
                L.append("- **描述**：%s" % str(f["title"])[:150])
            L.append("- **处置**：%s" % "；".join(acts))
            L.append("- **验收标准**：处置后同参数复扫，该端口产品版本不再落在受影响区间"
                     "（或服务已下线/加访问控制）")
            L.append("")
            if wo >= 20:
                break
        if wo >= 20:
            L.append("> 仅列前 20 条工单，完整明细见 JSON 版（GET /api/port_scan?id=）。")
            break
    tracked = [p for p in ops if p.get("cve_count") and p.get("risk_level") in ("中", "低")]
    if tracked:
        L.append("**列入跟踪**（中低危，按 SLA 常规排期）：%s"
                 % "、".join("%d/%s" % (p["port"], p.get("top") or "") for p in tracked[:10]))
        L.append("")
    if not wo:
        L.append("无 CRITICAL/HIGH/KEV 条目。%s"
                 % ("按常规节奏升级组件即可。" if corr.get("cve_hits")
                    else "保持周期性复扫，关注新情报。"))
        L.append("")
    L.append("## 五、口径与边界（不做的就不声称）")
    L.append("")
    L.append("- 识别置信度：banner / HTTP Server 头带版本=「高」（CPE 区间判定）；"
             "端口号推断=「低」（产品级全区间，**需人工确认版本后再派单**，不等于无风险）。")
    L.append("- connect 扫描只判「能否建立 TCP 连接」：防火墙 whitelisting 下的端口可能漏判。")
    L.append("- 版本指纹来自 banner/响应头，服务端可能伪装或隐藏版本（低置信结果须人工核实）。")
    L.append("- 命中数以「端口 × 情报库」为口径；同一 CVE 命中多个端口时按编号去重统计。")
    L.append("")
    L.append("## 六、复测计划")
    L.append("")
    L.append("1. 处置责任人在 SLA 内完成升级/加固，并在 CMDB 登记变更单号；")
    L.append("2. 安全组在 SLA 到期后用**相同参数**（同端口集/超时）复扫一次，比对开放端口与版本指纹；")
    L.append("3. 复扫报告与本报告同编号追加 -R1 后缀归档，未闭环工单顺延升级至部门负责人。")
    L.append("")
    return "\n".join(L)


# ── 报告渲染（与 asset_scan.report_to_markdown 同风格） ─────────────
def result_to_markdown(res: dict) -> str:
    L = []
    L.append("# 端口测绘报告 · %s" % res.get("host", ""))
    L.append("")
    L.append("- **目标**：%s（解析 IP：%s）" % (res.get("host"), res.get("ip")))
    L.append("- **扫描时间**：%s" % res.get("ts"))
    L.append("- **方法**：TCP connect（%d 端口，并发 %d，超时 %.1fs）"
             % (res.get("scanned") or 0, res.get("workers") or 0, res.get("timeout") or 0))
    L.append("- **耗时**：%s ms" % res.get("elapsed_ms"))
    L.append("- **合规提示**：%s" % res.get("disclaimer"))
    L.append("")
    L.append("## 开放端口（%d / %d）" % (res.get("open_count") or 0, res.get("scanned") or 0))
    L.append("")
    ops = res.get("open_ports") or []
    if ops:
        L.append("| 端口 | 服务 | Banner（被动接收） |")
        L.append("|---|---|---|")
        for p in ops:
            L.append("| **%d** | %s | %s |" % (p["port"], p["service"],
                                               (p.get("banner") or "—（未主动推送）")
                                               .replace("|", "\\|")[:80]))
    else:
        L.append("无开放端口（或全部被防火墙过滤）。")
    L.append("")
    L.append("> 方法说明：%s" % res.get("note"))
    L.append("")
    return "\n".join(L)
