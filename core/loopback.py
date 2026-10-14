# -*- coding: utf-8 -*-
"""loopback.py —— 本机回环请求免代理（2026-10-06 补）

问题：机器上设过系统代理（HTTP_PROXY / 常见于公司网/VPN 环境）时，
`urllib.request.urlopen("http://127.0.0.1:8848/...")` 会**把本机请求也发给代理**，
代理当然连不上这个端口 → `HTTP Error 502: Bad Gateway`。

症状极具迷惑性：服务明明在跑、浏览器能打开，评测脚本却全线 502，
很容易误判成"服务坏了"或"接口有问题"。本机 `curl --noproxy '*'` 就正常。

解决：`no_proxy_env()` 返回一份清掉了所有代理变量的环境映射，
在跑本机评测的脚本里 `os.environ.update(...)` 一下即可；
`call()` 则是给不想改全局环境的场合用的局部版本。

注意：这只影响**回环地址**。访问境外站点仍应走代理 —— 各评测脚本里
真正的外网请求走的是 core/net.py（它有自己的代理探测），不受这里影响。
"""
from __future__ import annotations

import urllib.request

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "0.0.0.0", "[::1]", "::1")
_PROXY_KEYS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
               "ALL_PROXY", "all_proxy", "FTP_PROXY", "ftp_proxy")


def is_loopback(url_or_host: str) -> bool:
    """判断是否指向本机（也接受裸 host:port 形式）。"""
    s = (url_or_host or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):
        return s.split("]")[0] + "]" in _LOOPBACK_HOSTS
    host = s.rsplit(":", 1)[0] if s.count(":") == 1 else s
    return host in _LOOPBACK_HOSTS or host.startswith("127.")


def no_proxy_env() -> dict:
    """返回一份剥掉全部代理变量的 os.environ 映射（可直接 update 进去）。"""
    import os
    env = dict(os.environ)
    for k in _PROXY_KEYS:
        env.pop(k, None)
    # urllib 只认 no_proxy 这一个变量，指向回环即豁免
    env["no_proxy"] = "127.0.0.1,localhost,::1"
    env["NO_PROXY"] = "127.0.0.1,localhost,::1"
    return env


def enable() -> None:
    """就地清掉当前进程的代理环境变量。评测脚本开头调一次即可。"""
    import os
    for k in _PROXY_KEYS:
        os.environ.pop(k, None)
    os.environ["no_proxy"] = "127.0.0.1,localhost,::1"
    os.environ["NO_PROXY"] = "127.0.0.1,localhost,::1"


# 一个"永不代理"的 opener：比改环境变量更局部，线程安全
_DIRECT = None


def direct_opener() -> urllib.request.OpenerDirector:
    global _DIRECT
    if _DIRECT is None:
        _DIRECT = urllib.request.build_opener(
            urllib.request.ProxyHandler({}))   # 空映射 = 忽略所有代理
    return _DIRECT


def call(url: str, timeout: float = 90, data=None, headers=None):
    """对回环地址发一次请求，强制不走代理；非回环地址回退到默认行为。"""
    if not is_loopback(url):
        req = urllib.request.Request(url, data=data, headers=headers or {})
        return urllib.request.urlopen(req, timeout=timeout)
    req = urllib.request.Request(url, data=data, headers=headers or {})
    return direct_opener().open(req, timeout=timeout)


if __name__ == "__main__":
    print("127.0.0.1:8848 →", is_loopback("http://127.0.0.1:8848/api/stats"))
    print("localhost:1  →", is_loopback("http://localhost:1/x"))
    print("example.com  →", is_loopback("https://www.example.com/a"))
    print("10.0.0.5     →", is_loopback("http://10.0.0.5:8848/x"))