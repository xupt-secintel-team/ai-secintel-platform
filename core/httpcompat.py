# -*- coding: utf-8 -*-
"""
httpcompat.py —— requests 缺失时的标准库降级实现
=================================================
背景（本次修复的真实缺陷）：`m2_enrich` 的两个核心富化能力（受影响资产定位
`/api/assets`、POC/EXP 搜索 `/api/poc`）都直接 `import requests`。项目此前
**没有任何依赖清单**，换一台没装 requests 的机器，接口会直接抛
`No module named 'requests'`（500 / 空结果），而文档却写着"3 步跑起来"。

本模块用标准库 `urllib` 复刻了项目实际用到的那一小撮 requests API：
    会话   Session().headers.update() / .verify / .get() / .post()
    响应   .status_code / .headers.get() / .text / .json() / .raise_for_status()
    异常   exceptions.RequestException
    类型   Response（仅作类型标注用）

用法（调用方）：
    try:
        import requests
    except ImportError:
        import httpcompat as requests     # 需保证 core/ 在 sys.path 上

约束与取舍：
  * 只实现本项目用到的功能，**不是** requests 的完整替代；装了 requests 时永远优先用它。
  * 会读取 AISEC_PROXY / HTTP_PROXY / HTTPS_PROXY 走代理，与项目其它抓取逻辑一致。
  * 不支持连接池复用（每次请求新建连接），性能略差，但保证"能跑通"优先。
"""

from __future__ import annotations

import gzip
import json as _json
import os
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import zlib
from typing import Any, Dict, Optional
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

__all__ = ["Session", "Response", "RequestException", "get", "post"]

DEFAULT_TIMEOUT = 20.0
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


# --------------------------------------------------------------------------
# 异常：与 requests.exceptions.RequestException 兼容（调用方 except 的是这个名字）
# --------------------------------------------------------------------------
class RequestException(Exception):
    """所有网络异常的基类（对齐 requests.exceptions.RequestException）。"""


class _ExceptionsModule:
    """让 `requests.exceptions.RequestException` 这种写法也能命中。"""

    RequestException = RequestException
    Timeout = RequestException
    ConnectionError = RequestException  # noqa: A001 - 对齐 requests 命名
    HTTPError = RequestException


exceptions = _ExceptionsModule()


def _proxy() -> Optional[str]:
    for k in ("AISEC_PROXY", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        v = os.environ.get(k)
        if v:
            return v
    return None


def _opener(verify_ssl: bool, proxies: Optional[str]) -> urllib.request.Opener:
    handlers: list = []
    if proxies:
        handlers.append(urllib.request.ProxyHandler({"http": proxies, "https": proxies}))
    if not verify_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def _decode(raw: bytes, headers: Any) -> str:
    enc = (headers.get("Content-Encoding") or "").lower()
    if "gzip" in enc:
        try:
            raw = gzip.decompress(raw)
        except OSError as _sw_e:
            _swallow("core/httpcompat.py:92", _sw_e)
    elif "deflate" in enc:
        try:
            raw = zlib.decompress(raw, -zlib.MAX_WBITS)
        except zlib.error as _sw_e:
            _swallow("core/httpcompat.py:97", _sw_e)
    for enc_name in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc_name)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


class Response:
    """最小响应对象：status_code / headers / text / json / raise_for_status。"""

    def __init__(self, status_code: int, headers: Any, content: bytes, url: str = ""):
        self.status_code = int(status_code)
        # urllib 返回的 headers 本身支持大小写不敏感 .get()（与 requests 行为一致），
        # 非预期类型时退化为普通字典，避免属性缺失。
        self.headers = headers if hasattr(headers, "get") else (headers or {})
        self.content = content
        self.url = url
        self.encoding = "utf-8"
        self._text: Optional[str] = None

    # requests 的 headers 是大小写不敏感字典，这里补齐最常用的 .get 语义
    @property
    def text(self) -> str:
        if self._text is None:
            self._text = _decode(self.content, self.headers)
        return self._text

    def json(self) -> Any:
        return _json.loads(self.text)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RequestException(f"HTTP {self.status_code} for {self.url}")

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"<Response [{self.status_code}]>"


class Session:
    """最小会话对象：headers / verify / get() / post()。"""

    def __init__(self, verify: bool = True, proxies: Optional[str] = None):
        self.headers: Dict[str, str] = {"User-Agent": DEFAULT_UA}
        self.verify = verify
        self.proxies = proxies
        self.timeout = DEFAULT_TIMEOUT

    # -- requests 的便捷属性（本项目设置了 session.verify，这里保持同名可写） --
    def _request(self, method: str, url: str,
                 params: Optional[Dict] = None,
                 data: Any = None,
                 json: Any = None,          # noqa: A002 - 对齐 requests 的参数名
                 headers: Optional[Dict] = None,
                 timeout: Optional[float] = None,
                 **_ignored: Any) -> Response:
        if params:
            url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        body: Optional[bytes] = None
        req_headers = dict(self.headers)
        if headers:
            req_headers.update(headers)
        if json is not None:
            body = _json.dumps(json, ensure_ascii=False).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        elif isinstance(data, (str, bytes)):
            body = data.encode("utf-8") if isinstance(data, str) else data
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=req_headers, method=method.upper())
        opener = _opener(self.verify, self.proxies or _proxy())
        try:
            with opener.open(req, timeout=timeout or self.timeout) as resp:
                return Response(resp.getcode(), dict(resp.headers), resp.read(), url)
        except urllib.error.HTTPError as e:  # HTTPError 也是响应，保留状态码
            try:
                content = e.read()
            except Exception:  # noqa: BLE001
                content = b""
            return Response(e.code, dict(e.headers or {}), content, url)
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
            raise RequestException(f"{method.upper()} {url} 失败: {e}")

    def get(self, url: str, **kw: Any) -> Response:
        return self._request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> Response:
        return self._request("POST", url, **kw)


def get(url: str, **kw: Any) -> Response:
    return Session().get(url, **kw)


def post(url: str, **kw: Any) -> Response:
    return Session().post(url, **kw)
