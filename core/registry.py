# -*- coding: utf-8 -*-
"""
registry.py —— 模块注册中心（核心层）
============================================================
主体只做三件事：HTTP 宿主、静态资源、把请求转给注册表。
每个模块在自己的 ``modules/<id>/api.py`` 里写::

    def register(ctx):
        ctx.route("GET", "/api/live", handle_live)
        ctx.on_start(start)          # 可选：启动后台线程

于是**合并 = 把模块文件夹复制进来**，不需要再手改 server.py 或 app.js。

模块清单 ``modules/<id>/module.json``：:

    {
      "id": "m1_monitor",
      "name": "情报监测",
      "owner": "成员A",
      "enabled": true,
      "backend_dirs": ["backend"],       # 加入 sys.path 的目录（模块内部互相 import）
      "entry": "api.py",                 # 注册入口
      "web": ["web/panel.js"],           # 自动注入 index.html 的前端脚本
      "routes": ["GET /api/live"],       # 声明式路由清单（文档/核查用）
      "docs": "docs"
    }

任何模块被删掉/禁用，主体依旧能启动，只是少了那部分 API 与前端面板。
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
import sys
import traceback

import paths

ROUTE_ORDER = ("GET", "POST", "PUT", "DELETE")


class Request:
    """一次 HTTP 请求的轻量封装（模块 handler 拿到它就能干活）"""

    __slots__ = ("h", "method", "path", "qs", "body", "module_id",
                 "_rfile", "_length", "_remaining")

    def __init__(self, handler, method, path, qs, body=b"", module_id=""):
        self.h = handler
        self.method = method
        self.path = path
        self.qs = qs or {}
        self.body = body or b""
        self.module_id = module_id
        self._rfile = None       # 流式模式：直接从 socket 读，不落中间文件
        self._length = 0
        self._remaining = 0

    # ---- 大请求的流式支持（2026-10-06，两轮迭代）----
    # 背景：CMDB 全量 .db 上百 MB，最初实现 `self.rfile.read(length)`
    # 把整个请求体一次性读进内存，再由 API 层切片复制
    # → 峰值内存是文件体积的 2~3 倍。688MB 的库在浏览器侧
    # 表现为 "Failed to fetch"（连 HTTP 状态码都拿不到）。
    #
    # 第一版改成“先落临时文件、再由 API 读盘切分”，内存问题解决了，
    # 但实测 122MB 的库跑了 1800 秒还没完 —— 因为**磁盘 I/O 走了两遍**：
    #   socket → 临时文件（全量写）→ 读临时文件 → 切分成 N 个 .db（再全量写）
    # 对 688MB 就是 2.7GB 的磁盘往返，纯属白干。
    #
    # 现在改成零拷贝：直接把 socket 流交给 API 层，边收边切分。
    # 磁盘写入只有一次（就是最终那 N 个 .db），内存峰值 = 一个 chunk。
    def begin_stream(self, length, rfile):
        """切到流式模式，直接从 rfile（socket）读。返回 True 表示已切换。

        调用方（server.do_POST）在 dispatch 前调用。handler 消费完后
        会自动切回内存模式（finish_stream）。
        """
        if not length or length <= self.STREAM_THRESHOLD:
            return False
        self._rfile = rfile
        self._length = length
        self._remaining = length
        return True

    # 超过这个体积就走流式。取 32MB：JSON/base64 路径本来也不应传这么大，
    # 走流式反而更安全；真实场景里 24MB 的单文件上限（MAX_UPLOAD）仍在 API 层生效。
    STREAM_THRESHOLD = 32 * 1024 * 1024

    def iter_body(self, chunk=1024 * 1024):
        """按块产出请求体字节。流式模式直接从 socket 读，否则产出内存里的 body。

        ★ 严格按 _remaining 截断：socket 上的字节可能超出 Content-Length
          （浏览器未等上一个请求完就发下一个），多读会污染下一个请求。
        """
        if self._rfile is not None:
            while self._remaining > 0:
                buf = self._rfile.read(min(chunk, self._remaining))
                if not buf:
                    break        # 客户端提前断开：正常结束，由调用方按“字节不足”报错
                self._remaining -= len(buf)
                yield buf
            return
        if self.body:
            yield self.body

    def finish_stream(self):
        """流式结束：只清标记，无需关句柄（rfile 由 http.server 自己管）。"""
        self._rfile = None
        self._remaining = 0

    # ---- 常用取值 ----
    def q(self, name, default=""):
        return (self.qs.get(name) or [default])[0]

    def q_int(self, name, default=0):
        try:
            return int(self.q(name) or default)
        except (TypeError, ValueError):
            return default

    def q_float(self, name, default=0.0):
        """同 q_int：非法值退回默认值，不让 ?cvss_min=abc / ?hours=xx 把请求打成 500"""
        try:
            return float(self.q(name) or default)
        except (TypeError, ValueError):
            return default

    def json_body(self, default=None):
        try:
            return json.loads(self.body.decode("utf-8")) if self.body else (default if default is not None else {})
        except (ValueError, UnicodeDecodeError):
            return None

    def header(self, name, default=""):
        """读请求头（大小写不敏感，http.server 已做规范化）。"""
        try:
            return self.h.headers.get(name) or default
        except AttributeError:
            return default

    # ---- 响应 ----
    def json(self, obj, code=200, etag=None):
        return self.h._json(obj, code, etag)

    def send(self, code, body, ctype="application/json; charset=utf-8", **kw):
        return self.h._send(code, body, ctype, **kw)

    @property
    def engine(self):
        return self.h.core.get_engine()


class ModuleCtx:
    """模块拿到的上下文：注册路由 / 启动钩子 / 取路径与核心能力"""

    def __init__(self, registry, manifest, mod_dir):
        self.registry = registry
        self.manifest = manifest
        self.id = manifest["id"]
        self.name = manifest.get("name", self.id)
        self.owner = manifest.get("owner", "")
        self.dir = mod_dir
        self.backend_dir = os.path.join(mod_dir, manifest.get("backend_dirs", ["backend"])[0])
        self.state = {}                     # 模块自留的全局状态
        self._get_routes = []
        self._post_routes = []
        self._start_hooks = []

    # ---- 注册 ----
    def route(self, method, path, fn):
        method = method.upper()
        if method == "GET":
            if not any(p == path for _f, p in self._get_routes):
                self._get_routes.append((fn, path))
        elif method == "POST":
            if not any(p == path for _f, p in self._post_routes):
                self._post_routes.append((fn, path))
        else:
            raise ValueError("暂只支持 GET/POST 路由：" + method)

    def on_start(self, fn):
        """服务启动后调用（用于起后台线程，参数：app=核心能力对象）"""
        self._start_hooks.append(fn)

    # ---- 便捷访问 ----
    @property
    def core(self):
        return self.registry.core

    @property
    def data_dir(self):
        return paths.DATA_DIR

    def data_path(self, *parts):
        return paths.data_path(*parts)

    def log(self, msg):
        print(f"[{self.id}] {msg}", flush=True)


class Registry:
    def __init__(self, core=None, config=None):
        self.core = core
        self.config = config or paths.load_config()
        self.modules = {}          # id -> ModuleCtx（已加载成功）
        self.skipped = {}          # id -> 原因（未启用/加载失败）
        self._get = {}             # path -> (module_id, fn)
        self._post = {}

    # ---------------- 发现 ----------------
    def discover(self):
        found = []
        if not os.path.isdir(paths.MODULES_DIR):
            return found
        for name in sorted(os.listdir(paths.MODULES_DIR)):
            d = os.path.join(paths.MODULES_DIR, name)
            man_fp = os.path.join(d, "module.json")
            if not os.path.isfile(man_fp):
                continue
            try:
                with open(man_fp, "r", encoding="utf-8") as f:
                    man = json.load(f)
            except (OSError, ValueError) as e:
                self.skipped[name] = f"module.json 解析失败：{e}"
                continue
            man.setdefault("id", name)
            found.append((man, d))
        return found

    # ---------------- 加载 ----------------
    def load_all(self):
        for man, d in self.discover():
            mid = man["id"]
            cfg_flag = (self.config.get("modules") or {}).get(mid)
            enabled = man.get("enabled", True) if cfg_flag is None else bool(cfg_flag)
            if not enabled:
                self.skipped[mid] = "config.json 中已禁用"
                continue
            try:
                self._load_one(man, d)
            except Exception as e:                                    # noqa: BLE001
                self.skipped[mid] = f"加载失败：{e}"
                print(f"!! 模块 {mid} 加载失败（已跳过，主体继续运行）：{e}", flush=True)
                traceback.print_exc()
        return self.modules

    def _load_one(self, man, mod_dir):
        mid = man["id"]
        ctx = ModuleCtx(self, man, mod_dir)
        # 模块内部互相 import：把 core 与模块自己的 backend 目录放进 sys.path
        for p in (paths.CORE_DIR, ctx.backend_dir):
            if p not in sys.path:
                sys.path.insert(0, p)
        entry = man.get("entry", "api.py")
        entry_fp = os.path.join(mod_dir, entry)
        if not os.path.isfile(entry_fp):
            raise FileNotFoundError(entry)
        spec = importlib.util.spec_from_file_location(f"{mid}_api", entry_fp)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[f"{mid}_api"] = mod
        spec.loader.exec_module(mod)
        if not hasattr(mod, "register"):
            raise AttributeError("api.py 缺少 register(ctx) 函数")
        mod.register(ctx)
        for fn, path in ctx._get_routes:
            self._get[path] = (mid, fn)
        for fn, path in ctx._post_routes:
            self._post[path] = (mid, fn)
        self.modules[mid] = ctx

    # ---------------- 分发 ----------------
    def dispatch(self, req):
        table = self._get if req.method == "GET" else self._post
        hit = table.get(req.path)
        if not hit:
            return False
        mid, fn = hit
        req.module_id = mid
        fn(req)
        return True

    # ---------------- 启动钩子 ----------------
    def start(self):
        for mid, ctx in self.modules.items():
            for fn in ctx._start_hooks:
                try:
                    fn(self.core)
                except Exception as e:                                # noqa: BLE001
                    print(f"!! 模块 {mid} 启动钩子异常：{e}", flush=True)
                    traceback.print_exc()

    # ---------------- 前端资源 ----------------
    def web_scripts(self):
        """返回 [(url, 磁盘路径)]，按模块顺序注入 index.html"""
        out = []
        for mid, ctx in self.modules.items():
            for rel in ctx.manifest.get("web", []) or []:
                fp = os.path.join(ctx.dir, rel.replace("/", os.sep))
                url = f"/modules/{mid}/{rel}"
                if os.path.isfile(fp):
                    out.append((url, fp))
                else:
                    print(f"!! 模块 {mid} 声明的前端文件不存在：{rel}", flush=True)
        return out

    def summary(self):
        lines = []
        for mid, ctx in self.modules.items():
            n = sum(1 for p, (m, _f) in self._get.items() if m == mid) + \
                sum(1 for p, (m, _f) in self._post.items() if m == mid)
            lines.append(f"  · {ctx.name}({mid})：{n} 个接口"
                         + (f" · 负责人 {ctx.owner}" if ctx.owner else ""))
        for mid, why in self.skipped.items():
            lines.append(f"  · {mid}：未加载（{why}）")
        return "\n".join(lines) if lines else "  （未发现任何模块）"
