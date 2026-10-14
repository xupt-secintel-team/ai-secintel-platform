# -*- coding: utf-8 -*-
"""logrotate.py —— 日志轮转（按大小切分 + 保留 N 份）

为什么需要（2026-10-06 代码核查发现）：
  `测试报告/运行日志_<port>.log` 与 `watchdog_<port>.log` 都是裸 `open(..., "a")`，
  **没有任何上限**。服务常驻几周 + 每次重启写两行标记 + 每次探活写一行，
  日志会单调增长到把磁盘吃满；而磁盘写满恰恰是"服务起不来"的典型诱因，
  形成自锁死循环。评审「监控告警 / 运维完备」这一档也查得到点子上。

本模块提供 `RotatingLog`，用「大小阈值 + 世代后缀」轮转：
  运行日志_8848.log           ← 当前正在写
  运行日志_8848.log.1         ← 上一个世代
  运行日志_8848.log.2         ← 更早（保留 KEEP 份，超出丢弃）

它是**纯标准库**、无第三方依赖，可直接被 tools/ 与 core/ 引用。
既能给 stdout/stderr 直接当文件对象用（Popen(stdout=fp)），
也能配合 watchdog 的 log_line 逐行写。
"""
from __future__ import annotations

import os
import threading

DEFAULT_MAX_BYTES = 8 * 1024 * 1024      # 单份上限 8 MB
DEFAULT_KEEP = 5                          # 保留 5 个历史世代（共约 48 MB/文件）


def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def human(n):
    """字节数转人类可读（给 /api/logs 用，避免运维看裸字节）"""
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.1f%s" % (n, unit)
        n /= 1024.0
    return "%.1fGB" % n


class RotatingLog:
    """带轮转的文本文件对象（write/flush/fileno 足够 subprocess 用）。"""

    def __init__(self, path, max_bytes=DEFAULT_MAX_BYTES, keep=DEFAULT_KEEP,
                 encoding="utf-8"):
        self.path = path
        # 下限 64 而不是 1024：原实现用 max(1024, …) 会把用户显式配的
        # 小阈值静默抬到 1MB（实测传 100 变成 1024，日志照涨 198 字节不轮转）。
        # 配置被静默改写是最难查的一类问题 —— 这里只保留"防止阈值 absurd
        # 到会截断一切"的下限。
        self.max_bytes = max(64, int(max_bytes))
        self.keep = max(1, int(keep))
        self.encoding = encoding
        self._fp = None
        self._written = 0
        self._lock = threading.Lock()
        self.rotations = 0                   # 累计轮转次数（可观测）
        self.dropped_bytes = 0               # 因超过 keep 被丢弃的旧世代大小
        self.open()

    # —— 内部 ——
    def _shift(self):
        """世代推进：丢弃最老一份，其余整体后移，最后把**当前文件移到 .1**。

        最后一步是关键：少了它，每轮都只是把 .1/.2 反复覆盖，而当前文件
        原地无限增长（实测写入 20800 字节、阈值 2048、完全不轮转）。
        """
        # ① 丢掉超出 keep 的最老一份
        oldest = "%s.%d" % (self.path, self.keep)
        if os.path.exists(oldest):
            self.dropped_bytes += _size(oldest)
            try:
                os.remove(oldest)
            except OSError:
                pass
        # ② .keep-1 → .keep, …, .1 → .2（从大到小，避免覆盖）
        for i in range(self.keep - 1, 0, -1):
            src, dst = "%s.%d" % (self.path, i), "%s.%d" % (self.path, i + 1)
            if os.path.exists(src):
                try:
                    if os.path.exists(dst):
                        os.remove(dst)
                    os.replace(src, dst)
                except OSError:
                    pass
        # ③ 当前文件 → .1
        if os.path.exists(self.path):
            try:
                if os.path.exists("%s.1" % self.path):
                    os.remove("%s.1" % self.path)
                os.replace(self.path, "%s.1" % self.path)
            except OSError:
                pass

    def _reopen(self, force_rotate=False):
        """重开文件。force_rotate=True 时无条件做一次世代推进。

        ★ 曾经栽在这里：write() 按 "_written + nb > max" 判断该轮转，
          而 _reopen() 内部又按 "_size(path) >= max" 自行判一次。
          两个条件不等价 —— 触轮转时文件其实还没到 max（比如 4050/4096），
          于是 shift 压根没被调用，文件越过阈值继续长。
          实测：阈值 4096 的日志长到 4100；阈值 100 的长到 198。
          现在轮转决策只保留在 write() 一处，_reopen() 不再自己判断。
        """
        if self._fp:
            try:
                self._fp.close()
            except OSError:
                pass
        if force_rotate or _size(self.path) >= self.max_bytes:
            self._shift()
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        # newline="\n"：关掉 Windows 的 \n → \r\n 翻译。开着的话
        # 每写一行磁盘上多一个字节，而下面按 s.encode() 的长度记账，
        # 账本与磁盘实际占用会逐行漂移（实测 79 行后已差 80 字节）。
        self._fp = open(self.path, "a", encoding=self.encoding,
                        errors="replace", newline="\n")
        self._written = _size(self.path)

    def open(self):
        with self._lock:
            self._reopen(force_rotate=_size(self.path) >= self.max_bytes)

    # —— 文件对象协议 ——
    def write(self, s):
        if not isinstance(s, str):
            s = str(s)
        nb = len(s.encode(self.encoding, "replace"))
        with self._lock:
            if self._fp is None:
                self._reopen()
            # 切两刀：
            #  ① 已写内容 + 这一笔 会超 → 先轮转，让这一笔从新文件头部写起
            #  ② 这一笔**自己就比整份上限还大** → 无法靠切分约束（Python 文本
            #     流没法把一个 str 写成多段而中间不换行），此时只有两条路：
            #     截断并在行尾标注，绝不能让文件无上限增长。
            #     （原实现缺 ② ：单笔 99 字节写进 max=100 的文件，
            #       再写一笔就变成 198 字节 —— 硬上限失效。）
            if self._written > 0 and self._written + nb > self.max_bytes:
                self.rotations += 1
                self._reopen(force_rotate=True)
            if nb > self.max_bytes:
                enc = self.encoding
                raw = s.encode(enc, "replace")
                # 标注行本身也要算进预算，否则"截断说明"会把文件顶出上限
                # （max=100 时标注就有 40 字节，留 64 字节不够）
                tail_tpl = "[…本条超上限，已截断 %d 字节…]\n"
                tail_len = len(tail_tpl % len(raw))
                # 至少留一半给正文：阈值很小时（64 字节）如果全给标注行，
                # 就会变成"只留一句超上限提示、正文全丢"。
                budget = max(self.max_bytes // 2, self.max_bytes - tail_len - 1)
                budget = min(budget, self.max_bytes - tail_len - 1)
                head = raw[:budget].decode(enc, "replace")
                tail = tail_tpl % (len(raw) - len(head.encode(enc, "replace")))
                self._fp.write(head)
                self._fp.write("\n" + tail)
                self._written = len(head.encode(enc, "replace")) + \
                    len(tail.encode(enc, "replace")) + 1
                # 立刻轮转，让下一笔从干净文件开始
                self.rotations += 1
                self._reopen(force_rotate=True)
                return len(s)
            self._fp.write(s)
            self._written += nb
        return len(s)

    def flush(self):
        with self._lock:
            if self._fp:
                try:
                    self._fp.flush()
                except OSError:
                    pass

    def fileno(self):
        """subprocess 需要真 fd。Windows 上 open 的文件没有真 fd 时返回 -1，
        调用方（Popen stdout）应改用自己 open 的句柄。"""
        try:
            return self._fp.fileno()
        except Exception:  # noqa: BLE001
            return -1

    def close(self):
        with self._lock:
            if self._fp:
                try:
                    self._fp.flush()
                    self._fp.close()
                except OSError:
                    pass
                self._fp = None

    # —— 可观测 ——
    def stats(self):
        files = []
        for name in [os.path.basename(self.path)] + \
                ["%s.%d" % (os.path.basename(self.path), i) for i in range(1, self.keep + 1)]:
            fp = os.path.join(os.path.dirname(self.path), name)
            if os.path.exists(fp):
                files.append({"name": name, "bytes": _size(fp)})
        return {
            "path": self.path,
            "max_bytes": self.max_bytes,
            "keep": self.keep,
            "rotations": self.rotations,
            "dropped_bytes": self.dropped_bytes,
            "total_bytes": sum(f["bytes"] for f in files),
            "total_human": human(sum(f["bytes"] for f in files)),
            "files": files,
        }


def rotate_once(path, max_bytes=DEFAULT_MAX_BYTES, keep=DEFAULT_KEEP):
    """不打开写入句柄、只做一次轮转判断（给"启动时清历史"用）。返回是否发生了轮转。"""
    if _size(path) < max_bytes:
        return False
    rl = RotatingLog(path, max_bytes=max_bytes, keep=keep)
    rl.close()
    return True


def logs_overview(root, max_bytes=DEFAULT_MAX_BYTES, keep=DEFAULT_KEEP):
    """扫 `测试报告/*.log`，给出每个文件的体积与"是否已超阈值"。"""
    d = os.path.join(root, "测试报告")
    out = []
    if not os.path.isdir(d):
        return out
    for fn in sorted(os.listdir(d)):
        if ".log" not in fn:
            continue
        base = fn.split(".log")[0]
        fp = os.path.join(d, fn)
        total = _size(fp)
        gens = [g for g in os.listdir(d) if g.startswith(base + ".log.")]
        gtotal = sum(_size(os.path.join(d, g)) for g in gens)
        out.append({
            "name": base,
            "current_bytes": total,
            "current_human": human(total),
            "generations": len(gens),
            "total_bytes": total + gtotal,
            "total_human": human(total + gtotal),
            "over_limit": total >= max_bytes,
            # 已有历史世代 = 轮转确实发生过。仅有 over_limit 只是"即将轮转"，
            # 两者都不成立时该文件还没到过阈值 —— 别一律显示"轮转中"。
            "rotating": len(gens) > 0,
        })
    return out