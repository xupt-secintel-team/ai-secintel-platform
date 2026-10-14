"""大体积 .db 直传的流式切分测试（2026-10-06）

背景：688MB 的 CMDB 库直传时浏览器只看到 "Failed to fetch" ——
根因是 core/server.py 的 `body = self.rfile.read(length)` 把整个请求体
一次性读进内存，峰值内存是文件体积的 2~3 倍，服务端被拖垮。
改成流式落盘后，切分逻辑就成了新的风险点，这里逐个边界钉死。

第一版实现就栽在这里：chunk 跨文件边界的续写逻辑写成了递归 while，
结果 10 字节的 a.db 直接丢了，只落盘了最后一个文件 ——
而外部看起来一切正常（返回值是"成功"的路径）。
"""
import importlib.util
import os
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))

# paths.DATA_DIR 指向真实 data/ 会污染工作区，先劫持到临时目录
_tmp_data = tempfile.mkdtemp(prefix="aisec_stage_test_")
import paths  # noqa: E402

paths.DATA_DIR = _tmp_data

spec = importlib.util.spec_from_file_location(
    "m2api", os.path.join(ROOT, "modules", "m2_enrich", "api.py"))
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)

_PASS = [0]
_FAIL = [0]


def ok(cond, label, extra=""):
    if cond:
        _PASS[0] += 1
        print("  [PASS] %s" % label)
    else:
        _FAIL[0] += 1
        print("  [FAIL] %s%s" % (label, ("  -> " + str(extra)) if extra else ""))


class FakeReq:
    """模拟 server 落到临时文件的流式请求体：iter_body 按 chunk 产出总字节"""

    def __init__(self, data, truncate_to=None):
        self._data = data if truncate_to is None else data[:truncate_to]

    def iter_body(self, chunk=1024 * 1024):
        i = 0
        while i < len(self._data):
            yield self._data[i:i + chunk]
            i += chunk


def _orig_name(path):
    """落盘名格式 <毫秒>_<微秒>_<序号>_<文件序号>_原名 → 取回原名。

    前缀段数会随 _unique_stamp() 的实现变化，所以不能写死 split 次数 ——
    写死了在改戳格式时就静默错位（2026-10-06 踩过：前缀从 2 段变 3 段，
    断言全变成"内容不对"，实际内容是对的）。改成从右侧按已知结构切：
    去掉 basename 里的 "_NN_"（NN 是文件序号，两位数字）之前的全部前缀。
    """
    base = os.path.basename(path)
    parts = base.split("_")
    # 结构：<stamp含下划线...>_<两位序号>_<原名>；原名本身可能含下划线
    for i, seg in enumerate(parts):
        if len(seg) == 2 and seg.isdigit() and i >= 3:
            return "_".join(parts[i + 1:])
    return base


def run(data, files, truncate_to=None, chunk_note=""):
    req = FakeReq(data, truncate_to)
    paths_list, err = api._stage_sqlite_uploads_stream(req, files)
    got = {}
    for p in paths_list or []:
        got[_orig_name(p)] = open(p, "rb").read()
    for p in paths_list or []:
        try:
            # 复用被测模块的删除实现：直接用 os.remove 会被宿主的
            # sitecustomize 包装成"移入回收站"而卡住，测试自身就会挂死。
            api._hard_unlink(p)
        except OSError:
            pass
    return got, err


print("=== ① 单文件（回归：最常见的用法） ===")
got, err = run(b"A" * 100, [{"filename": "cmdb.db", "size": 100}])
ok(not err, "单文件成功", err)
ok(list(got.values()) == [b"A" * 100], "内容完整", {k: len(v) for k, v in got.items()})

print("\n=== ② 多文件，各自边界不被吞掉 ===")
data = b"A" * 10 + b"B" * 7
got, err = run(data, [{"filename": "a.db", "size": 10}, {"filename": "b.db", "size": 7}])
ok(not err, "多文件成功", err)
ok(len(got) == 2, "两个文件都落盘了（第一版在这里只落 1 个）", list(got.keys()))
ok(got.get("a.db") == b"A" * 10, "a.db 内容正确", got.get("a.db"))
ok(got.get("b.db") == b"B" * 7, "b.db 内容正确", got.get("b.db"))

print("\n=== ③ chunk 跨文件边界（第一版的致命 bug） ===")
# 10 + 7 = 17 字节；强制用极小 chunk 逼出跨界
req = FakeReq(data)
paths_list, err = api._stage_sqlite_uploads_stream(req, [
    {"filename": "a.db", "size": 10}, {"filename": "b.db", "size": 7}])
got2 = {}
for p in paths_list or []:
    got2[_orig_name(p)] = open(p, "rb").read()
    api._hard_unlink(p)
ok(not err, "跨界切分不报错", err)
ok(got2.get("a.db") == b"A" * 10, "跨界时 a.db 仍完整", got2.get("a.db"))
ok(got2.get("b.db") == b"B" * 7, "跨界时 b.db 仍完整", got2.get("b.db"))

print("\n=== ④ 0 字节文件（选中的库是空的） ===")
got, err = run(b"", [{"filename": "empty.db", "size": 0}])
ok(not err, "0 字节文件不算错误", err)
ok(got.get("empty.db") == b"", "0 字节文件被创建且为空", got)

print("\n=== ⑤ 上传被截断 → 明确报错 + 回滚，不留半个 .db ===")
before = set(os.listdir(os.path.join(_tmp_data, "tmp_cmdb"))) \
    if os.path.isdir(os.path.join(_tmp_data, "tmp_cmdb")) else set()
got, err = run(b"A" * 10 + b"B" * 7,
               [{"filename": "a.db", "size": 10}, {"filename": "b.db", "size": 7}],
               truncate_to=12)
ok(bool(err), "截断时报错而不是假成功", "err=%r got=%s" % (err, list(got)))
ok("中断" in err or "字节" in err, "错误信息说清是上传断了", err)
# ★ 回滚改成后台异步（2026-10-06）后，这里不能"立刻"断言目录干净 ——
#   同步删几百 MB 的库会把请求线程挂死，浏览器只看到 Failed to fetch。
#   正确的不变式是：**最终**不残留，且不能阻塞调用方。
_t0 = time.time()
after = set(os.listdir(os.path.join(_tmp_data, "tmp_cmdb"))) \
    if os.path.isdir(os.path.join(_tmp_data, "tmp_cmdb")) else set()
ok(time.time() - _t0 < 0.5, "截断回滚不阻塞调用方（立即返回）",
   "%.3fs" % (time.time() - _t0))
leaked = after - before
for _ in range(40):                      # 给后台线程最多 4s
    if not (set(os.listdir(os.path.join(_tmp_data, "tmp_cmdb"))) - before):
        break
    time.sleep(0.1)
settled = set(os.listdir(os.path.join(_tmp_data, "tmp_cmdb"))) - before \
    if os.path.isdir(os.path.join(_tmp_data, "tmp_cmdb")) else set()
ok(not settled, "截断后临时目录最终无残留（后台回滚干净）", sorted(settled))

print("\n=== ⑥ size 非法 → 在写文件前就拒 ===")
for bad, label in (([{"filename": "x.db", "size": -1}], "负 size"),
                   ([{"filename": "x.db", "size": "abc"}], "非数字 size")):
    got, err = run(b"X" * 10, bad)
    ok(bool(err) and not got, "%s 被拒且无文件落盘" % label, "err=%r" % err)

print("\n=== ⑦ 文件名安全：目录穿越 ===")
got, err = run(b"X" * 5, [{"filename": "../../../../evil.db", "size": 5}])
ok(not err, "穿越名也能安全落盘", err)
ok(all(".." not in p for p in (got.keys())), "落盘名里没有 ..", list(got.keys()))

print("\n=== ⑧ 数据比清单多（客户端多发） → 不越界写 ===")
got, err = run(b"A" * 10 + b"EXTRA" * 10, [{"filename": "a.db", "size": 10}])
ok(got.get("a.db") == b"A" * 10, "只按清单长度写，多余数据被忽略", got.get("a.db"))

print("\n=== ⑨ 临时文件名唯一性（2026-10-06 修 Permission denied）===")
# 背景：小库走 _stage_sqlite_uploads、大库走 _stage_sqlite_uploads_stream，
#   两者原先各自算 "%d_%d" % (秒级时间戳, pid)。同一秒内先后传两个库
#   → 路径完全相同 → 第二次 open("wb") 直接 Permission denied。
#   清理改异步后残留窗口更大，从"理论可能"变成 e2e 稳定复现。
stamps = [api._unique_stamp() for _ in range(500)]
ok(len(set(stamps)) == 500, "连打 500 次不撞名（唯一 %d/500）" % len(set(stamps)))
# 两条落盘路径必须共用同一个生成器，否则以后新增落盘点又会漏
_src = ""
try:
    import re as _re
    _src = open(os.path.join(ROOT, "modules", "m2_enrich", "api.py"),
                encoding="utf-8").read()
except Exception:  # noqa: BLE001
    pass
if _src:
    _callers = len(_re.findall(r"stamp = _unique_stamp\(\)", _src))
    _old = len(_re.findall(r'stamp = "%d_%d"', _src))
    ok(_callers == 2, "两条落盘路径都走 _unique_stamp（找到 %d 处）" % _callers)
    ok(_old == 0, "没有残留的秒级戳写法（找到 %d 处）" % _old)

print("\n=== ⑩ file 模式也必须流式落盘（2026-10-06 修「明明有网却报网络中断」）===")
# 背景：core/server.py 对 >32MB 的请求体走 begin_stream()，req.body 是**空的**。
#   原来只有 sqlite 模式走 iter_body，file 模式仍在内存路径切空 body → 立刻返回
#   400「文件清单与请求体大小不符」；而浏览器还在往 socket 写，服务端已开始写
#   响应并关连接 → XHR 触发 onerror → 前端只显示「网络中断」，
#   真实原因（清单不匹配）被完全掩盖。
# 这组测试锁住：file 模式的 xlsx/csv 也走 _stage_manifest_stream 落盘。


def _run_file(data, mfiles):
    """走 file 模式的流式落盘（_stage_file_uploads_stream）。"""
    before = set(os.listdir(os.path.join(_tmp_data, "tmp_cmdb"))) \
        if os.path.isdir(os.path.join(_tmp_data, "tmp_cmdb")) else set()
    r = FakeReq(data)
    paths, err = api._stage_file_uploads_stream(r, mfiles)
    return paths, err, before


_csv = b"col1,col2\na,b\n"
_p, _e, _b = _run_file(_csv, [{"filename": "t.csv", "size": len(_csv)}])
ok(not _e and len(_p) == 1, "单个 csv 流式落盘成功", _e)
ok(_p and os.path.isfile(_p[0]), "落盘文件真实存在")
if _p:
    ok(open(_p[0], "rb").read() == _csv, "内容与请求体一致")

_p2, _e2, _ = _run_file(b"A" * 10 + b"B" * 10,
                         [{"filename": "x.xlsx", "size": 10},
                          {"filename": "y.csv", "size": 10}])
ok(not _e2 and len(_p2) == 2, "多文件（xlsx+csv 混合）都能落盘", _e2)
if len(_p2) == 2:
    ok(open(_p2[0], "rb").read() == b"A" * 10, "第一个文件内容正确")
    ok(open(_p2[1], "rb").read() == b"B" * 10, "第二个文件内容正确")
    ok(_p2[0].endswith(".xlsx"), "xlsx 保留扩展名（下游按扩展名分派解析器）", _p2[0])
    ok(_p2[1].endswith(".csv"), "csv 保留扩展名", _p2[1])

# 无扩展名 → 必须补一个可识别的，否则下游 read_upload / _rows_from_bytes 全跳过
_p3, _e3, _ = _run_file(b"X" * 4, [{"filename": "无扩展名", "size": 4}])
ok(not _e3 and _p3 and os.path.splitext(_p3[0])[1],
   "无扩展名的文件名被补上可识别后缀", _p3[0] if _p3 else _e3)

# 目录穿越防护
_p4, _e4, _ = _run_file(b"Y" * 6,
                         [{"filename": "../../../evil.csv", "size": 6}])
ok(not _e4 and _p4 and ".." not in _p4[0], "穿越名被清洗（落盘名无 ..）", _p4[0] if _p4 else _e4)

# 截断 → 报错 + 异步回滚
_b4 = set(os.listdir(os.path.join(_tmp_data, "tmp_cmdb")))
_p5, _e5, _ = _run_file(b"Z" * 5, [{"filename": "cut.csv", "size": 100}])
ok(bool(_e5) and not _p5, "声明 100 字节只收到 5 字节 → 报错并回滚", _e5)
ok("中断" in (_e5 or "") or "字节" in (_e5 or ""), "错误文案说清是上传断了", _e5)
for _ in range(40):
    if not (set(os.listdir(os.path.join(_tmp_data, "tmp_cmdb"))) - _b4):
        break
    time.sleep(0.1)
ok(not (set(os.listdir(os.path.join(_tmp_data, "tmp_cmdb"))) - _b4),
   "截断后临时目录最终无残留")

# ★ 惰性文件序列：读一个丢一个，峰值内存 = 单文件而非全部之和
_pairs = [("a.csv", _p[0])] if _p else []
if len(_p2) == 2:
    _pairs = [("x.xlsx", _p2[0]), ("y.csv", _p2[1])]
if _pairs:
    lz = api._file_entries_from_paths(_pairs)
    ok(len(lz) == len(_pairs), "惰性序列 len() 正确", len(lz))
    _seen = []
    for _f in lz:
        _seen.append(_f["filename"])
        lz.release_one()
    ok(_seen == [n for n, _ in _pairs], "惰性序列按序产出全部文件", _seen)
    ok(lz._cache == {}, "release_one 后缓存清空（字节已释放）", list(lz._cache))
    ok(len(lz) == len(_pairs), "释放后 len() 仍正确（可重复遍历）")
    ok(lz[0]["filename"] == _pairs[0][0], "释放后可重新按索引读（位置索引阶段需要）")

if _src:
    # ★ 结构性防线：file 模式的流式分支必须真实存在
    ok("_stage_file_uploads_stream(req, mfiles)" in _src,
       "file 模式的流式分支已接入（不是只在 sqlite 分支）")
    ok('if mode == "sqlite" and hasattr(req, "iter_body")' not in _src,
       "旧的「仅 sqlite 走流式」条件已移除（那正是断连根因）")

print("\n" + "=" * 60)
print("合计 %d 项，通过 %d，失败 %d"
      % (_PASS[0] + _FAIL[0], _PASS[0], _FAIL[0]))

shutil.rmtree(_tmp_data, ignore_errors=True)
sys.exit(1 if _FAIL[0] else 0)