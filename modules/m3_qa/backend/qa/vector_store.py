# -*- coding: utf-8 -*-
"""
vector_store.py — 语义向量库（默认 NumPy 后端）
================================================================================
为什么不用 Chroma（原方案）：本项目实测**进程被强杀（taskkill /F）后 Chroma 的 HNSW 段会损坏**
（`Error loading hnsw index`），重启后 count 直接变 0、向量「全部消失」且无法自愈。
对「可中断、可续跑、重启后必须在」的演示/比赛场景不可接受。

NumPy 后端：一个 `.npy` 矩阵 + 一个 `.jsonl` 元数据，自己管、可自证、可断点续跑。
  规模：82,985 条 × 384 维 float32 ≈ 122 MB；暴力检索一次 83k×384 点积 ≈ 30~60 ms（CPU），
  10 万级数据下比 ann 索引更稳（构建/持久化成本远大于收益）。

产物（共享数据目录下，路径由 core/paths.py 统一解析）：
    data/vector_store/embeddings.npy    向量矩阵（float32，L2 归一化 → 余弦=点积）
    data/vector_store/meta.jsonl        第 i 行对应矩阵第 i 行
    data/vector_store/index.json        模型名/维度/条数/生成时间（自证文件）

对外契约（retriever.py 只依赖这三个方法）：
    count() -> int
    search(query, top_k) -> [{id,title,desc,cvss,published,category,source,type,vector_score,_from}]
    build_index(records, batch_size, progress, resume) -> {indexed,skipped,total,model,dim}
向量库为空 / 模型不可用时 search() 返回 [] → 上游自动降级为纯关键词检索（不报错）。
"""
from __future__ import annotations

import gc as _gc
import json
import os
import sys
import threading
import time
from typing import Callable, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from qa.config import VECTOR_CONFIG, EMBEDDING_CONFIG          # noqa: F401  （保持配置入口不变）
from qa.local_embedder import local_embedder as _embedder
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

def _find_root() -> Optional[str]:
    """向上找项目根（含 core/paths.py 的那一层）。

    为什么要这么做：模块文件在 modules/<id>/backend/qa/ 下，靠固定层数 `dirname` 数上去
    一旦结构变化或从不同 cwd 启动就会算错，**独立进程里 data 目录会指到 modules/data**，
    表现成「服务端能看到向量、命令行看不到」这种诡异现象。改为按标志文件向上找，稳。
    """
    p = os.path.dirname(os.path.abspath(__file__))
    for _ in range(8):
        p = os.path.dirname(p)
        if os.path.exists(os.path.join(p, "core", "paths.py")):
            return p
    return None


ROOT = _find_root() or os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
_paths = None
try:  # 共享数据目录（core/paths.py 统一解析）
    if ROOT:
        sys.path.insert(0, os.path.join(ROOT, "core"))
    import paths as _paths  # noqa: F401
except Exception:  # noqa: BLE001
    _paths = None

STORE_SUBDIR = "vector_store"
NP_DTYPE = "float32"


def data_dir() -> str:
    return _paths.DATA_DIR if _paths is not None else os.path.join(ROOT, "data")


def store_dir() -> str:
    """向量库目录（默认 data/vector_store；可被 AISEC_VECTOR_DIR 覆盖）"""
    return os.environ.get("AISEC_VECTOR_DIR") or os.path.join(data_dir(), STORE_SUBDIR)


def persist_path() -> str:
    """兼容旧接口名（日志/文档里出现过），语义等同 store_dir()"""
    return store_dir()


def _npy_path() -> str:
    return os.path.join(store_dir(), "embeddings.npy")


def _resolve_matrix_path(name: Optional[str] = None) -> str:
    """当前矩阵文件名（index.json 里可指向扩容后生成的新文件）"""
    return os.path.join(store_dir(), name or "embeddings.npy")


def _meta_path() -> str:
    return os.path.join(store_dir(), "meta.jsonl")


def _index_path() -> str:
    return os.path.join(store_dir(), "index.json")


class VectorStore:
    """NumPy 向量库（构建时持锁；检索只读；进程内单例）"""

    def __init__(self):
        self.ok = False
        self.note = ""
        self.model = ""
        self.dim = 0
        self._lock = threading.RLock()
        self._loaded = False
        self._np = None
        self._mat = None
        self._meta: List[Dict] = []
        self._id2row: Dict[str, int] = {}
        self._capacity = 0        # 矩阵已分配的行数（.npy 的物理容量）
        self._valid = 0           # 有效行数（= meta.jsonl 行数，<= capacity）
        self._matrix_path = ""    # 当前矩阵文件（扩容时换新文件，避免 Windows 文件锁）

    # ------------------------------------------------------------------ 初始化
    def init(self) -> bool:
        """加载向量库。线程安全：`_loaded` 只在**加载结束后**才置位。

        原实现先进无锁快速路径并立刻 `self._loaded = True`，而 `self.ok` 要等
        meta.jsonl 读完 + mmap 建好才为 True。并发首访时（主体是
        ThreadingHTTPServer，一请求一线程，必然可复现），后到的线程会走
        `if self._loaded: return self.ok` 拿到加载中的 `ok=False`，
        进而 `count()` 返回 0 —— /api/qa/status 误报「向量库为空」，
        前端据此显示「语义索引未建库」。实测 6 线程并发有 5 个拿到 0。
        """
        if self._loaded:
            return self.ok
        with self._lock:
            if self._loaded:
                return self.ok
            try:
                import numpy as np
                self._np = np
                os.makedirs(store_dir(), exist_ok=True)
                if os.path.exists(_meta_path()):
                    with open(_meta_path(), "r", encoding="utf-8") as f:
                        self._meta = [json.loads(l) for l in f if l.strip()]
                idx = {}
                if os.path.exists(_index_path()):
                    try:
                        with open(_index_path(), "r", encoding="utf-8") as f:
                            idx = json.load(f) or {}
                    except Exception:  # noqa: BLE001
                        idx = {}
                self.model = idx.get("model", "")
                self._matrix_path = _resolve_matrix_path(idx.get("matrix"))
                if os.path.exists(self._matrix_path):
                    raw = np.load(self._matrix_path, mmap_mode="r")
                    self._capacity = int(raw.shape[0])
                    self.dim = int(raw.shape[1])
                    # 有效行数取「元数据行数 / index.json 记的条数 / 物理容量」三者最小：
                    # 被强杀时矩阵可能比元数据多写了几行（孤儿行），一律忽略，下次建库覆盖
                    n = min(len(self._meta), int(idx.get("count") or len(self._meta)), self._capacity)
                    self._valid = max(0, n)
                    if n != len(self._meta):
                        self._meta = self._meta[:n]
                        self.note = f"矩阵与元数据按 {n} 行对齐（孤儿行已忽略）"
                    self._mat = raw[:n] if n < self._capacity else raw
                else:
                    self._mat = None
                    self._valid = 0
                self._id2row = {str(m.get("id")): i for i, m in enumerate(self._meta)}
                self.ok = True
                self._loaded = True      # 结论已定（必须在下面的日志之前置位：
                                          # 日志里调了 self.count() → init()，
                                          # 若此时还没置位会因 RLock 可重入而无限递归）
                print(f"[VectorStore] NumPy 向量库就绪：{self.count()} 条 · {self.dim} 维 · "
                      f"模型 {self.model or '（未建库）'} · 容量 {self._capacity} 行 · 目录 {store_dir()}")
            except Exception as e:  # noqa: BLE001
                self.ok = False
                self.note = f"{type(e).__name__}: {e}"
                self._loaded = True      # 失败也是「结论已定」，不再让每个线程重试一次
                print(f"[VectorStore] 初始化失败（向量检索降级为纯关键词）：{self.note}")
            return self.ok

    # ------------------------------------------------------------------ 构建
    def build_index(self, records: List[Dict], batch_size: int = 64,
                    progress: Optional[Callable[[int, int], None]] = None,
                    resume: bool = True, capacity_hint: int = 0) -> Dict[str, object]:
        """把文档编码进向量库；**断点续跑**（已入库 id 直接跳过），可被强杀后直接重跑。

        :param capacity_hint: 预期总条数（如全量语料 82985）——一次性把矩阵开到足够大，
                              避免中途扩容（Windows 下重建被 mmap 锁住的文件很麻烦）。
        """
        if not self.init():
            return {"error": f"向量库不可用：{self.note}"}
        if not _embedder.ensure():
            return {"error": f"本地嵌入模型不可用：{_embedder.info().get('note') or '未知'}",
                    "hint": "检查 <项目根>/data/models 下是否已有模型，或设 AISEC_EMBED_MODEL_DIR"}
        np = self._np

        rows = []
        for i, r in enumerate(records):
            doc_id = str(r.get("id") or f"rec_{i}")
            text = f"{r.get('title', '')} {str(r.get('desc', ''))[:1000]}".strip()
            if not text:
                continue
            cv = r.get("cvss") if isinstance(r.get("cvss"), dict) else {}
            rows.append((doc_id, text, {
                "id": doc_id,
                "title": str(r.get("title", ""))[:200],
                "severity": str(cv.get("severity") or ""),
                "cvss_score": float(cv.get("score") or 0),
                "published": str(r.get("published") or ""),
                "category": str(r.get("category") or ""),
                "source": str(r.get("source") or ""),
                "type": str(r.get("type") or ""),
            }))

        todo = [x for x in rows if x[0] not in self._id2row] if resume else rows
        skipped = len(rows) - len(todo)
        if not todo:
            return {"indexed": 0, "skipped": skipped, "total": self.count(),
                    "model": _embedder.model_name, "dim": _embedder.dim,
                    "note": "全部已索引，无需重建"}

        print(f"[VectorStore] 待索引 {len(todo)} 条（已有 {skipped} 条 / 共 {len(rows)} 条），"
              f"模型 {_embedder.model_name}，批次 {batch_size}")

        dim = _embedder.dim or self.dim or 384
        start = self._valid
        need = start + len(todo)
        want_cap = max(need, int(capacity_hint or 0))
        if not self._matrix_path:
            self._matrix_path = _npy_path()

        # 0) 首次建库 / 容量不足 → 写一个新矩阵文件（Windows 下不能重写被 mmap 锁住的文件）
        if want_cap > self._capacity or not os.path.exists(self._matrix_path):
            new_cap = int(want_cap * 1.1) + 1024
            old = None
            if os.path.exists(self._matrix_path):
                self._mat = None
                _gc.collect()
                try:
                    with open(self._matrix_path, "rb") as f:   # 读进内存（非 mmap，避免句柄锁）
                        old = np.load(f)
                except Exception as e:  # noqa: BLE001
                    print(f"[VectorStore] 读取旧矩阵失败（将重建）：{e}")
                    old = None
            new_path = (_npy_path() if not os.path.exists(_npy_path())
                        else os.path.join(store_dir(), f"embeddings-cap{new_cap}.npy"))
            fresh = np.lib.format.open_memmap(new_path, mode="w+", dtype=NP_DTYPE, shape=(new_cap, dim))
            if old is not None and old.shape[0] > 0:
                keep = min(old.shape[0], start)
                if keep:
                    fresh[:keep] = old[:keep]
                    print(f"[VectorStore] 换矩阵文件：保留前 {keep} 行 → {os.path.basename(new_path)}")
            fresh.flush()
            old_path = self._matrix_path
            del fresh, old
            _gc.collect()
            self._matrix_path = new_path
            self._capacity = new_cap
            if old_path != new_path:
                try:            # 尽力清理旧文件；被锁就留着，下次启动再删
                    os.remove(old_path)
                except Exception as _sw_e:  # noqa: BLE001
                    _swallow("modules/m3_qa/backend/qa/vector_store.py:245", _sw_e)
            print(f"[VectorStore] 矩阵容量 {self._capacity} 行（需 {need} 行，文件 {os.path.basename(new_path)}）")

        self._mat = None
        _gc.collect()
        fp = np.load(self._matrix_path, mmap_mode="r+")
        meta_fp = open(_meta_path(), "a" if start > 0 else "w", encoding="utf-8")
        indexed = 0
        try:
            for i in range(0, len(todo), batch_size):
                chunk = todo[i:i + batch_size]
                vecs = _embedder.encode([c[1] for c in chunk], kind="passage", batch_size=batch_size)
                arr = np.asarray(vecs, dtype=NP_DTYPE)
                fp[start + indexed: start + indexed + arr.shape[0]] = arr
                fp.flush()                      # 每批落盘：被强杀最多丢一批，重跑自动跳过已写行
                for c in chunk:
                    meta_fp.write(json.dumps(c[2], ensure_ascii=False) + "\n")
                    self._id2row[c[0]] = len(self._meta)
                    self._meta.append(c[2])
                meta_fp.flush()
                self._valid = len(self._meta)
                indexed += len(chunk)
                self._write_index()             # 记录有效条数（强杀后据此对齐）
                if progress:
                    progress(skipped + indexed, len(rows))
        finally:
            meta_fp.close()
            try:
                del fp
            except Exception as _sw_e:  # noqa: BLE001
                _swallow("modules/m3_qa/backend/qa/vector_store.py:275", _sw_e)
        self._mat = None                        # 下次检索重新映射，拿到最新长度
        self.model = _embedder.model_name
        self.dim = dim
        self._write_index()
        print(f"[VectorStore] 建索引完成：本次 {indexed} 条，库中 {self.count()} 条")
        return {"indexed": indexed, "skipped": skipped, "total": self.count(),
                "model": _embedder.model_name, "dim": dim}

    def _write_index(self) -> None:
        """把「模型/维度/有效条数/容量」写进 index.json —— 强杀后靠它对齐矩阵与元数据"""
        try:
            with open(_index_path(), "w", encoding="utf-8") as f:
                json.dump({"model": self.model, "dim": self.dim, "count": self._valid,
                           "capacity": self._capacity,
                           "matrix": os.path.basename(self._matrix_path or "embeddings.npy"),
                           "built_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                           "note": "由 tools/建向量库.py 或 POST /api/qa/build_vector 生成；"
                                   "删除本目录不影响使用，检索自动降级为纯关键词"}, f,
                          ensure_ascii=False, indent=2)
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("modules/m3_qa/backend/qa/vector_store.py:296", _sw_e)

    # ------------------------------------------------------------------ 检索
    def _matrix(self):
        path = self._matrix_path or _npy_path()
        if self._mat is None and os.path.exists(path) and self._meta:
            try:
                raw = self._np.load(path, mmap_mode="r")
                # 只暴露前 _valid 行（容量可能大于有效行数，尾部是未写入的空位）
                self._mat = raw[:self._valid] if 0 < self._valid < raw.shape[0] else raw
            except Exception as e:  # noqa: BLE001
                print(f"[VectorStore] 加载矩阵失败：{e}")
                self._mat = None
        return self._mat

    def search(self, query: str, top_k: int = 10) -> List[Dict]:
        """余弦相似度检索（向量已归一化 → 余弦=点积）。空库/模型不可用返回 []（上游自动降级）"""
        if not self.init():
            return []
        mat = self._matrix()
        if mat is None or mat.shape[0] == 0 or not _embedder.ensure():
            return []
        try:
            np = self._np
            qv = np.asarray(_embedder.encode([query], kind="query")[0], dtype=NP_DTYPE)
            qv = qv / (float(np.linalg.norm(qv)) or 1.0)
            n = int(mat.shape[0])
            k = max(1, min(int(top_k), n))
            step = 8192
            sims_parts, idx_parts = [], []
            for s in range(0, n, step):
                block = np.asarray(mat[s:s + step], dtype=NP_DTYPE)
                sims_parts.append(block @ qv)
                idx_parts.append(np.arange(s, s + block.shape[0]))
            sims = np.concatenate(sims_parts)
            idxs = np.concatenate(idx_parts)
            sel = np.argpartition(-sims, k - 1)[:k]
            sel = sel[np.argsort(-sims[sel])]
            out = []
            for j in sel:
                row = int(idxs[j])
                m = self._meta[row] if row < len(self._meta) else {}
                out.append({
                    "id": m.get("id"),
                    "title": m.get("title") or "",
                    "desc": "",
                    "cvss": {"score": m.get("cvss_score"), "severity": m.get("severity")},
                    "published": m.get("published") or "",
                    "category": m.get("category") or "",
                    "source": m.get("source") or "",
                    "type": m.get("type") or "vulnerability",
                    "vector_score": round(float(sims[j]), 4),
                    "_from": "vector",
                })
            return out
        except Exception as e:  # noqa: BLE001
            print(f"[VectorStore] 检索失败: {e}")
            return []

    # ------------------------------------------------------------------ 维护
    def warm(self, budget_s: float = 60.0) -> Dict:
        """预热：把 mmap 的向量矩阵**整块读进物理内存**，消除首问的页错误开销。

        ★ 为什么必须有这个方法（实测，2026-10-07）：
          `_matrix()` 用 `mmap_mode="r"` 打开 118348×384 float32（≈180MB），
          第一次 `search()` 逐块访问时整块磁盘页错误（page fault），
          实测**首问比次问慢约 11 秒**（13.13s vs 1.93s）—— 且这与
          `local_embedder` 的模型加载**无关**（warmup 已把模型加载挪走，
          但 mmap 的页错误发生在"第一次真正做矩阵乘"的那一刻）。

          `AISEC_MAIN_SERVER` 启动预热线程调用本方法后，首问与次问耗时一致。
          低配机器可用 `AISEC_WARM_VECTOR=0` 关闭（把 180MB 常驻内存换成首问等待）。

        返回 {"ok": bool, "rows": int, "ms": int}，失败静默降级（返回 ok=False）。
        """
        import time as _t
        t0 = _t.time()
        try:
            if not self.init():
                return {"ok": False, "rows": 0, "ms": int((_t.time() - t0) * 1000),
                        "note": "向量库未就绪"}
            mat = self._matrix()
            if mat is None or mat.shape[0] == 0:
                return {"ok": False, "rows": 0, "ms": int((_t.time() - t0) * 1000),
                        "note": "矩阵为空"}
            # 整块求和是最省的"touch"方式：强制所有页进入物理内存，
            # 且不分配新的大数组（np.sum 走的是块内累加）。
            # 按块做，避免一次性 peek 触发极端内存峰值。
            np = self._np
            step = 16384
            n = int(mat.shape[0])
            acc = 0.0
            for s in range(0, n, step):
                if (_t.time() - t0) > budget_s:
                    break
                acc += float(np.asarray(mat[s:s + step]).sum())
            # 同时预热嵌入模型（首问的另一半开销）
            try:
                if _embedder.ensure():
                    _embedder.encode(["预热"], kind="query")
            except Exception:  # noqa: BLE001
                pass
            return {"ok": True, "rows": n, "ms": int((_t.time() - t0) * 1000),
                    "touch_sum": round(acc, 3)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "rows": 0, "ms": int((_t.time() - t0) * 1000),
                    "note": str(e)[:120]}

    def count(self) -> int:
        """库中向量条数（会触发一次惰性加载，保证「文件在→条数对」）"""
        self.init()
        return len(self._meta)

    def reset(self) -> None:
        """清空向量库（换模型 / 重建时调用）"""
        with self._lock:
            self._meta = []
            self._id2row = {}
            self._mat = None
            self._capacity = 0
            self._valid = 0
            targets = {_npy_path(), _meta_path(), _index_path(),
                       self._matrix_path or _npy_path()}
            try:                      # 扩容产生的历史矩阵文件一并清掉
                for fn in os.listdir(store_dir()):
                    if fn.startswith("embeddings") and fn.endswith(".npy"):
                        targets.add(os.path.join(store_dir(), fn))
            except Exception as _sw_e:  # noqa: BLE001
                _swallow("modules/m3_qa/backend/qa/vector_store.py:376", _sw_e)
            for p in targets:
                try:
                    if p and os.path.exists(p):
                        os.remove(p)
                except Exception as _sw_e:  # noqa: BLE001
                    _swallow("modules/m3_qa/backend/qa/vector_store.py:382", _sw_e)
            self._matrix_path = _npy_path()
            print("[VectorStore] 向量库已清空")

    def info(self) -> Dict[str, object]:
        return {"backend": "numpy", "count": self.count(), "capacity": self._capacity,
                "dim": self.dim or _embedder.dim,
                "dir": store_dir(), "matrix": self._matrix_path or _npy_path(),
                "meta": _meta_path(), "model": self.model,
                "embedder": _embedder.info(), "note": self.note}


# 全局单例
vector_store = VectorStore()
