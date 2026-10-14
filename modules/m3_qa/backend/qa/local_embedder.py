# -*- coding: utf-8 -*-
"""
local_embedder.py — 本地免费嵌入模型（不联网、不计费、数据不出本机）
================================================================================
为什么用它：DeepSeek 不提供 embeddings 接口，走付费 API 需要再配一把 Key 且按量计费；
本地多语模型在**中文检索**上通常不输 text-embedding-3-small，且零成本。

模型优先级（第一个能加载成功的就用它）：
  1. 环境变量 AISEC_EMBED_MODEL_DIR 指定的本地目录
  2. 项目内 data/models/<模型名>
  3. HuggingFace 缓存（仓库 ID，需能联网/挂代理）

默认模型：intfloat/multilingual-e5-small（118M 参数，384 维，多语，CPU 可用，fp32 约 470MB）
兜底模型：BAAI/bge-small-zh-v1.5（中文强，95 MB）→ BAAI/bge-small-en-v1.5（英文）

用法：
    from qa.local_embedder import local_embedder
    if local_embedder.ensure():                     # 加载成功返回 True
        vecs = local_embedder.encode(texts, kind="passage")
        q    = local_embedder.encode(["某条查询"], kind="query")[0]
说明：
    · e5 系列必须带前缀（query: / passage:），否则效果明显下降；这里按模型自动加。
    · 归一化后的向量配合 chroma 的 cosine 空间使用。
    · 全部在 CPU 上跑，不占用 GPU、不发起任何网络请求（模型已在本地时）。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional, Sequence
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

_HERE = os.path.dirname(os.path.abspath(__file__))


def _find_root() -> Optional[str]:
    """向上找项目根（含 core/paths.py 的那一层）——别靠固定层数 dirname，结构一变就指错目录。"""
    p = _HERE
    for _ in range(8):
        p = os.path.dirname(p)
        if os.path.exists(os.path.join(p, "core", "paths.py")):
            return p
    return None


_PROJ = _find_root() or os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))  # 项目根

# 各模型的前缀约定（e5 必需；bge-zh 有推荐前缀；bge-en 可选）
MODELS: List[Dict[str, object]] = [
    {
        "name": "intfloat/multilingual-e5-small",
        "dim": 384,
        "prefix_query": "query: ",
        "prefix_passage": "passage: ",
    },
    {
        "name": "BAAI/bge-small-zh-v1.5",
        "dim": 512,
        "prefix_query": "为这个句子生成表示以用于检索相关文章：",
        "prefix_passage": "",
    },
    {
        "name": "BAAI/bge-small-en-v1.5",
        "dim": 384,
        "prefix_query": "Represent this sentence for searching relevant passages: ",
        "prefix_passage": "",
    },
]

LOCAL_ROOTS = [
    os.environ.get("AISEC_EMBED_MODEL_DIR", ""),
    os.path.join(_PROJ, "data", "models"),
]


def candidate_dirs(model_name: str) -> List[str]:
    """该模型所有可能的本地目录（按优先级）"""
    short = model_name.split("/")[-1]
    out = []
    for root in LOCAL_ROOTS:
        if not root:
            continue
        out.append(os.path.join(root, short))
    return out


# —— 判「齐」：按最小合理体积判定，残包也算缺（与 translator.py 同一套踩坑经验）——
_MIN_SIZE = {
    "config.json": 500,
    "tokenizer.json": 5_000_000,
    "tokenizer_config.json": 300,
    "special_tokens_map.json": 100,
    "sentencepiece.bpe.model": 1_000_000,
    "model.safetensors": 400_000_000,
}
_EMBED_FILES = ["config.json", "tokenizer.json", "tokenizer_config.json",
                "special_tokens_map.json", "sentencepiece.bpe.model", "model.safetensors"]


def missing_files(d: str) -> List[str]:
    """该模型目录还缺/残缺哪些关键文件（空 = 齐全）。"""
    if not d or not os.path.isdir(d):
        return list(_EMBED_FILES)
    miss = []
    for f, minsz in _MIN_SIZE.items():
        p = os.path.join(d, f)
        if not os.path.isfile(p) or os.path.getsize(p) < minsz:
            miss.append(f)
    return miss


class LocalEmbedder:
    """本地嵌入模型封装（线程安全，进程内单例）"""

    def __init__(self):
        self.ok = False
        self.model_name = ""
        self.dim = 0
        self.model_dir = ""
        self.max_length = int(os.environ.get("AISEC_EMBED_MAXLEN", "256"))
        self.batch_size = int(os.environ.get("AISEC_EMBED_BATCH", "32"))
        self._tok = None
        self._model = None
        self._torch = None
        self._lock = threading.Lock()
        self._note = ""
        self._loaded = False

    # ------------------------------------------------------------------ 加载
    def ensure(self) -> bool:
        """确保模型已加载；返回是否可用（失败不抛异常，调用方降级到纯 BM25）

        线程安全说明：`self.ok` 要等 `_load()` 跑完才为 True，而加载要好几秒。
        原实现进函数就先置 `_loaded = True` 再慢慢加载，于是并发首访时，
        先到的线程在加载中，后到的线程走无锁快速路径 `if self._loaded: return self.ok`，
        读到的还是加载中的 `ok=False` —— 误判「模型不可用」，把向量检索静默降级成
        纯 BM25（实测 6 线程并发有 5 个拿到 False）。主体是 ThreadingHTTPServer，
        一请求一线程，必然可复现。
        修法：`_loaded` 只表示「结论已定」，加载成功或失败后才置位；
        后来者因此会阻塞在锁上，等前面的线程加载完再拿到真实 ok。
        """
        if self._loaded:
            return self.ok
        with self._lock:
            if self._loaded:                      # 双重检查：前一个线程已加载完
                return self.ok
            try:
                self._load()
            except Exception as e:  # noqa: BLE001
                self.ok = False
                self._note = f"{type(e).__name__}: {e}"
                print(f"[LocalEmbedder] 加载失败，向量检索降级为纯 BM25：{self._note}")
            finally:
                self._loaded = True                # 无论成败，结论已定，不再重试
            return self.ok

    def _load(self) -> None:
        import torch
        from transformers import AutoModel, AutoTokenizer

        _n = int(os.environ.get("AISEC_EMBED_THREADS", "0") or 0) or (os.cpu_count() or 4)
        try:                   # 性能档位：低配机器上推理线程压到 2，别把 CPU 吃满
            from envprofile import T
            _n = T.workers(min(_n, 24))
        except Exception:
            _n = min(_n, 24)
        torch.set_num_threads(max(1, _n))
        os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

        last_err = None
        for spec in MODELS:
            name = str(spec["name"])
            target = name
            for d in candidate_dirs(name):
                if os.path.isdir(d) and (os.path.exists(os.path.join(d, "config.json"))
                                         or os.path.exists(os.path.join(d, "model.safetensors"))):
                    target = d
                    break
            try:
                tok = AutoTokenizer.from_pretrained(target)
                mdl = AutoModel.from_pretrained(target)
                mdl.eval()
                self._tok, self._model, self._torch = tok, mdl, torch
                self.model_name = name
                self.model_dir = target
                # 真实维度以模型配置为准（避免写死出错）
                self.dim = int(getattr(mdl.config, "hidden_size", spec["dim"]))
                self._spec = spec
                self.ok = True
                print(f"[LocalEmbedder] 已加载本地嵌入模型 {name}（{self.dim} 维，"
                      f"{'本地目录 ' + target if target != name else 'HF 缓存'}，maxlen={self.max_length}）")
                return
            except Exception as e:  # noqa: BLE001
                last_err = e
                print(f"[LocalEmbedder] {name} 不可用：{type(e).__name__}: {str(e)[:120]}")
        raise RuntimeError(f"没有可用的本地嵌入模型（最后错误：{last_err}）")

    # ------------------------------------------------------------------ 编码
    def encode(self, texts: Sequence[str], kind: str = "passage",
               batch_size: Optional[int] = None, progress=None) -> List[List[float]]:
        """把文本编码成归一化向量（kind: 'query' 或 'passage'）。

        :param progress: 可选回调 progress(done, total)，用于打印进度
        """
        if not self.ensure():
            raise RuntimeError("本地嵌入模型不可用")
        torch = self._torch
        pre = str(self._spec.get("prefix_query" if kind == "query" else "prefix_passage") or "")
        bs = int(batch_size or self.batch_size)
        out: List[List[float]] = []
        items = list(texts)
        with torch.no_grad():
            for i in range(0, len(items), bs):
                chunk = [pre + (t or "")[:2000] for t in items[i:i + bs]]
                enc = self._tok(chunk, padding=True, truncation=True,
                                max_length=self.max_length, return_tensors="pt")
                res = self._model(**enc)
                mask = enc["attention_mask"].unsqueeze(-1).float()
                summed = (res.last_hidden_state * mask).sum(dim=1)
                cnt = mask.sum(dim=1).clamp(min=1e-6)
                vec = summed / cnt
                vec = torch.nn.functional.normalize(vec, p=2, dim=1)
                out.extend(vec.cpu().numpy().astype("float32").tolist())
                if progress:
                    progress(min(i + bs, len(items)), len(items))
        return out

    # ------------------------------------------------------------------ 状态
    def info(self) -> Dict[str, object]:
        """模型自述。

        ★ 实测踩过的坑（2026-10-07）：`model_name` 只在 `_load()` 成功后才赋值，
          因此**模型尚未加载时** `info()["model"]` 是空串 ——
          而 `/api/qa/status` 直接读它，于是页面显示 `vector_model: ""`，
          与 `/api/qa/vector_probe` 报出的真实模型名自相矛盾。
          这里在"未加载"时回落到**配置里打算用的模型名**（MODELS[0]），
          让"口径"在任何时刻都有值；`ok=False` 仍然如实说明当前不可用。
        """
        name = self.model_name or (str(MODELS[0]["name"]) if MODELS else "")
        dim = self.dim or (int(MODELS[0].get("dim") or 0) if MODELS else 0)
        return {"ok": self.ok, "model": name, "dim": dim,
                "dir": self.model_dir, "max_length": self.max_length,
                "loaded": self._loaded, "configured": name if not self.ok else "",
                "note": self._note, "candidates": [str(m["name"]) for m in MODELS]}

    def status_line(self) -> str:
        if self.ok:
            return f"本地嵌入模型 {self.model_name}（{self.dim} 维，CPU，零费用）"
        if not self._loaded:
            return "本地嵌入模型未加载"
        return f"本地嵌入模型不可用：{self._note or '未知原因'}（向量检索降级为纯 BM25）"

    # ------------------------------------------------------------------ 下载
    def download(self, progress=None) -> Dict:
        """下载默认嵌入模型到 data/models/。返回 {ok, model, dir, size_mb, seconds, missing, source, error}。

        下载策略（与 translator.py 同一套本机实测经验）：
          · ModelScope 镜像直连优先（不依赖代理，评委机器只要能上网即可，实测可达）；
          · 失败退回 HuggingFace（走代理）。
        已下好的文件按体积跳过；体积对不上（下到一半）就续传重下。
        """
        t0 = time.time()
        name = str(MODELS[0]["name"])                      # intfloat/multilingual-e5-small
        dest = os.path.join(_PROJ, "data", "models", name.split("/")[-1])
        os.makedirs(dest, exist_ok=True)
        curl = shutil.which("curl")
        no_proxy_env = dict(os.environ)
        for k in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
            no_proxy_env.pop(k, None)
        no_proxy_env["NO_PROXY"] = "*"

        got_ms = False
        if curl:
            for i, f in enumerate(_EMBED_FILES, 1):
                path = os.path.join(dest, f)
                need = _MIN_SIZE.get(f, 1)
                if os.path.isfile(path) and os.path.getsize(path) >= need:
                    continue
                if os.path.isfile(path) and os.path.getsize(path) < need:
                    try:
                        os.remove(path)
                    except OSError as _sw_e:
                        _swallow("modules/m3_qa/backend/qa/local_embedder.py:261", _sw_e)
                if progress:
                    progress(f"{i}/{len(_EMBED_FILES)} {f}", int(i * 100 / len(_EMBED_FILES)))
                url = f"https://modelscope.cn/models/{name}/resolve/master/{f}"
                for _attempt in range(1, 4):
                    try:
                        subprocess.run([curl, "-sL", "-C", "-", "--retry", "3", "--retry-delay", "5",
                                        "--retry-all-errors", "--speed-limit", "20000",
                                        "--speed-time", "45", "--max-time", "1800",
                                        "-o", path, url],
                                       timeout=1900, check=False, env=no_proxy_env)
                    except subprocess.TimeoutExpired as _sw_e:
                        _swallow("modules/m3_qa/backend/qa/local_embedder.py:273", _sw_e)
                    if os.path.isfile(path) and os.path.getsize(path) >= need:
                        got_ms = True
                        break
                    time.sleep(2)

        miss = missing_files(dest)
        if miss and curl:
            proxy = os.environ.get("AISEC_PROXY") or os.environ.get("HTTPS_PROXY") or ""
            env2 = dict(os.environ)
            if proxy:
                env2["HTTPS_PROXY"] = proxy
                env2["HTTP_PROXY"] = proxy
            for f in _EMBED_FILES:
                path = os.path.join(dest, f)
                if os.path.isfile(path) and os.path.getsize(path) >= _MIN_SIZE.get(f, 1):
                    continue
                try:
                    subprocess.run([curl, "-sL", "-C", "-", "--retry", "2", "--retry-delay", "4",
                                    "--max-time", "1800", "-o", path,
                                    f"https://huggingface.co/{name}/resolve/main/{f}"],
                                   timeout=1900, check=False, env=env2)
                except subprocess.TimeoutExpired as _sw_e:
                    _swallow("modules/m3_qa/backend/qa/local_embedder.py:296", _sw_e)
            miss = missing_files(dest)

        size_mb = 0.0
        if os.path.isdir(dest):
            size_mb = round(sum(os.path.getsize(os.path.join(dest, f))
                                for f in os.listdir(dest)
                                if os.path.isfile(os.path.join(dest, f))) / 1048576, 1)
        return {"ok": not miss, "model": name, "dir": dest, "size_mb": size_mb,
                "missing": miss, "seconds": round(time.time() - t0, 1),
                "source": "modelscope（直连镜像）" if got_ms else "huggingface（代理）",
                "error": None if not miss else f"缺少/残缺文件：{'、'.join(miss)}（重跑本命令会续传）"}


local_embedder = LocalEmbedder()

if __name__ == "__main__":  # 自检/下载：py -3 qa/local_embedder.py [--status|--download|--test]
    ap = argparse.ArgumentParser(description="本地免费嵌入模型自检/下载")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--download", action="store_true")
    a = ap.parse_args()
    if a.status:
        print(json.dumps(local_embedder.info(), ensure_ascii=False, indent=2))
        _d = os.path.join(_PROJ, "data", "models", str(MODELS[0]["name"]).split("/")[-1])
        print("模型目录:", _d)
        print("缺失文件:", missing_files(_d) or "齐全")
        sys.exit(0)
    if a.download:
        def prog(stage, pct):
            print(f"  [{stage}] {pct}%", flush=True)
        r = local_embedder.download(prog)
        print(json.dumps(r, ensure_ascii=False, indent=2))
        sys.exit(0 if r.get("ok") else 1)
    t0 = time.time()
    ok = local_embedder.ensure()
    print(local_embedder.status_line())
    print("信息:", local_embedder.info())
    if ok:
        v = local_embedder.encode(["Ollama 远程代码执行漏洞", "how to exploit log4j"], kind="query")
        print(f"编码 {len(v)} 条，维度 {len(v[0])}，耗时 {time.time() - t0:.1f}s")
    sys.exit(0 if ok else 1)
