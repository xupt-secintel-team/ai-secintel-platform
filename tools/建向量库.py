# -*- coding: utf-8 -*-
"""
建向量库.py —— ① 全量语义召回：把语料编码进本地向量库（免费、不联网、不花钱）
================================================================================
为什么要有它：检索引擎原本只有关键词（BM25）。对「口语化/语义改写」的提问
（例如「AI 硬件/驱动层面的漏洞」「有东西能被远程打穿的 AI 框架」）关键词召回会漂移，
语义向量能补上这一块。

数据来源：**主体进程内已加载的语料**（约 8.2 万条，随实时监测持续增长），所以必须由正在运行的服务来做，
本脚本只是一个「命令行客户端」：POST 给服务 → 轮询进度 → 打印 ETA。

前置条件：
    · 服务已启动（默认 http://127.0.0.1:8848）
    · 本地嵌入模型已就位：<项目根>/data/models/multilingual-e5-small
      （或设 AISEC_EMBED_MODEL_DIR 指向别处；模型是免费开源的，与 Key 无关）

用法：
    py -3 tools/建向量库.py                 # 全量建库（断点续跑，可中断后重跑）
    py -3 tools/建向量库.py --limit 2000    # 先小样验证（约 2 分钟）
    py -3 tools/建向量库.py --reset         # 清空重建（换模型时必须）
    py -3 tools/建向量库.py --status        # 只看当前向量库状态
建完后：
    · 检索自动变成「关键词 + 语义」混合（modules/m3_qa/backend/qa/retriever.py 里融合）
    · 用 tools/评测检索.py --compare 测试报告/检索评测.json 可以看到语义召回类题目的提升
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def http_json(url, payload=None, timeout=600):
    req = urllib.request.Request(url, method="POST" if payload is not None else "GET")
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode()
        req.add_header("Content-Type", "application/json; charset=utf-8")
    with urllib.request.urlopen(req, data=data, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def fmt(sec):
    sec = int(sec or 0)
    if sec < 60:
        return f"{sec} 秒"
    if sec < 3600:
        return f"{sec // 60} 分 {sec % 60} 秒"
    return f"{sec // 3600} 小时 {sec % 3600 // 60} 分"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=os.environ.get("AISEC_EVAL_BASE", "http://127.0.0.1:8848"))
    ap.add_argument("--limit", type=int, default=0, help="只索引前 N 条（0=全部）")
    ap.add_argument("--batch", type=int, default=64)
    ap.add_argument("--reset", action="store_true", help="先清空向量库再建")
    ap.add_argument("--status", action="store_true", help="只看状态，不建库")
    args = ap.parse_args()
    url = args.base.rstrip("/") + "/api/qa/build_vector"

    st = http_json(url)
    print(f"[建向量库] 服务 {args.base}")
    print(f"[建向量库] 语料 {st.get('total') or '—'} 条 · 库中已有 {st.get('count', 0)} 条 · "
          f"嵌入模型 {st.get('model') or (st.get('embedder') or {}).get('model') or '未加载'}")
    if st.get("embedder", {}).get("note"):
        print(f"[建向量库] 注意：{st['embedder']['note']}")
    if args.status:
        print(json.dumps(st, ensure_ascii=False, indent=2)[:1200])
        return 0

    resp = http_json(url, payload={"limit": args.limit, "batch": args.batch, "reset": args.reset})
    if resp.get("error"):
        print(f"[建向量库] 启动失败：{resp['error']}")
        return 1
    print(f"[建向量库] 已启动（limit={args.limit or '全部'} batch={args.batch} reset={args.reset}）")

    last = 0
    while True:
        time.sleep(5)
        st = http_json(url, timeout=60)
        if st.get("error"):
            print(f"[建向量库] 出错：{st['error']}")
            return 1
        done, total = st.get("processed", 0), st.get("total", 0)
        if done != last or done == total:
            pct = f"{done * 100 // total}%" if total else "—"
            print(f"  [{time.strftime('%H:%M:%S')}] {done}/{total or '?'}（{pct}）"
                  f"　{st.get('rate', 0)} 条/秒　已用 {fmt(st.get('elapsed'))}　"
                  f"预计剩余 {fmt(st.get('eta'))}　库中 {st.get('count', 0)}")
            last = done
        if st.get("done") or not st.get("running"):
            print(f"[建向量库] {st.get('note') or '结束'}"
                  f"　错误：{st.get('error') or '无'}")
            print(f"[建向量库] 向量库现有 {st.get('count', 0)} 条向量"
                  f"（模型 {st.get('model')}，{st.get('dim')} 维）")
            return 0 if not st.get("error") else 1


if __name__ == "__main__":
    raise SystemExit(main())
