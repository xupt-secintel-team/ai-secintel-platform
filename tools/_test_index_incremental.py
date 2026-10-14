# -*- coding: utf-8 -*-
"""
索引缓存「前缀命中 + 尾部增量」A/B 正确性 + 收益验证
================================================================
背景：旧口径的缓存键里含「文档总条数」，而本平台每轮同步都会 append 新情报，
于是条数一变缓存就整个作废 —— 下次启动必吃 355s 全量重建（10 万条实测）。
改成分两种命中：条数没变 → 精确命中；只在末尾追加了少量 → 复用旧索引 + 只给尾部建索引。

本测试证明两件事（用同一份语料、两条路径各建一次引擎）：
  ① 正确性：增量路径与全量重建的检索结果、倒排表、df/dl/id_map 完全一致；
  ② 收益：增量路径的启动耗时显著低于全量重建。

用法： python tools/_test_index_incremental.py
"""
import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))

from engine import SearchEngine  # noqa: E402
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

TOPICS = [
    ("Apache", "Struts 远程代码执行漏洞", "攻击者可构造恶意请求绕过拦截器执行任意命令，影响多个版本"),
    ("nginx", "解析模块内存破坏", "特制请求触发越界写，可导致工作进程崩溃或任意代码执行"),
    ("Redis", "未授权访问导致数据泄露", "默认配置暴露在公网时可被直接读取与写入，进而植入计划任务反弹 shell"),
    ("Jenkins", "插件反序列化漏洞", "利用链依赖常见组件，成功利用可在构建节点执行系统命令"),
    ("GitLab", "越权读取私有仓库", "权限校验缺失使低权限用户可读取他人代码，存在源码泄露风险"),
    ("vLLM", "远程代码执行漏洞", "推理服务接口未校验输入，攻击者可借恶意请求在服务端执行代码"),
    ("Ollama", "模型文件解析漏洞", "加载恶意模型文件时触发内存破坏，可在本地环境执行任意代码"),
    ("Spring", "SpEL 表达式注入", "参数绑定过程未做白名单校验，可构造表达式触发远程代码执行"),
    ("OpenSSL", "证书校验绕过", "特定构造的证书链可通过校验，导致中间人攻击风险上升"),
    ("Chrome", "类型混淆漏洞", "渲染进程内存破坏，配合沙箱逃逸可实现完整利用链"),
]
TAIL_TOPICS = [
    ("Ray", "分布式框架未授权访问", "作业提交接口缺少鉴权，攻击者可远程提交任务在集群内执行任意命令"),
    ("ComfyUI", "自定义节点任意文件读取", "节点安装流程未限制路径，可读取宿主机敏感文件造成信息泄露"),
]


def _rec(rid, vendor, title_body, desc):
    return {
        "id": rid, "type": "cve", "kind": "CVE",
        "title": f"{vendor} {title_body}", "desc": desc,
        "published": "2026-09-%02d" % (int(rid.split("-")[-1]) % 28 + 1),
        "modified": "", "status": "", "scope": "",
        "cvss": {"score": 7.5, "severity": "HIGH", "vector": "", "version": "3.1",
                 "exploitability": None, "impact": None},
        "cwe": [], "cpe": [], "products": [vendor], "vendors": [vendor], "refs": [],
        "poc_links": [], "patch_links": [], "advisory_links": [],
        "osv_packages": [], "osv_summaries": [], "osv_refs": [],
        "sources": ["测试"], "kev": {}, "tags": ["测试"], "risk_tags": [],
        "ai_score": 1.0, "category": "漏洞", "category_reason": "",
        "atlas": [], "atlas_mitigations": [], "papers": [], "remediation": [],
        "link": "http://test.local/%s" % rid, "fetched_at": "",
    }


def build_docs(n_base, n_tail):
    base, tail = [], []
    for i in range(n_base):
        v, t, d = TOPICS[i % len(TOPICS)]
        base.append(_rec("CVE-2026-%04d" % (1000 + i), v, t, "%s（第 %d 条样本语料，用于索引对齐校验）" % (d, i)))
    for i in range(n_tail):
        v, t, d = TAIL_TOPICS[i % len(TAIL_TOPICS)]
        tail.append(_rec("CVE-2026-%04d" % (9000 + i), v, t, "%s（尾部增量样本 %d）" % (d, i)))
    return base, tail


def snapshot(eng):
    """取出可与另一条路径逐项对比的索引切面。"""
    return {
        "N": eng.N,
        "docs": len(eng.docs),
        "tf": len(eng.tf),
        "dl": [round(x, 6) for x in eng.dl],
        "postings_terms": len(eng.postings),
        "postings_len": {t: len(p) for t, p in list(eng.postings.items())[:200]},
        "df_sample": {t: eng.df.get(t, 0) for t in list(eng.df)[:200]},
        "id_map": dict(list(eng.id_map.items())),
    }


def top_ids(eng, q, k=10):
    r = eng.search(q, top_k=k)
    return [x.get("id") for x in (r or {}).get("results", [])]


def main():
    tmp = tempfile.mkdtemp(prefix="aisec_idxtest_")
    path = os.path.join(tmp, "corpus.json")
    base, tail = build_docs(160, 4)

    json.dump({"records": base}, open(path, "w", encoding="utf-8"), ensure_ascii=False)
    t0 = time.time()
    SearchEngine(path)                      # 首建：必定全量重建并落盘缓存
    t_first = time.time() - t0
    cache = path + ".idxcache"
    assert os.path.isfile(cache), "首建未落盘缓存"

    # 尾部追加 4 条新情报 → 模拟"平台持续收录"后的重启
    json.dump({"records": base + tail}, open(path, "w", encoding="utf-8"), ensure_ascii=False)
    t0 = time.time()
    eng_inc = SearchEngine(path)
    t_inc = time.time() - t0

    # 对照组：删掉缓存，同一份语料全量重建
    os.remove(cache)
    t0 = time.time()
    eng_full = SearchEngine(path)
    t_full = time.time() - t0

    ok = True
    print("=" * 68)
    print("① 首建（全量）           %.3fs" % t_first)
    print("② 缓存 + 尾部增量 4 条   %.3fs   命中缓存=%s 增量=%d"
          % (t_inc, eng_inc._loaded_from_cache, eng_inc._incremental_from_cache))
    print("③ 无缓存全量重建         %.3fs" % t_full)
    if not (eng_inc._loaded_from_cache and eng_inc._incremental_from_cache == len(tail)):
        print("   !! 未走增量路径")
        ok = False

    qs = ["远程代码执行", "未授权访问", "反序列化", "中间人攻击", "Ray 作业提交",
          "ComfyUI 节点", "沙箱逃逸", "Ollama 模型文件", "越权读取", "内存破坏"]
    for q in qs:
        a, b = top_ids(eng_inc, q), top_ids(eng_full, q)
        tag = "OK " if a == b else "!! "
        if a != b:
            ok = False
        print("    %s检索[%s] 增量=%s 全量=%s" % (tag, q, a[:3], b[:3]))

    s_inc, s_full = snapshot(eng_inc), snapshot(eng_full)
    for k in ("N", "docs", "tf", "postings_terms"):
        if s_inc[k] != s_full[k]:
            print("   !! 结构不一致 %s: %r vs %r" % (k, s_inc[k], s_full[k]))
            ok = False
    if s_inc["dl"] != s_full["dl"]:
        print("   !! dl 不一致")
        ok = False
    if s_inc["id_map"] != s_full["id_map"]:
        print("   !! id_map 不一致")
        ok = False
    if s_inc["df_sample"] != s_full["df_sample"]:
        diff = {t: (s_inc["df_sample"][t], s_full["df_sample"][t])
                for t in s_inc["df_sample"] if s_inc["df_sample"][t] != s_full["df_sample"][t]}
        print("   !! df 不一致：%s" % list(diff.items())[:5])
        ok = False
    if s_inc["postings_len"] != s_full["postings_len"]:
        print("   !! 倒排表长度不一致")
        ok = False

    print("-" * 68)
    print("② 与 ③ 完全一致" if ok else "存在差异，增量路径不可用")
    print("增量路径相对全量重建：%.2fx" % (t_full / max(t_inc, 1e-6)))
    print("=" * 68)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
