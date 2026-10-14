# -*- coding: utf-8 -*-
"""近重检测（similarity_to_existing）隔离回归测试。
用小语料构建真实 SearchEngine：先 add_documents 收录一篇，再用「同正文不同链接」的新稿
去比，验证 content_containment / title_sim 能命中阈值（过分相同 → 应被过滤）。
同时验证「不同主题的稿件」不应被误判为雷同。
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m1_monitor", "backend"))

from engine import SearchEngine  # noqa: E402
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

DUP_TITLE = "供应链攻击溯源实战：从依赖投毒到内网横向移动"
DUP_BODY = (
    "供应链攻击已成为高级威胁的主要入口。攻击者通过在开源依赖中植入后门或投毒，"
    "借用可信构建链将恶意代码送入目标内网，实现隐蔽的权限提升与持久化。"
    "本文结合真实入侵案例，梳理从依赖投毒、钓鱼社工到内网横向移动的完整攻击链，"
    "并给出基于零信任与微隔离的纵深防御思路。"
    "溯源环节强调日志关联、流量取证与内存马检测，配合红蓝对抗演练持续打磨检测规则，"
    "提升对 APT 组织供应链作战手法的识别与响应能力。"
)
OTHER_TITLE = "Prompt Injection 实战：大模型越狱与防护"
OTHER_BODY = (
    "本文梳理提示词注入在大模型应用中的攻击面，涵盖直接注入、间接注入与多轮越狱。"
    "攻击者可借 RAG 检索增强与 MCP 协议暴露面构造恶意指令，诱导 Agent 越权调用工具。"
    "防御侧给出输入清洗、权限最小化、护栏与输出审计的组合方案。"
)


def _rec(rid, title, desc):
    return {
        "id": rid, "type": "article", "kind": "用户投稿文章",
        "title": title, "desc": desc, "published": "2026-09-30",
        "modified": "", "status": "", "scope": "",
        "cvss": {"score": None, "severity": "", "vector": "", "version": "",
                 "exploitability": None, "impact": None},
        "cwe": [], "cpe": [], "products": [], "vendors": [], "refs": [],
        "poc_links": [], "patch_links": [], "advisory_links": [],
        "osv_packages": [], "osv_summaries": [], "osv_refs": [],
        "sources": ["测试"], "kev": {}, "tags": ["测试"], "risk_tags": [],
        "ai_score": 1.0, "category": "测试", "category_reason": "",
        "atlas": [], "atlas_mitigations": [], "papers": [], "remediation": [],
        "link": f"http://test.local/{rid}", "fetched_at": "",
    }


BASE_DOCS = [
    ("V1", "Apache Struts 远程代码执行漏洞", "该漏洞允许攻击者通过构造恶意请求执行任意命令，影响多个版本，建议升级修复。"),
    ("V2", "WordPress 插件存储型 XSS", "插件未对输入做过滤导致存储型跨站脚本，攻击者可窃取管理员 Cookie 并提权。"),
    ("V3", "Exchange Server 代理漏洞利用链", "组合多个漏洞实现未授权访问与内网横向移动，需尽快打补丁并排查日志。"),
    ("V4", "Log4Shell JNDI 注入分析", "日志组件远程类加载导致任意代码执行，应急建议关闭 lookup 并升级依赖。"),
    ("V5", "内网钓鱼社工与凭据窃取", "攻击者仿冒登录页诱导员工提交口令，建议开启多因素认证与邮件网关检测。"),
    ("V6", "勒索软件加密与横向移动", "样本在入侵后期加密数据并借助弱口令扩散，需做好离线备份与最小权限。"),
    ("V7", "容器逃逸与特权滥用", "特权容器与危险挂载可突破隔离边界，应禁止特权模式并启用 seccomp 策略。"),
    ("V8", "WAF 绕过与预编译防护", "攻击者通过编码变形绕过规则，建议采用参数化查询与语义检测结合的方案。"),
]


def main():
    corpus = os.path.join(ROOT, "data", "_test_sim_corpus.json")
    payload = {
        "records": [_rec(i, t, d) for i, t, d in BASE_DOCS],
        "knowledge": [], "papers": [],
    }
    import json
    with open(corpus, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)
    # 清掉可能存在的旧缓存，保证本次真正建索引
    try:
        os.remove(corpus + ".idxcache")
    except OSError as _sw_e:
        _swallow("tools/_test_similarity.py:74", _sw_e)

    eng = SearchEngine(corpus)
    n0 = len(eng.docs)
    print(f"基础语料 {n0} 条")

    # 1) 收录 dup_a
    dupa = _rec("SUB:DUPA", DUP_TITLE, DUP_BODY)
    added = eng.add_documents([dupa])
    assert added == 1, f"dup_a 应新增 1 条，实际 {added}"
    print(f"add_documents(dup_a) -> {added}")

    # 2) dup_b：同正文、不同链接与 id → 应被判过分相同
    dupb = _rec("SUB:DUPB", DUP_TITLE, DUP_BODY)
    sim = eng.similarity_to_existing(dupb)
    print("dup_b similarity:", sim)
    assert sim["content_containment"] >= 0.6, (
        f"dup_b 正文包含率应 >=0.6（过分相同），实际 {sim['content_containment']}")
    assert sim["title_sim"] >= 0.9, (
        f"dup_b 标题相似度应 >=0.9，实际 {sim['title_sim']}")

    # 3) 不同主题稿件：不应被误判
    other = _rec("SUB:OTHER", OTHER_TITLE, OTHER_BODY)
    sim_o = eng.similarity_to_existing(other)
    print("other similarity:", sim_o)
    assert sim_o["content_containment"] < 0.6, (
        f"不同主题稿件不应被判雷同，实际包含率 {sim_o['content_containment']}")
    assert sim_o["title_sim"] < 0.9, (
        f"不同主题标题不应雷同，实际 {sim_o['title_sim']}")

    # 4) 与语料库已有文档雷同：构造一篇与 BASE V6 高度相似的稿
    v6_like = _rec("SUB:V6LIKE", "勒索软件加密与横向移动", BASE_DOCS[5][2])
    sim_v = eng.similarity_to_existing(v6_like)
    print("v6_like similarity:", sim_v)
    assert sim_v["content_containment"] >= 0.6, (
        f"与语料库已有文档雷同应被检出，实际 {sim_v['content_containment']}")

    print("TEST SIMILARITY OK")


if __name__ == "__main__":
    main()
