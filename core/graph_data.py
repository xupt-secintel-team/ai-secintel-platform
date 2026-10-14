# -*- coding: utf-8 -*-
"""
graph_data.py —— 情报关联推荐与图谱数据
========================================
后端模块，提供两类数据：

1. find_related()  相关情报推荐（同组件/同弱点/同攻击技术/同分类）
2. build_graph()    单条情报的关系图谱数据（nodes + links，供ECharts渲染）

API挂载（在server.py中）：
  GET /api/related?id=xxx   相关推荐
  GET /api/graph?id=xxx     关系图谱
"""

from collections import Counter, defaultdict


# ==========================================================================
# 关联打分
# ==========================================================================
def relation_score(source, target):
    """计算两条情报的关联分数与命中原因"""
    score = 0.0
    reasons = []

    # 共享受影响组件
    sp = set(source.get("products", [])) & set(target.get("products", []))
    if sp:
        score += 3.0 * len(sp)
        reasons.append("共享组件:" + ",".join(list(sp)[:2]))

    # 共享弱点
    sc = {w["id"] for w in source.get("cwe", [])} & {w["id"] for w in target.get("cwe", [])}
    if sc:
        score += 2.0 * len(sc)
        reasons.append("同弱点:" + ",".join(list(sc)[:2]))

    # 共享攻击技术
    sa = {t["id"] for t in source.get("atlas", [])} & {t["id"] for t in target.get("atlas", [])}
    if sa:
        score += 2.5 * len(sa)
        reasons.append("同攻击技术:" + ",".join(list(sa)[:2]))

    # 同风险分类
    if source.get("category") and source.get("category") == target.get("category"):
        score += 0.5

    # 目标严重度加权（高危的相关情报更值得推荐）
    cvss = (target.get("cvss", {}) or {}).get("score")
    if cvss:
        score += float(cvss) * 0.08

    return score, reasons


def _light(rec, score=None, reasons=None):
    """推荐列表的轻量输出结构"""
    return {
        "id": rec.get("id"),
        "title": rec.get("title"),
        "type": rec.get("type", "vulnerability"),
        "kind": rec.get("kind", ""),
        "published": (rec.get("published") or "")[:10],
        "cvss": (rec.get("cvss", {}) or {}).get("score"),
        "severity": (rec.get("cvss", {}) or {}).get("severity", ""),
        "products": rec.get("products", [])[:4],
        "exploited": bool(rec.get("kev")),
        "poc_count": len(rec.get("poc_links", [])),
        "category": rec.get("category", ""),
        "rel_score": round(score, 2) if score else 0,
        "rel_reasons": reasons or [],
        "trust_label": rec.get("trust_label", ""),
        "confidence": rec.get("confidence", 0),
    }


# ==========================================================================
# 候选集倒排（合并版新增）
# ==========================================================================
# 合并后语料从 2.5 万级升到 8.2 万级，find_related 若仍对全库逐条打分会
# 让「打开详情 → 拉相关情报」变成秒级卡顿。此处按关系维度建倒排桶，
# 只对「至少共享一个字段」的候选打分，把 O(N) 降为 O(命中桶大小)。
CATEGORY_CAND_CAP = 3000     # 同分类只值 0.5 分，桶过大时采样，避免退化成全库扫描


def build_neighbor_index(docs):
    """建立关系候选倒排：组件 / 弱点 / 攻击技术 / 分类 → 文档下标集合"""
    by_product = defaultdict(set)
    by_cwe = defaultdict(set)
    by_atlas = defaultdict(set)
    by_cat = defaultdict(set)
    for i, d in enumerate(docs):
        for p in d.get("products", [])[:8]:
            by_product[p].add(i)
        for w in d.get("cwe", [])[:8]:
            if isinstance(w, dict) and w.get("id"):
                by_cwe[w["id"]].add(i)
        for t in d.get("atlas", [])[:8]:
            if isinstance(t, dict) and t.get("id"):
                by_atlas[t["id"]].add(i)
        c = d.get("category")
        if c:
            by_cat[c].add(i)
    return {"product": by_product, "cwe": by_cwe, "atlas": by_atlas, "cat": by_cat}


def _candidates(source, index, total):
    """由倒排桶取出候选下标集合（不含自身）"""
    if not index:
        return range(total)
    cand = set()
    for p in source.get("products", [])[:8]:
        cand |= index["product"].get(p, set())
    for w in source.get("cwe", [])[:8]:
        if isinstance(w, dict) and w.get("id"):
            cand |= index["cwe"].get(w["id"], set())
    for t in source.get("atlas", [])[:8]:
        if isinstance(t, dict) and t.get("id"):
            cand |= index["atlas"].get(t["id"], set())
    cat_bucket = index["cat"].get(source.get("category"), set())
    if cat_bucket and len(cat_bucket) <= CATEGORY_CAND_CAP:
        cand |= cat_bucket
    return cand


# ==========================================================================
# 相关情报推荐
# ==========================================================================
def find_related(rec_id, docs, top_n=8, index=None):
    """找到与指定情报相关的其他情报，按关联维度分组返回。

    index 为 build_neighbor_index() 的结果，传入即启用倒排候选加速（推荐）；
    不传则退化为全库扫描（兼容旧调用）。
    """
    source, src_i = None, -1
    for i, d in enumerate(docs):
        if d.get("id", "").upper() == rec_id.upper():
            source, src_i = d, i
            break
    if not source:
        return None

    scored = []
    for j in _candidates(source, index, len(docs)):
        if j == src_i:
            continue
        target = docs[j]
        if not isinstance(target, dict) or target.get("id") == source.get("id"):
            continue
        s, reasons = relation_score(source, target)
        if s > 0.5:
            scored.append((target, s, reasons))

    scored.sort(key=lambda x: -x[1])

    src_products = set(source.get("products", []))
    src_cwes = {w["id"] for w in source.get("cwe", []) if isinstance(w, dict)}
    src_atlas = {t["id"] for t in source.get("atlas", []) if isinstance(t, dict)}
    src_cat = source.get("category")

    same_product, same_cwe, same_atlas, same_cat = [], [], [], []
    seen_ids = set()

    for target, s, reasons in scored:
        t_id = target.get("id")
        item = _light(target, s, reasons)

        tp = set(target.get("products", []))
        tc = {w["id"] for w in target.get("cwe", []) if isinstance(w, dict)}
        ta = {t["id"] for t in target.get("atlas", []) if isinstance(t, dict)}

        if src_products & tp and len(same_product) < 6:
            same_product.append(item)
            seen_ids.add(t_id)
        elif src_cwes & tc and len(same_cwe) < 6 and t_id not in seen_ids:
            same_cwe.append(item)
            seen_ids.add(t_id)
        elif src_atlas & ta and len(same_atlas) < 6 and t_id not in seen_ids:
            same_atlas.append(item)
            seen_ids.add(t_id)
        elif src_cat and target.get("category") == src_cat and len(same_cat) < 5 and t_id not in seen_ids:
            same_cat.append(item)
            seen_ids.add(t_id)

    top_overall = [_light(t, s, r) for t, s, r in scored[:top_n]]

    return {
        "source_id": source.get("id"),
        "source_title": source.get("title"),
        "top_overall": top_overall,
        "same_product": same_product,
        "same_cwe": same_cwe,
        "atlas_related": same_atlas,
        "same_category": same_cat,
        "counts": {
            "same_product": len(same_product),
            "same_cwe": len(same_cwe),
            "atlas_related": len(same_atlas),
            "same_category": len(same_cat),
        },
    }


# ==========================================================================
# 关系图谱数据（供前端 ECharts graph 组件渲染）
# ==========================================================================
def build_graph(rec):
    """
    为单条情报构建关系图谱：
      中心：漏洞节点
      辐射：弱点 → 组件 → 攻击技术 → 战术阶段
                           → 利用代码 → 缓解措施
                           → 关联研究
    """
    nodes = []
    links = []

    vuln_id = rec.get("id")
    cvss_info = rec.get("cvss", {}) or {}
    nodes.append({
        "id": vuln_id,
        "name": vuln_id,
        "kind": "vulnerability",
        "category": 0,
        "symbolSize": 55,
        "cvss": cvss_info.get("score"),
    })

    # 弱点节点
    for w in rec.get("cwe", [])[:5]:
        wid = w["id"]
        nodes.append({
            "id": wid,
            "name": wid + " " + w.get("name", "")[:22],
            "kind": "cwe", "category": 1, "symbolSize": 36,
        })
        links.append({"source": vuln_id, "target": wid, "label": "弱点类型"})

    # 受影响组件节点
    for p in rec.get("products", [])[:6]:
        pid = "prod:" + p
        nodes.append({
            "id": pid, "name": p,
            "kind": "product", "category": 2, "symbolSize": 40,
        })
        links.append({"source": vuln_id, "target": pid, "label": "影响组件"})

    # 攻击技术节点
    for t in rec.get("atlas", [])[:6]:
        tid = t["id"]
        nodes.append({
            "id": tid,
            "name": tid + " " + t.get("name", "")[:22],
            "kind": "atlas", "category": 3, "symbolSize": 42,
        })
        links.append({"source": vuln_id, "target": tid, "label": "攻击技术"})

        # 技术 → 战术阶段
        for tac in t.get("tactics", [])[:2]:
            tac_id = "tac:" + tac
            if not any(n["id"] == tac_id for n in nodes):
                nodes.append({
                    "id": tac_id, "name": tac,
                    "kind": "tactic", "category": 4, "symbolSize": 30,
                })
            links.append({"source": tid, "target": tac_id, "label": "战术阶段"})

    # 验证/复现节点
    for i, u in enumerate(rec.get("poc_links", [])[:4]):
        node_id = "verify:" + str(i)
        low_u = u.lower()
        if "exploit-db" in low_u:
            vname = "Exploit-DB"
        elif "github" in low_u:
            vname = "GitHub 验证代码"
        elif "packetstorm" in low_u:
            vname = "PacketStorm"
        else:
            vname = "验证链接"
        nodes.append({
            "id": node_id, "name": vname,
            "kind": "verify", "category": 5, "symbolSize": 28, "url": u,
        })
        links.append({"source": vuln_id, "target": node_id, "label": "可复现"})

    # 缓解措施节点
    for m in rec.get("atlas_mitigations", [])[:4]:
        mid = m["id"]
        node_id = "mit:" + mid
        nodes.append({
            "id": node_id,
            "name": mid + " " + m.get("name", "")[:18],
            "kind": "mitigation", "category": 6, "symbolSize": 34,
        })
        # 缓解措施挂到对应的攻击技术上
        linked_techs = {r["id"] for r in m.get("techniques", []) if isinstance(r, dict)}
        placed = False
        for t in rec.get("atlas", []):
            if t["id"] in linked_techs:
                links.append({"source": t["id"], "target": node_id, "label": "缓解措施"})
                placed = True
                break
        if not placed:
            links.append({"source": vuln_id, "target": node_id, "label": "缓解"})

    # 关联研究节点
    for i, p in enumerate(rec.get("papers", [])[:3]):
        node_id = "study:" + str(i)
        nodes.append({
            "id": node_id,
            "name": p.get("title", "")[:24] + "...",
            "kind": "study", "category": 7, "symbolSize": 26, "url": p.get("url"),
        })
        links.append({"source": vuln_id, "target": node_id, "label": "关联研究"})

    categories = [
        {"name": "漏洞情报"}, {"name": "弱点(CWE)"}, {"name": "受影响组件"},
        {"name": "攻击技术(ATLAS)"}, {"name": "战术阶段"}, {"name": "验证代码"},
        {"name": "缓解措施"}, {"name": "学术研究"},
    ]

    return {
        "nodes": nodes,
        "links": links,
        "categories": categories,
        "stats": {"nodes": len(nodes), "links": len(links)},
    }


# ==========================================================================
# CTI 知识图谱多跳关联（决赛创新点①：CVE ↔ 组件 ↔ 资产 ↔ 攻击技术 多跳）
# ==========================================================================
# 单条 build_graph 只是「一颗星」（CVE 中心辐射一层）。真正的 CTI 知识图谱
# 要能沿关系**多跳游走**：从一个 CVE 出发，沿「共享组件 / 共享攻击技术」跳到
# 相邻 CVE，再跳到它们各自挂的资产、弱点、战术 —— 形成一张可解释的攻击面图，
# 回答「这个漏洞背后到底牵连了哪些资产、哪些相关漏洞、哪些战术路径」。
#
# 资产节点来自两处：① 情报记录自带的 assets 字段；② 受影响组件（products）
# 作为「逻辑资产」占位。多跳游走仅靠内存 docs（不 import 其他模块），
# 用倒排索引保证 O(命中桶) 复杂度，不随 8.2 万语料线性放大。


def _asset_node_id(p):
    return "asset:" + str(p)


def build_graph_multi(rec, docs, index=None, max_hops=2, max_related_cves=6):
    """在单条 build_graph 基础上做多跳扩展。

    返回结构与 build_graph 兼容（nodes/links/categories），并额外追加：
      hops:        实际游走到的跳数
      related_cves: 沿共享组件/攻击技术跳到的相邻 CVE（含跳数、命中关系）
      path_examples:可读的多跳关联路径示例（供 XAI 解释「为什么它们连在一起」）

    多跳策略（跳数上限 2，覆盖「CVE→组件→资产→技术→战术」的完整链路）：
      第 1 跳：本 CVE 直连的组件 / 攻击技术 / 资产 / 弱点 / 战术（build_graph 已有）
      第 2 跳：与任一相邻 CVE 共享组件或攻击技术 → 并入这些 CVE 及其资产节点
    """
    base = build_graph(rec)
    nodes, links = base["nodes"], base["links"]
    seen_ids = {n["id"] for n in nodes}
    related = []          # 相邻 CVE 信息
    paths = []            # 多跳路径示例

    if not index or not docs:
        return _finalize(base, nodes, links, 1, related, paths)

    # 相邻 CVE 候选：与源共享组件 / 攻击技术的文档
    src_products = set(rec.get("products", []))
    src_atlas = {t["id"] for t in rec.get("atlas", []) if isinstance(t, dict)}

    hop1_candidates = set()
    for p in src_products:
        hop1_candidates |= index["product"].get(p, set())
    for t in src_atlas:
        hop1_candidates |= index["atlas"].get(t, set())

    # 打分排序：共享组件多 + CVSS 高者优先
    scored = []
    src_i = None
    for i, d in enumerate(docs):
        if d.get("id", "").upper() == (rec.get("id") or "").upper():
            src_i = i
            break
    for j in hop1_candidates:
        if j == src_i:
            continue
        t = docs[j]
        if not isinstance(t, dict) or t.get("id") == rec.get("id"):
            continue
        sp = src_products & set(t.get("products", []))
        sa = src_atlas & {x["id"] for x in t.get("atlas", []) if isinstance(x, dict)}
        if not sp and not sa:
            continue
        s = 3.0 * len(sp) + 2.5 * len(sa) + float((t.get("cvss") or {}).get("score") or 0) * 0.08
        scored.append((t, s, sp, sa))
    scored.sort(key=lambda x: -x[1])

    for t, s, sp, sa in scored[:max_related_cves]:
        tid = t.get("id")
        # 相邻 CVE 节点（第 2 跳，用 category=8 区分「关联漏洞」）
        nodes.append({
            "id": "cve:" + tid, "name": tid, "kind": "related_cve",
            "category": 8, "symbolSize": 44,
            "cvss": (t.get("cvss") or {}).get("score"),
            "rel": list(sp)[:2] + list(sa)[:2],
        })
        # 连接：源 → 相邻 CVE（标签标注命中关系）
        hop_label = []
        if sp:
            hop_label.append("同组件:" + ",".join(list(sp)[:1]))
        if sa:
            hop_label.append("同技术:" + ",".join(list(sa)[:1]))
        links.append({"source": rec.get("id"), "target": "cve:" + tid,
                      "label": ";".join(hop_label)})
        # 相邻 CVE 各自的资产节点（第 2 跳终点）
        for p in t.get("products", [])[:2]:
            aid = _asset_node_id(tid + "|" + p)
            if aid in seen_ids:
                continue
            seen_ids.add(aid)
            nodes.append({"id": aid, "name": p, "kind": "asset",
                          "category": 2, "symbolSize": 30})
            links.append({"source": "cve:" + tid, "target": aid, "label": "影响组件"})
        related.append({
            "cve": tid,
            "hop": 2,
            "shared_products": sorted(sp)[:4],
            "shared_techniques": sorted(sa)[:4],
            "cvss": (t.get("cvss") or {}).get("score"),
            "exploited": bool(t.get("kev")),
        })
        if sp and len(paths) < 4:
            paths.append(f"{rec.get('id')} —同组件({sorted(sp)[0]})→ {tid}")
        elif sa and len(paths) < 4:
            paths.append(f"{rec.get('id')} —同攻击技术({sorted(sa)[0]})→ {tid}")

    return _finalize(base, nodes, links, 2 if related else 1, related, paths)


def _finalize(base, nodes, links, hops, related, paths):
    base["nodes"] = nodes
    base["links"] = links
    base["hops"] = hops
    base["related_cves"] = related
    base["path_examples"] = paths
    base["stats"] = {"nodes": len(nodes), "links": len(links), "hops": hops,
                     "related_cves": len(related)}
    # 追加「关联漏洞」图例（若尚无）
    names = {c["name"] for c in base["categories"]}
    if "关联漏洞" not in names:
        base["categories"].append({"name": "关联漏洞"})
    return base


if __name__ == "__main__":
    import io
    import sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    demo = {
        "id": "CVE-2024-12345",
        "title": "Inference Server RCE",
        "products": ["vllm"],
        "category": "test",
        "cwe": [{"id": "CWE-78", "name": "OS Command Injection"}],
        "atlas": [{"id": "AML.T0049", "name": "Exploit Public-Facing Application",
                    "tactics": ["AML.TA0001"]}],
        "poc_links": ["https://github.com/demo/repo"],
        "atlas_mitigations": [{
            "id": "AML.M0002", "name": "Input Validation",
            "techniques": [{"id": "AML.T0049"}], "use": "Validate inputs",
        }],
        "papers": [{"title": "A Study on Inference Server Security", "url": "http://demo"}],
        "cvss": {"score": 9.1, "severity": "CRITICAL"},
    }
    g = build_graph(demo)
    print("nodes=" + str(g["stats"]["nodes"]) + " links=" + str(g["stats"]["links"]))
    for n in g["nodes"]:
        print("  [" + n["kind"] + "] " + n["id"] + " | " + n["name"][:32])

    # 测试关联推荐
    docs = [demo, {
        "id": "CVE-2024-67890", "title": "Another vllm issue",
        "products": ["vllm"], "cwe": [{"id": "CWE-78"}],
        "atlas": [], "cvss": {"score": 7.5, "severity": "HIGH"},
    }]
    rel = find_related("CVE-2024-12345", docs)
    print("\nrelated top:", [(x["id"], x["rel_score"]) for x in rel["top_overall"]])
