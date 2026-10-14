# -*- coding: utf-8 -*-
"""
atlas.py —— MITRE ATLAS 威胁知识库接入
========================================
解决 NVD 的固有盲区：越狱、模型窃取、数据投毒、RAG 投毒等**模型层风险**
大多不会被分配 CVE，因此仅靠 NVD 无法覆盖赛题附录中的第②类风险。

MITRE ATLAS 是面向 AI 系统的对抗战术与技术知识库（170 项技术 / 35 项缓解措施 /
57 个真实案例），本模块负责：
  1. 拉取并解析 ATLAS 数据（ATLAS.yaml），建立本地技术库
  2. 依据领域规则把漏洞情报映射到 ATLAS 技术（可解释的"攻击链"富化维度）
  3. 反查 ATLAS 官方缓解措施，作为修复建议的权威补充

数据源： https://github.com/mitre-atlas/atlas-data  (dist/ATLAS.yaml)
"""

import json
import os
import re
import urllib.request
import paths  # noqa: E402 —— 数据目录统一解析（core/paths.py）



def _yaml():
    """惰性加载 PyYAML：仅在需要联网解析 ATLAS.yaml 时才要求该依赖。
    本地已有 data/atlas.json 缓存时，整套系统零第三方依赖即可运行。"""
    try:
        import yaml  # noqa: PLC0415
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "解析 ATLAS.yaml 需要 PyYAML（pip install pyyaml）。"
            "若已存在 data/atlas.json 缓存，则无需该依赖。") from e
    return yaml

ATLAS_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = paths.data_path("atlas.json")
UA = {"User-Agent": "AI-Sec-Intel-Collector/1.0 (academic competition project)"}
LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def clean(txt):
    """去掉 ATLAS 描述里的 Markdown 链接语法"""
    return " ".join(LINK_RE.sub(r"\1", str(txt or "")).split())


# --------------------------------------------------------------------------
# 领域映射规则： technique_id -> 触发关键词（词边界匹配）
# --------------------------------------------------------------------------
TECH_RULES = {
    "AML.T0051": ["prompt injection", "prompt-injection", "inject a prompt", "prompt manipulation"],
    "AML.T0051.000": ["direct prompt injection"],
    "AML.T0051.001": ["indirect prompt injection", "cross-domain prompt injection",
                      "prompt injection through", "prompt injection via"],
    "AML.T0054": ["jailbreak", "guardrail bypass", "safety filter bypass", "safety bypass",
                  "alignment bypass", "circumvent safety", "bypass restrictions"],
    "AML.T0057": ["system prompt", "prompt leakage", "prompt leak", "training data extraction",
                  "memorization", "sensitive information disclosure"],
    "AML.T0044": ["model weights", "safetensors", "model checkpoint", "model file",
                  "full model access", "model artifact"],
    "AML.T0020": ["poisoning", "poisoned", "poison training", "label manipulation"],
    "AML.T0018": ["backdoor", "trojan", "adversarially modified model"],
    "AML.T0010": ["supply chain", "dependency confusion", "malicious package", "typosquat",
                  "untrusted model repository"],
    "AML.T0043": ["adversarial", "evasion attack", "perturbation"],
    "AML.T0024": ["model extraction", "model theft", "model stealing", "membership inference"],
    "AML.T0029": ["resource exhaustion", "gpu exhaustion", "model denial of service"],
    "AML.T0070": ["rag poisoning", "index poisoning", "knowledge base poisoning",
                  "vector database poisoning", "embedding poisoning"],
    "AML.T0071": ["malicious document", "injected document", "retrieval poisoning"],
    "AML.T0053": ["tool invocation", "tool calling", "function calling", "agent tool",
                  "tool abuse", "tool use bypass"],
    "AML.T0040": ["inference api", "model endpoint", "inference endpoint"],
    "AML.T0055": ["hard-coded credential", "hardcoded credential", "api key leak"],
    "AML.T0052": ["spearphishing", "phishing email generated"],
    "AML.T0025": ["exfiltration via", "data exfiltration"],
    "AML.T0049": ["exploit public-facing application"],
}
# 反向：把 CWE 直接映射到 ATLAS 技术（结构化信号优先）
CWE_TO_TECH = {
    "CWE-1336": ["AML.T0051"],
    "CWE-1427": ["AML.T0051.000"],
    "CWE-1426": ["AML.T0051"],
    "CWE-502": ["AML.T0044"],
    "CWE-506": ["AML.T0018"],
    "CWE-494": ["AML.T0010"],
    "CWE-829": ["AML.T0010"],
    "CWE-1104": ["AML.T0010"],
    "CWE-1389": ["AML.T0010"],
}


class AtlasKB:
    def __init__(self, cache=CACHE, refresh=False):
        self.tech = {}
        self.tactics = {}
        self.mitigations = []
        self.case_studies = []
        self.version = ""
        if os.path.isfile(cache) and not refresh:
            with open(cache, "r", encoding="utf-8") as f:
                d = json.load(f)
        else:
            d = self._download()
        self._load(d)

    def _download(self):
        import time
        urls = [
            ATLAS_URL,
            "https://cdn.jsdelivr.net/gh/mitre-atlas/atlas-data@main/dist/ATLAS.yaml",
        ]
        raw, last = None, None
        for attempt in range(4):
            for u in urls:
                try:
                    req = urllib.request.Request(u, headers=UA)
                    raw = urllib.request.urlopen(req, timeout=90).read()
                    if raw and len(raw) > 10000:
                        break
                except Exception as e:  # noqa: BLE001
                    last = e
                    raw = None
            if raw:
                break
            time.sleep(4 * (attempt + 1))
        if not raw:
            raise RuntimeError(f"ATLAS 数据获取失败（已重试 4 次）：{last}")
        data = _yaml().safe_load(raw)
        m = data["matrices"][0]
        out = {
            "version": str(data.get("version", "")),
            "tactics": [{"id": t.get("id"), "name": t.get("name")} for t in m.get("tactics", [])],
            "techniques": [],
            "mitigations": [],
            "case_studies": [],
        }
        for t in m.get("techniques", []):
            out["techniques"].append({
                "id": t.get("id"), "name": t.get("name"),
                "description": clean(t.get("description"))[:1200],
                "tactics": t.get("tactics") or [],
                "maturity": t.get("maturity") or "",
                "created": str(t.get("created_date") or ""),
                "modified": str(t.get("modified_date") or ""),
            })
        for mi in m.get("mitigations", []):
            refs = []
            for r in (mi.get("techniques") or []):
                if isinstance(r, dict) and r.get("id"):
                    refs.append({"id": r["id"], "use": clean(r.get("use"))[:400]})
            out["mitigations"].append({
                "id": mi.get("id"), "name": mi.get("name"),
                "description": clean(mi.get("description"))[:900],
                "category": mi.get("category") or [],
                "techniques": refs,
            })
        for cs in data.get("case-studies", []):
            out["case_studies"].append({
                "name": cs.get("name"),
                "summary": clean(cs.get("description") or cs.get("summary"))[:900],
                "techniques": [x.get("id") for x in (cs.get("techniques") or []) if isinstance(x, dict)],
                "references": [r.get("url") for r in (cs.get("references") or []) if isinstance(r, dict)][:5],
            })
        os.makedirs(os.path.dirname(CACHE), exist_ok=True)
        with open(CACHE, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=1)
        return out

    def _load(self, d):
        self.version = d.get("version", "")
        self.tactics = {t["id"]: t["name"] for t in d.get("tactics", [])}
        for t in d.get("techniques", []):
            t = dict(t)
            t["tactic_names"] = [self.tactics.get(x, x) for x in t.get("tactics", [])]
            self.tech[t["id"]] = t
        self.mitigations = d.get("mitigations", [])
        self.case_studies = d.get("case_studies", [])
        unknown = [k for k in TECH_RULES if k not in self.tech]
        if unknown:
            print("  [atlas] 规则中未在知识库找到的技术 ID（已忽略）：", unknown)

    # ------------------------------------------------------------------
    @staticmethod
    def _hit(term, text):
        pat = r"(?<![a-z0-9])" + re.escape(term).replace(r"\ ", r"[\s\-_]+") + r"(?![a-z0-9])"
        return re.search(pat, text) is not None

    def map_record(self, rec, limit=4):
        """把一条漏洞情报映射到 ATLAS 技术，返回 (技术列表, 依据说明)"""
        text = (rec.get("desc", "") + " " + rec.get("title", "") + " " +
                " ".join(rec.get("products", []))).lower()
        votes, why = {}, []

        # 1) CWE 结构化映射（最可信）
        for w in rec.get("cwe", []):
            for tid in CWE_TO_TECH.get(w["id"], []):
                votes[tid] = votes.get(tid, 0) + 3.0
                why.append(f"{w['id']} → {tid}")

        # 2) 关键词映射
        for tid, keys in TECH_RULES.items():
            if tid not in self.tech:
                continue
            hits = [k for k in keys if self._hit(k, text)]
            if hits:
                votes[tid] = votes.get(tid, 0) + 1.0 * len(hits) + 0.5
                why.append(f"命中 {hits[0]}")

        # 3) ATLAS 技术名直接命中
        for tid, t in self.tech.items():
            if len(t["name"]) >= 8 and self._hit(t["name"].lower(), text):
                votes[tid] = votes.get(tid, 0) + 2.0
                why.append(f"技术名 {t['name']}")

        if not votes:
            return [], []
        ordered = sorted(votes.items(), key=lambda x: -x[1])[:limit]
        out = []
        for tid, sc in ordered:
            t = self.tech[tid]
            out.append({
                "id": tid, "name": t["name"],
                "tactics": t["tactic_names"],
                "description": t["description"][:460],
                "url": f"https://atlas.mitre.org/techniques/{tid}",
                "score": round(min(sc / 3.0, 1.0), 2),
            })
        return out, why[:6]

    def mitigations_for(self, tech_ids, limit=4):
        pts = []
        for mi in self.mitigations:
            for r in mi["techniques"]:
                if r["id"] in tech_ids:
                    pts.append({
                        "id": mi["id"], "name": mi["name"],
                        "use": r["use"] or mi["description"][:300],
                        "category": mi["category"],
                        "url": f"https://atlas.mitre.org/mitigations/{mi['id']}",
                    })
                    break
        # 去重
        seen, out = set(), []
        for p in pts:
            if p["id"] in seen:
                continue
            seen.add(p["id"])
            out.append(p)
        return out[:limit]

    def cases_for(self, tech_ids, limit=3):
        out = []
        for cs in self.case_studies:
            if set(cs["techniques"]) & set(tech_ids):
                out.append({"name": cs["name"], "summary": cs["summary"],
                            "references": cs["references"]})
        return out[:limit]

    def stats(self):
        return {"version": self.version, "techniques": len(self.tech),
                "tactics": len(self.tactics), "mitigations": len(self.mitigations),
                "case_studies": len(self.case_studies)}

    # ------------------------------------------------------------------
    # 把 ATLAS 技术转成与漏洞情报同构的"知识条目"，以便统一检索与展示。
    # 这些条目本身没有 CVE，却正是模型层风险（越狱/投毒/模型窃取）的权威来源。
    # ------------------------------------------------------------------
    TECH_CATEGORY = {
        "AML.T0051": "③ AI应用与智能体", "AML.T0051.000": "② 模型与数据层",
        "AML.T0051.001": "③ AI应用与智能体", "AML.T0051.002": "③ AI应用与智能体",
        "AML.T0054": "② 模型与数据层", "AML.T0057": "② 模型与数据层",
        "AML.T0069": "② 模型与数据层", "AML.T0069.000": "② 模型与数据层",
        "AML.T0069.001": "② 模型与数据层", "AML.T0069.002": "② 模型与数据层",
        "AML.T0044": "② 模型与数据层", "AML.T0020": "② 模型与数据层",
        "AML.T0018": "② 模型与数据层", "AML.T0043": "② 模型与数据层",
        "AML.T0024": "② 模型与数据层", "AML.T0040": "① AI基础设施与推理框架",
        "AML.T0029": "① AI基础设施与推理框架", "AML.T0010": "④ AI供应链与平台",
        "AML.T0053": "③ AI应用与智能体", "AML.T0070": "③ AI应用与智能体",
        "AML.T0071": "③ AI应用与智能体", "AML.T0108": "③ AI应用与智能体",
    }

    def to_records(self):
        out = []
        for tid, t in self.tech.items():
            # 只保留主技术（子技术以 .xxx 结尾）与有实质描述者
            mits = self.mitigations_for([tid], limit=5)
            cat = self.TECH_CATEGORY.get(tid)
            if not cat:
                cat = self.TECH_CATEGORY.get(tid.split(".")[0], "④ AI供应链与平台")
            out.append({
                "id": tid,
                "type": "knowledge",
                "kind": "MITRE ATLAS 威胁技术",
                "title": t["name"],
                "desc": t["description"],
                "published": t.get("created") or "",
                "modified": t.get("modified") or "",
                "status": "知识库条目",
                "cvss": {"score": None, "severity": "", "vector": "", "version": "",
                         "exploitability": None, "impact": None},
                "cwe": [], "cpe": [], "products": [], "vendors": [], "refs": [],
                "poc_links": [], "patch_links": [],
                "advisory_links": ["https://atlas.mitre.org/techniques/" + tid],
                "osv_packages": [], "osv_summaries": [], "osv_refs": [],
                "sources": ["MITRE ATLAS"],
                "kev": {},
                "tags": ["ATLAS 威胁技术"] + list(t.get("tactic_names", [])),
                "risk_tags": list(t.get("tactic_names", [])),
                "ai_score": 1.0,
                "category": cat,
                "category_reason": "MITRE ATLAS 战术归属：" + "、".join(t.get("tactic_names", []))
                                   + f"（ATLAS {self.version}）",
                "atlas": [{"id": tid, "name": t["name"], "tactics": t.get("tactic_names", []),
                           "description": t["description"][:460], "score": 1.0,
                           "url": f"https://atlas.mitre.org/techniques/{tid}"}],
                "atlas_mitigations": mits,
                "atlas_cases": self.cases_for([tid], limit=3),
                "papers": [],
                "remediation": [f"{m['id']} {m['name']}：{m['use'][:220]}" for m in mits] or
                               ["参见 MITRE ATLAS 对应技术页面的缓解措施章节"],
            })
        out.sort(key=lambda r: r["id"])
        return out


if __name__ == "__main__":
    import io
    import sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    kb = AtlasKB(refresh=True)
    print("ATLAS 知识库：", kb.stats())
    demo = {"desc": "A vulnerability in vLLM allows remote code execution. The model weights "
                     "are loaded from an untrusted safetensors file, enabling prompt injection "
                     "and jailbreak of the served large language model. RAG poisoning is possible.",
            "title": "vLLM RCE", "products": ["vllm"], "cwe": [{"id": "CWE-502"}]}
    techs, why = kb.map_record(demo)
    for t in techs:
        print(" ", t["id"], t["name"], t["tactics"], t["score"])
    print("依据:", why)
    print("缓解措施:", [(m["id"], m["name"]) for m in kb.mitigations_for([t["id"] for t in techs])])
