# -*- coding: utf-8 -*-
"""
harvest_github.py —— GitHub 语料大规模扩容
================================================
两条通道（均绕过 GitHub API 匿名 60/h 限额）：

  1. GHSA 全量：下载 github/advisory-database 官方仓库 tarball（codeload，
     无速率限制），流式解析 advisories/github-reviewed/**.json（OSV 格式）。
     · 含 CVE alias 的公告 → ghsa_by_cve（供 merge 并回 CVE 记录）
     · 无 CVE alias 的公告 → ghsa_standalone（独立知识条目）
     · 公告引用中的 github.com/{owner}/{repo} → 受影响项目条目（GitHub 语料）

  2. GitHub 仓库元数据：ecosyste.ms 公共 API（免密钥、限额宽松），
     按安全 topic 分页收割，star/描述门控，断点续跑。

产出：
  data/ghsa_full.json   {ghsa_by_cve, ghsa_standalone, meta}
  data/gh_repos.json    [repo 知识条目...]
"""

import io
import json
import os
import re
import sys
import tarfile
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extra_sources as X  # noqa: E402
# —— 模块化结构：数据目录统一由 core/paths.py 解析（本文件可独立运行）——
import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import paths  # noqa: E402


HERE = os.path.dirname(os.path.abspath(__file__))
DATA = paths.DATA_DIR
TARBALL = os.path.join(DATA, "ghsa", "advisory-db.tar.gz")
GHSA_OUT = os.path.join(DATA, "ghsa_full.json")
REPO_DIR = os.path.join(DATA, "gh_repos_ai")   # AI 专属 topic 收割的状态与分片目录
REPO_OUT = os.path.join(DATA, "gh_repos.json")
os.makedirs(os.path.dirname(TARBALL), exist_ok=True)
os.makedirs(REPO_DIR, exist_ok=True)

TARBALL_URL = "https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main"
MIN_STARS = 2
OWNER_CAP = 300          # 每个 owner 最多收录多少仓库
PER_PAGE = 100           # ecosyste.ms owner 端点每页条数
PAGE_SLEEP = 0.6         # 页间节流（API 免密钥，宽松但不必打满）

# AI 安全相关的组织 / 个人（owner 维度枚举）
# 弃用 topic 维度的原因：ecosyste.ms 的 ?topic= 过滤参数被服务端忽略，
# 不同 topic 返回完全相同的全局列表（按 id 升序的 0-star 仓库），
# 实测同一批 2,435 条记录里只有 85 个唯一 id —— 等于没有按主题取数。
AI_OWNERS = sorted({
    # ① AI 基础设施 / 推理框架 / 训练栈
    "ollama", "vllm-project", "ggml-org", "ggerganov", "sgl-project",
    "triton-inference-server", "NVIDIA", "pytorch", "tensorflow", "keras-team",
    "openxla", "onnx", "microsoft", "google", "google-deepmind",
    "ray-project", "kubeflow", "mlflow", "kserve", "seldon",
    "bentoml", "tvm", "tlcpack", "apache", "Lightning-AI", "fastai",
    "mosaicml", "deepspeedai", "paddlepaddle", "PaddlePaddle", "horovod",
    "Unbabel", "petuum", "h2oai", "dmlc", "zilliztech", "milvus-io",
    "qdrant", "weaviate", "chroma-core", "lancedb", "activeloopai",
    "pgvector", "facebookresearch", "nmslib", "spotify", "unum-cloud",
    "vespa-engine", "opensearch-project", "elastic", "marqo-ai",
    "feast-dev", "featurestoreorg", "iterative", "dagster-io", "wandb",
    "determined-ai", "kubeflow", "LocalAI-io", "mudler", "oobabooga",
    "lostruins", "nomic-ai", "unslothai", "vllm-project",
    # ② 模型与数据层（提示词注入 / 越狱 / 投毒 / 对抗 / 护栏）
    "centerforaisafety", "leondz", "protectai", "guardrails-ai",
    "NVIDIA", "deepset-ai", "explodinggradients", "promptfoo",
    "meta-llama", "anthropics", "openai", "google-research", "cohere-ai",
    "ai21labs", "EleutherAI", "stabilityai", "CompVis", "AUTOMATIC1111",
    "invoke-ai", "comfyanonymous", "huggingface", "QwenLM", "deepseek-ai",
    "mistralai", "THUDM", "OpenBMB", "internlm", "baichuan-inc", "zhipuai",
    "MoonshotAI", "01-ai", "MiniMax-AI", "modelscope", "sensenova",
    "SheffieldML", "facebook", "stanfordnlp", "princeton-nlp", "AI-Secure",
    "unitaryai", "giskard-ai", "lakeraai", "robustintelligence",
    "Trusted-AI", "fairlearn", "IBM", "tensorflow",
    # ③ AI 应用与智能体
    "langchain-ai", "run-llama", "BerriAI", "FlowiseAI", "n8n-io",
    "langgenius", "infiniflow", "activepieces", "modelcontextprotocol",
    "crewAIInc", "joaomdmoura", "Significant-Gravitas", "TransformerOptimus",
    "OpenInterpreter", "KillianLucas", "All-Hands-AI", "browser-use",
    "Skyvern-AI", "e2b-dev", "continuedev", "TabbyML", "block", "sourcegraph",
    "aider-AI", "paul-gauthier", "lobehub", "open-webui", "SillyTavern",
    "chatwoot", "RocketChat", "danny-avila", "mckaywrigley", "binary-husky",
    "lobehub", "reworkd", "microsoft", "microsoftresearch", "Azure",
    "vercel", "supabase", "chroma-core", "weaviate",
    # ④ AI 供应链 / 平台 / 安全检测
    "ossf", "sigstore", "pypa", "safetensors", "huggingface", "modelscope",
    "aquasecurity", "anchore", "semgrep", "returntocorp", "bridgecrewio",
    "derailed", "zaproxy", "OWASP", "trailofbits", "NCCGroup",
    "WithSecureLabs", "mandiant", "projectdiscovery", "rapid7", "qualys",
    "swisskyrepo", "danielmiessler", "sensepost", "PortSwigger",
    "cisagov", "mitre", "mitre-attack", "MITRECyber", "owasp-amass",
    "SIWECOS", "AI-Security", "microsoft", "google",
})



def log(*a):
    print("[gh]", *a, flush=True)


# ==========================================================================
# 1. GHSA 全量（tarball 流式解析）
# ==========================================================================
_SEV_MAP = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM",
            "MEDIUM": "MEDIUM", "LOW": "LOW"}
_GH_REPO_RE = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:/|$)")


def _ghsa_to_rec(a):
    """advisory-database 的 OSV 格式公告 → skeleton 记录；返回 (rec, cve, repo_names)"""
    gid = a.get("id") or ""
    if not gid.startswith("GHSA-"):
        return None, "", []
    aliases = a.get("aliases") or []
    cve = next((x for x in aliases if x.startswith("CVE-")), "")
    dbs = a.get("database_specific") or {}
    pkgs, ranges_txt, repos = [], [], set()
    for aff in a.get("affected") or []:
        pn = ((aff.get("package") or {}).get("name")) or ""
        if pn:
            pkgs.append(pn)
        for r in aff.get("ranges") or []:
            events = r.get("events") or []
            intro = fixed = ""
            for ev in events:
                intro = intro or ev.get("introduced", "")
                fixed = fixed or ev.get("fixed", "")
            if pn and (intro or fixed):
                ranges_txt.append(f"{pn}: {intro or '*'} → 修复 {fixed or '待定'}")
    refs = [r.get("url") for r in (a.get("references") or []) if r.get("url")]
    for u in refs:
        m = _GH_REPO_RE.match(u)
        if m and not any(k in u for k in ("/commit/", "/pull/", "/issues", "/releases", "/blob/")):
            repos.add(m.group(1))
    sev_gh = (dbs.get("severity") or "").upper()
    sev = _SEV_MAP.get(sev_gh, sev_gh if sev_gh in _SEV_MAP.values() else "")
    cvss_vec = ""
    for s in a.get("severity") or []:
        if (s.get("type") or "").startswith("CVSS"):
            cvss_vec = s.get("score") or ""
            break
    summary = " ".join((a.get("summary") or "").split())
    details = " ".join((a.get("details") or "").split())
    desc = details or summary
    if ranges_txt:
        desc = (desc + "\n受影响版本区间：" + "；".join(ranges_txt[:6])).strip()
    cat = X._guess_category(desc + " " + summary, pkgs)
    rec = X._skeleton(
        rid=gid, rtype="advisory", kind="GitHub 供应链公告",
        title=summary or gid,
        desc=desc or summary,
        published=(a.get("published") or "")[:10],
        sources=["GitHub Advisory"],
        category=cat,
        reason=f"GitHub 官方供应链公告（affects={', '.join(pkgs[:4]) or '多生态'}）",
        tags=["供应链公告"] + [f"包:{p}" for p in pkgs[:4]],
    )
    rec["modified"] = (a.get("modified") or "")[:10]
    rec["products"] = sorted(set(pkgs))[:8]
    # OSV 的 severity 字段是 CVSS 向量字符串，无数值分；数值分留空由 UI 显示"—"
    rec["cvss"] = {"score": None, "severity": sev, "vector": cvss_vec,
                   "version": "", "exploitability": None, "impact": None}
    rec["advisory_links"] = [f"https://github.com/advisories/{gid}"]
    rec["cwe"] = [{"id": w, "name": "", "source": "GitHub"}
                  for w in (dbs.get("cwe_ids") or [])][:3]
    rec["refs"] = [{"url": u, "tags": [], "source": "GHSA"} for u in refs[:8]]
    return rec, cve, sorted(repos)


def harvest_ghsa():
    log("下载 advisory-database tarball（一次性，数百 MB，无速率限制）...")
    if not os.path.isfile(TARBALL) or os.path.getsize(TARBALL) < 10 * 1024 * 1024:
        import urllib.request
        req = urllib.request.Request(TARBALL_URL, headers=X.UA)
        tmp = TARBALL + ".part"
        with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
            n = 0
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
                n += len(chunk)
                if n % (100 << 20) < (1 << 20):
                    log(f"  已下载 {n >> 20} MB ...")
        os.replace(tmp, TARBALL)
    log(f"tarball 就绪：{os.path.getsize(TARBALL) >> 20} MB，开始流式解析 ...")

    by_cve, standalone = {}, []
    repo_hits = {}   # full_name -> [advisory summaries]
    n = 0
    t0 = time.time()
    with tarfile.open(TARBALL, "r:gz") as tf:
        for m in tf:
            if not m.isfile() or not m.name.endswith(".json"):
                continue
            if "/github-reviewed/" not in m.name:
                continue
            try:
                a = json.loads(tf.extractfile(m).read().decode("utf-8"))
            except Exception:  # noqa: BLE001
                continue
            rec, cve, repos = _ghsa_to_rec(a)
            n += 1
            if n % 20000 == 0:
                log(f"  已解析 {n} 条公告（{round(time.time()-t0)}s）...")
            if not rec:
                continue
            if cve:
                by_cve.setdefault(cve.upper(), []).append(rec)
            else:
                standalone.append(rec)
            for rp in repos:
                repo_hits.setdefault(rp, []).append(rec["title"][:120])
    log(f"GHSA 解析完成：{n} 条 → by_cve {len(by_cve)} 组 / 独立 {len(standalone)} 条 / "
        f"受影响项目 {len(repo_hits)} 个")

    # 受影响 GitHub 项目 → 轻量 repo 条目（GHSA 关联的项目是真实的安全相关仓库语料）
    proj_docs = []
    for name, titles in sorted(repo_hits.items()):
        desc = ("该项目受 GitHub Security Advisory 公告影响：" +
                "；".join(titles[:3])[:600])
        rec = X._skeleton(
            rid="GH-PROJ:" + name, rtype="repo", kind="GitHub 受影响项目（GHSA 关联）",
            title=name,
            desc=desc,
            published="",
            sources=["GitHub Advisory"],
            category=X._guess_category(desc),
            reason=f"出现在 {len(titles)} 条 GHSA 公告的受影响仓库引用中",
            tags=["受影响项目", "供应链"],
        )
        rec["repo_url"] = f"https://github.com/{name}"
        rec["advisory_links"] = [f"https://github.com/{name}"]
        rec["ghsa_count"] = len(titles)
        proj_docs.append(rec)

    data = {
        "ghsa_by_cve": by_cve,
        "ghsa_standalone": standalone,
        "ghsa_projects": proj_docs,
        "meta": {
            "collected_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "total_advisories": n,
            "by_cve": len(by_cve), "standalone": len(standalone),
            "projects": len(proj_docs),
        },
    }
    with open(GHSA_OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    log(f"写入 {GHSA_OUT}（{os.path.getsize(GHSA_OUT) >> 20} MB）")
    return data


# ==========================================================================
# 2. ecosyste.ms 仓库收割（断点续跑，按 topic 分片落盘）
# ==========================================================================
def _fetch_owner_page(owner, page):
    url = ("https://repos.ecosyste.ms/api/v1/hosts/GitHub/owners/"
           f"{urllib.parse.quote(owner)}/repositories"
           f"?per_page={PER_PAGE}&page={page}")
    try:
        return X.get_json(url, tries=2)
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        if "400" in msg or "404" in msg:
            return []          # 越界页 / 无此 owner，不重试
        log(f"  owner={owner} p{page} 失败: {msg[:50]}")
        time.sleep(15)
        try:
            return X.get_json(url, tries=2)
        except Exception:  # noqa: BLE001
            return []


def _repo_to_rec(r):
    full = r.get("full_name") or ""
    topics = r.get("topics") or []
    if not full:
        return None
    stars = r.get("stargazers_count") or 0
    if stars < MIN_STARS:
        return None
    desc = " ".join((r.get("description") or "").split())
    if len(desc) < 10:
        # 无简介仓库：用语言与 topic 合成可检索描述（ecosyste.ms 按 id 序返回，
        # 大量优质仓库没有 description，一概丢弃会损失大半语料）
        if not topics and not r.get("language"):
            return None
        desc = (f"GitHub 安全仓库 {full}。"
                + (f"主要语言：{r.get('language')}。" if r.get("language") else "")
                + ("主题：" + "、".join(topics[:8]) + "。" if topics else ""))
    rec = X._skeleton(
        rid="GH:" + full, rtype="repo", kind="GitHub 安全工具仓库",
        title=full,
        desc=desc,
        published=(r.get("created_at") or "")[:10],
        sources=["GitHub"],
        category=X._guess_category(desc + " " + " ".join(topics)),
        reason="GitHub topic 检索命中（" + "、".join(topics[:4]) + "）",
        tags=["安全工具仓库"] + topics[:5],
    )
    rec["modified"] = (r.get("pushed_at") or "")[:10]
    rec["stars"] = stars
    rec["language"] = r.get("language") or ""
    rec["repo_topics"] = topics[:10]
    rec["repo_url"] = r.get("html_url") or ("https://github.com/" + full)
    rec["advisory_links"] = [rec["repo_url"]]
    return rec


def harvest_repos():
    """按 owner 维度枚举 AI 相关组织 / 个人的仓库（断点续跑，owner 粒度状态）。"""
    state_fp = os.path.join(REPO_DIR, "_state.json")
    st = {"done": [], "owners": []}
    if os.path.isfile(state_fp):
        with open(state_fp, "r", encoding="utf-8") as f:
            st = json.load(f)
    done = set(st.get("owners") or [])
    total = len(AI_OWNERS)
    log(f"ecosyste.ms 仓库收割（owner 维度）：{total} 个 owner（已完成 {len(done)}）")
    for i, owner in enumerate(AI_OWNERS, 1):
        if owner in done:
            continue
        recs, seen = [], set()
        page = 1
        while len(recs) < OWNER_CAP:
            arr = _fetch_owner_page(owner, page)
            if not arr:
                break
            for r in arr:
                full = r.get("full_name")
                if not full or full in seen:
                    continue
                seen.add(full)
                if r.get("archived"):
                    continue
                rec = _repo_to_rec(r)
                if rec:
                    recs.append(rec)
            if len(arr) < PER_PAGE:
                break
            page += 1
            time.sleep(PAGE_SLEEP)
        time.sleep(PAGE_SLEEP)
        shard = os.path.join(REPO_DIR, f"owner_{owner.replace('/', '_')}.json")
        with open(shard, "w", encoding="utf-8") as f:
            json.dump(recs, f, ensure_ascii=False)
        done.add(owner)
        st["owners"] = sorted(done)          # 只维护 owner 状态，旧版 topic 状态自动失效
        with open(state_fp, "w", encoding="utf-8") as f:
            json.dump(st, f)
        log(f"  [{i}/{total}] {owner}: +{len(recs)} 仓库")
    # 汇总去重（只认 owner_ 分片）
    out, seen = [], set()
    for fn in sorted(os.listdir(REPO_DIR)):
        if not fn.startswith("owner_"):
            continue
        try:
            with open(os.path.join(REPO_DIR, fn), "r", encoding="utf-8") as f:
                arr = json.load(f)
        except (ValueError, OSError):
            continue
        for rec in arr:
            if rec["id"] not in seen:
                seen.add(rec["id"])
                out.append(rec)
    out.sort(key=lambda r: -(r.get("stars") or 0))
    with open(REPO_OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
    log(f"仓库条目合计：{len(out)}（写入 {REPO_OUT}，{os.path.getsize(REPO_OUT) >> 20} MB）")
    return out


def main():
    t0 = time.time()
    if "--repos-only" not in sys.argv:
        harvest_ghsa()
    if "--ghsa-only" not in sys.argv:
        harvest_repos()
    log(f"全部完成，耗时 {round(time.time()-t0)}s")


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    main()
