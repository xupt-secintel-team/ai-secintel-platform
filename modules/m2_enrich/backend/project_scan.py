# -*- coding: utf-8 -*-
"""project_scan.py —— 项目成分扫描（SCA，Software Composition Analysis）
================================================================
为什么做（2026-10-08 用户需求）：情报系统此前只接受"资产清单文件"
（asset_scan 的 docx/xlsx/txt），但**真实项目的组件清单是结构化的**——
requirements.txt / package.json / pom.xml / go.mod。导入一个项目
（zip 或文件夹），自动识别依赖清单 → 解析组件+版本 → 匹配本地情报库
CVE（复用 asset_scan 的 AssetRiskScanner，同一套 CPE 版本区间判定）
→ 出 CMDB 风格的风险评估报告。

支持的清单（第一版，按生态覆盖主流）：
  Python     requirements*.txt / pyproject.toml（poetry/pep621 简版）
  Node.js    package.json / package-lock.json（锁版本精确）
  Java       pom.xml（Maven）/ build.gradle（简版）
  Go         go.mod
  .NET       *.csproj（PackageReference）
  PHP        composer.json
  Ruby       Gemfile / Gemfile.lock

zip 安全（每个解压的 zip 都可能恶意）：
  - 条目数 cap 5000、累计解压体积 cap 200MB、单文件 cap 20MB
  - 路径穿越检查（.. / 绝对路径 / 盘符）→ 拒收该条目
  - 只读白名单文件名模式的文本内容，其余文件只计数不读（防 zip bomb）
"""
from __future__ import annotations

import io
import json
import os
import re
import threading
import time
import zipfile
from collections import OrderedDict

try:
    import paths
except Exception:  # pragma: no cover
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    import paths

MAX_ZIP_ENTRIES = 100000                   # 10GB 级真实项目包（node_modules）条目可上万
MAX_ZIP_TOTAL = 10 * 1024 * 1024 * 1024    # 单包上限 10GB（2026-10-08 用户需求，原 200MB）
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_TEXT_BYTES = 2 * 1024 * 1024          # 单个清单文本解析上限
MAX_COMPONENTS = 2000                     # 单项目组件上限
STORE_MAX = 50

# ★ zip 炸弹防御口径（上限放开后重申）：本模块**从不解压落盘**，
#   只按文件名白名单挑出清单文件、逐个读入且单文件 ≤ 20MB ——
#   内存峰值 = 单个清单文件，与包总体积无关。条目数/总体积上限只防
#   "极端畸形包拖垮 infolist 遍历"，真正的边界在白名单 + 单文件 cap。

# 清单文件名匹配（zip 内路径尾部匹配）
_MANIFEST_PATTERNS = [
    re.compile(r"(^|/)requirements[\w.-]*\.txt$", re.I),
    re.compile(r"(^|/)pyproject\.toml$", re.I),
    re.compile(r"(^|/)package\.json$", re.I),
    re.compile(r"(^|/)package-lock\.json$", re.I),
    re.compile(r"(^|/)pom\.xml$", re.I),
    re.compile(r"(^|/)build\.gradle(?:\.kts)?$", re.I),
    re.compile(r"(^|/)go\.mod$", re.I),
    re.compile(r"(^|/)[\w.-]+\.csproj$", re.I),
    re.compile(r"(^|/)composer\.json$", re.I),
    re.compile(r"(^|/)Gemfile(?:\.lock)?$", re.I),
]

_VER_SPLIT = re.compile(r"[<>=!~^,\s]+")


# ════════════════════════════════════════════════════════════════
# 一、清单解析器（每类返回 [(name, version, extra)]）
# ════════════════════════════════════════════════════════════════

def _clean_ver(v: str) -> str:
    """从版本表达式提取裸版本：'>=1.2.3' → '1.2.3'；'^1.2.3' → '1.2.3'。"""
    v = str(v or "").strip().strip('"\'')
    if not v:
        return ""
    parts = [p for p in _VER_SPLIT.split(v) if p]
    for p in parts:
        if re.match(r"^\d+(\.\d+)*", p):
            m = re.match(r"(\d+(?:\.\d+)*(?:[.\-][\w.]+)?)", p)
            if m:
                return m.group(1)
    return parts[0] if parts else ""


def _is_noise(name: str) -> bool:
    """明显的非运行时依赖名（版本号占位/注释残留）。"""
    return not name or name.startswith(("#", "//", "$")) or len(name) > 120


def parse_requirements(text: str):
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith(("#", "-")):
            continue
        # pkg==1.2.3 / pkg>=1.0 / pkg~=1.2 / pkg (>=1.0)
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:\[.*?\])?\s*(.*)$", ln)
        if not m:
            continue
        name = m.group(1)
        ver = _clean_ver(m.group(2))
        if _is_noise(name):
            continue
        out.append((name, ver, "requirements"))
    return out


def parse_pyproject(text: str):
    out = []
    # poetry：[tool.poetry.dependencies] 段下的 name = "^1.2"
    # pep621：dependencies = ["pkg>=1.2", ...]
    m = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.S | re.M)
    if m:
        for item in re.findall(r'"([^"]+)"', m.group(1)):
            pm = re.match(r"^([A-Za-z0-9_.-]+)\s*(.*)$", item.strip())
            if pm and not _is_noise(pm.group(1)):
                out.append((pm.group(1), _clean_ver(pm.group(2)), "pyproject"))
    sec = re.search(r"\[tool\.poetry\.dependencies\](.*?)(?:\n\[|\Z)", text, re.S)
    if sec:
        for ln in sec.group(1).splitlines():
            pm = re.match(r'^\s*([A-Za-z0-9_.-]+)\s*=\s*"([^"]+)"', ln)
            if pm and not _is_noise(pm.group(1)) and pm.group(1).lower() != "python":
                out.append((pm.group(1), _clean_ver(pm.group(2)), "pyproject(poetry)"))
    return out


def parse_package_json(text: str):
    try:
        d = json.loads(text)
    except ValueError:
        return []
    out = []
    for sect in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = d.get(sect)
        if isinstance(deps, dict):
            for name, ver in deps.items():
                if _is_noise(str(name)):
                    continue
                out.append((str(name), _clean_ver(str(ver)), sect))
    return out


def parse_package_lock(text: str):
    """package-lock.json：packages/*/dependencies 树 → 精确 resolved 版本。"""
    try:
        d = json.loads(text)
    except ValueError:
        return []
    out = []
    pkgs = d.get("packages") if isinstance(d.get("packages"), dict) else None
    if pkgs is not None:                      # lock v2/v3
        for path, info in pkgs.items():
            if not path or not isinstance(info, dict):
                continue                      # 根包 "" 跳过
            name, ver = info.get("name") or path.split("node_modules/")[-1], info.get("version")
            if name and ver:
                out.append((str(name), str(ver), "package-lock"))
    else:                                     # lock v1：扁平 dependencies
        deps = d.get("dependencies")
        if isinstance(deps, dict):
            for name, info in deps.items():
                ver = info.get("version") if isinstance(info, dict) else None
                if name and ver:
                    out.append((str(name), str(ver), "package-lock"))
    return out


def parse_pom(text: str):
    out = []
    for blk in re.findall(r"<dependency>(.*?)</dependency>", text, re.S):
        g = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", blk)
        a = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", blk)
        v = re.search(r"<version>\s*([^<]+?)\s*</version>", blk)
        if a:
            name = "%s:%s" % (g.group(1).strip() if g else "?", a.group(1).strip())
            ver = v.group(1).strip() if v else ""
            if "${" in ver:                   # 属性占位符 → 留空（unknown 版本，低置信匹配）
                ver = ""
            out.append((name, ver, "pom.xml"))
    return out


def parse_gradle(text: str):
    out = []
    for m in re.finditer(
            r"(?:implementation|api|compile|runtimeOnly|testImplementation)\s+"
            r"[\"']([^:\"']+):([^:\"']+):([^\"']+)[\"']", text):
        out.append(("%s:%s" % (m.group(1), m.group(2)), m.group(3), "gradle"))
    return out


def parse_go_mod(text: str):
    out = []
    in_block = False
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s.startswith(")"):
            in_block = False
            continue
        m = re.match(r"([\w./-]+)\s+(v[\w.\-+]+)", s)
        if m and not s.startswith("//"):
            out.append((m.group(1), m.group(2).lstrip("v"), "go.mod"))
    return out


def parse_csproj(text: str):
    out = []
    for m in re.finditer(
            r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]*)"', text):
        out.append((m.group(1), _clean_ver(m.group(2)), "csproj"))
    return out


def parse_composer(text: str):
    try:
        d = json.loads(text)
    except ValueError:
        return []
    out = []
    for sect in ("require", "require-dev"):
        deps = d.get(sect)
        if isinstance(deps, dict):
            for name, ver in deps.items():
                if name in ("php", "ext-json") or _is_noise(str(name)):
                    continue
                out.append((str(name), _clean_ver(str(ver)), sect))
    return out


def parse_gemfile(text: str):
    out = []
    for m in re.finditer(r"^\s*gem\s+[\"']([^\"']+)[\"'](?:\s*,\s*[\"']([^\"']+)[\"'])?", text, re.M):
        out.append((m.group(1), m.group(2) or "", "Gemfile"))
    return out


_PARSERS = [
    ("requirements", re.compile(r"(^|/)requirements[\w.-]*\.txt$", re.I), parse_requirements),
    ("pyproject", re.compile(r"(^|/)pyproject\.toml$", re.I), parse_pyproject),
    ("package.json", re.compile(r"(^|/)package\.json$", re.I), parse_package_json),
    ("package-lock.json", re.compile(r"(^|/)package-lock\.json$", re.I), parse_package_lock),
    ("pom.xml", re.compile(r"(^|/)pom\.xml$", re.I), parse_pom),
    ("build.gradle", re.compile(r"(^|/)build\.gradle(?:\.kts)?$", re.I), parse_gradle),
    ("go.mod", re.compile(r"(^|/)go\.mod$", re.I), parse_go_mod),
    ("csproj", re.compile(r"(^|/)[\w.-]+\.csproj$", re.I), parse_csproj),
    ("composer.json", re.compile(r"(^|/)composer\.json$", re.I), parse_composer),
    ("Gemfile", re.compile(r"(^|/)Gemfile\.lock$", re.I), parse_gemfile),
    ("Gemfile", re.compile(r"(^|/)Gemfile$", re.I), parse_gemfile),
]


def _zip_safe(name: str) -> bool:
    """zip 路径安全：拒绝对路径/盘符/绝对路径。"""
    n = name.replace("\\", "/")
    if n.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", n):
        return False
    return ".." not in n.split("/")


def _parse_zipobj(zf: zipfile.ZipFile, source_name: str = "") -> dict:
    """解析一个已打开的 zip 对象（parse_zip / parse_zip_path 共用循环）。

    只读白名单清单文件、单文件 ≤ MAX_FILE_BYTES —— 内存峰值与包总体积无关，
    这是 10GB 上限能安全放开的根本前提。
    """
    comps = OrderedDict()      # key=(canon_name, version) → 记录（同名同版去重，来源合并）
    manifests = []             # [{file, kind, count}]
    warnings = []
    files_seen = 0
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        return {"error": "zip 条目数 %d 超上限 %d" % (len(infos), MAX_ZIP_ENTRIES)}
    total_unc = sum(i.file_size for i in infos)
    if total_unc > MAX_ZIP_TOTAL:
        return {"error": "zip 解压总体积 %.2fGB 超上限 %dGB（防 zip bomb）"
                         % (total_unc / 1073741824.0, MAX_ZIP_TOTAL // 1073741824)}
    for info in infos:
        if info.is_dir():
            continue
        files_seen += 1
        name = info.filename
        if not _zip_safe(name):
            warnings.append("跳过不安全路径：%s" % name[:80])
            continue
        hit = None
        for kind, pat, fn in _PARSERS:
            if pat.search(name):
                hit = (kind, fn)
                break
        if not hit:
            continue
        if info.file_size > MAX_FILE_BYTES:
            warnings.append("跳过超大文件：%s（%.1fMB）" % (name, info.file_size / 1048576))
            continue
        try:
            raw = zf.read(info)
        except Exception as e:  # noqa: BLE001
            warnings.append("读取失败 %s: %s" % (name[:60], str(e)[:60]))
            continue
        try:
            text = raw[:MAX_TEXT_BYTES].decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            continue
        del raw                                   # 大清单读完立刻释放
        kind, fn = hit
        try:
            items = fn(text)
        except Exception as e:  # noqa: BLE001
            warnings.append("解析失败 %s: %s" % (name[:60], str(e)[:80]))
            items = []
        for cname, ver, extra in items:
            key = (cname.lower(), ver or "")
            ent = comps.get(key)
            if ent is None:
                comps[key] = {"name": cname, "version": ver or "",
                              "ecosystem": kind, "sources": [name],
                              "evidence": extra}
            else:
                if name not in ent["sources"]:
                    ent["sources"].append(name)
        manifests.append({"file": name, "kind": kind, "count": len(items)})
        if len(comps) >= MAX_COMPONENTS:
            warnings.append("组件数达上限 %d，其余截断" % MAX_COMPONENTS)
            break
    return {"components": list(comps.values()), "manifests": manifests,
            "files": files_seen, "warnings": warnings}


def parse_zip(data: bytes, filename: str = "") -> dict:
    """zip 字节 → 清单解析（小包内存路径；大包请走 parse_zip_path）。"""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return {"error": "不是有效的 zip 文件（或已损坏）"}
    return _parse_zipobj(zf, filename)


def parse_zip_path(fp: str) -> dict:
    """磁盘 zip 文件 → 清单解析（10GB 级大包路径：字节不整体进内存）。

    zipfile 按条目惰性读取，这里只把白名单清单文件读进内存（单文件
    ≤ 20MB），其余条目只扫 infolist 元数据。zip64 大包 Python 原生支持。
    """
    try:
        with open(fp, "rb") as f:
            with zipfile.ZipFile(f) as zf:
                return _parse_zipobj(zf, os.path.basename(fp))
    except zipfile.BadZipFile:
        return {"error": "不是有效的 zip 文件（或已损坏）"}
    except OSError as e:
        return {"error": "zip 文件读取失败：%s" % str(e)[:120]}


def parse_multi_text(files: list) -> dict:
    """文件夹多选上传：[{path, content}]（前端已只筛清单文件）。"""
    comps = OrderedDict()
    manifests = []
    warnings = []
    for f in files[:200]:
        path = str(f.get("path") or f.get("name") or "file")
        text = str(f.get("content") or "")[:MAX_TEXT_BYTES]
        for kind, pat, fn in _PARSERS:
            if pat.search(path):
                try:
                    items = fn(text)
                except Exception as e:  # noqa: BLE001
                    warnings.append("解析失败 %s: %s" % (path[:60], str(e)[:80]))
                    items = []
                for cname, ver, extra in items:
                    key = (cname.lower(), ver or "")
                    ent = comps.get(key)
                    if ent is None:
                        comps[key] = {"name": cname, "version": ver or "",
                                      "ecosystem": kind, "sources": [path],
                                      "evidence": extra}
                    elif path not in ent["sources"]:
                        ent["sources"].append(path)
                manifests.append({"file": path, "kind": kind, "count": len(items)})
                break
    return {"components": list(comps.values()), "manifests": manifests,
            "files": len(files), "warnings": warnings}


# ════════════════════════════════════════════════════════════════
# 二、CVE 匹配（复用 asset_scan 的扫描器——同一套 CPE 区间判定）
# ════════════════════════════════════════════════════════════════

def scan_components(engine, components: list) -> dict:
    """组件 → 命中 CVE（复用 AssetRiskScanner.match，含版本区间判定）。"""
    from asset_scan import AssetRiskScanner, _risk_of
    sc = AssetRiskScanner(engine)
    results = []
    for c in components[:MAX_COMPONENTS]:
        # Maven/Gradle 的 "group:artifact" 拿 artifact 部分去匹配 CPE
        name = c["name"]
        if ":" in name:
            name = name.split(":")[-1]
        fs = sc.match({"name": name, "version": c.get("version") or ""})
        level, kev, cnt = _risk_of(fs, bool(c.get("version")))
        item = dict(c)
        item.update({"risk_level": level, "kev_count": kev, "cve_count": cnt,
                     "findings": fs, "top": fs[0]["id"] if fs else "",
                     "max_score": max([f.get("score") or 0 for f in fs], default=0)})
        results.append(item)
    order = {"严重": 4, "高": 3, "中": 2, "低": 1, "无已知风险": 0, "待确认": 0}
    results.sort(key=lambda p: (order.get(p["risk_level"], 0),
                                p["kev_count"], p["max_score"]), reverse=True)
    all_f = [f for x in results for f in x["findings"]]
    kev_ids = [f["id"] for f in all_f if f["exploited"]]
    return {
        "components": results,
        "summary": {
            "components": len(results),
            "with_version": sum(1 for c in results if c.get("version")),
            "cve_hits": len({f["id"] for f in all_f}),
            "critical": len({f["id"] for f in all_f if f["severity"] == "CRITICAL"}),
            "high": len({f["id"] for f in all_f if f["severity"] == "HIGH"}),
            "exploited": len(set(kev_ids)),
            "kev_ids": sorted(set(kev_ids))[:20],
            "risk_components": sum(1 for c in results if c["risk_level"] in ("严重", "高")),
            "scanned_docs": len(sc.docs),
        },
    }


# ════════════════════════════════════════════════════════════════
# 三、报告构建 / 持久化 / 导出（CMDB 风格）
# ════════════════════════════════════════════════════════════════

def _new_id() -> str:
    return "PROJ-%s-%s" % (time.strftime("%Y%m%d%H%M%S"),
                            os.urandom(2).hex())


def build_report(source_name: str, data: bytes, engine,
                 files: list = None, persist: bool = True,
                 path: str = None) -> dict:
    """入口：zip 字节 / 磁盘 zip 路径 / 多文本文件列表 → 解析 → 匹配 → 报告 dict。

    path 优先于 data（10GB 大包走磁盘流式，见 parse_zip_path）。
    """
    if files is not None:
        parsed = parse_multi_text(files)
        source_kind = "文件夹（多文件）"
    elif path:
        parsed = parse_zip_path(path)
        source_kind = "zip 压缩包（大包磁盘流式）"
    else:
        parsed = parse_zip(data or b"", source_name)
        source_kind = "zip 压缩包"
    if parsed.get("error"):
        return {"ok": False, "error": parsed["error"]}
    comps = parsed.get("components") or []
    if not comps:
        return {"ok": False,
                "error": "未在项目中识别到任何依赖清单（支持 requirements.txt / "
                         "package.json / pom.xml / go.mod / build.gradle / *.csproj / "
                         "composer.json / Gemfile / pyproject.toml）",
                "manifests": parsed.get("manifests") or [],
                "files": parsed.get("files") or 0}
    matched = scan_components(engine, comps)
    rep = {
        "ok": True,
        "id": _new_id(),
        "source": source_name,
        "source_kind": source_kind,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "manifests": parsed.get("manifests") or [],
        "files_scanned": parsed.get("files") or 0,
        "warnings": parsed.get("warnings") or [],
        **matched,
    }
    if persist:
        _save_report(rep)
    return rep


def _store_fp():
    return os.path.join(paths.DATA_DIR, "project_scans.json")


_STORE_LOCK = threading.Lock()     # 模块级锁：并发保存报告/索引互斥


def _load_store():
    fp = _store_fp()
    if not os.path.isfile(fp):
        return []
    try:
        with open(fp, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def _save_store(items):
    fp = _store_fp()
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    tmp = "%s.%d.tmp" % (fp, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(items[:STORE_MAX], f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, fp)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _report_fp(scan_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9\-]", "", scan_id or "")[:40]
    return os.path.join(paths.DATA_DIR, "project_scan_reports", safe + ".json")


def _save_report(rep: dict) -> None:
    fp = _report_fp(rep.get("id") or "")
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    tmp = "%s.%d.tmp" % (fp, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, fp)
        with _STORE_LOCK:
            items = _load_store()
            items.insert(0, {
                "id": rep["id"], "source": rep.get("source"),
                "source_kind": rep.get("source_kind"), "ts": rep.get("ts"),
                "components": rep.get("summary", {}).get("components"),
                "cve_hits": rep.get("summary", {}).get("cve_hits"),
                "critical": rep.get("summary", {}).get("critical"),
                "high": rep.get("summary", {}).get("high"),
                "exploited": rep.get("summary", {}).get("exploited"),
                "manifests": len(rep.get("manifests") or []),
            })
            _save_store(items)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


def load_report(scan_id: str):
    fp = _report_fp(scan_id)
    if not os.path.isfile(fp):
        return None
    try:
        with open(fp, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def list_scans():
    return _load_store()


def clear_scans() -> int:
    n = len(_load_store())
    for it in _load_store():
        try:
            os.remove(_report_fp(it.get("id") or ""))
        except OSError:
            pass
    try:
        os.remove(_store_fp())
    except OSError:
        pass
    return n


def report_to_markdown(rep: dict) -> str:
    """CMDB 风格七章制报告（对齐 评审已认可的 CMDB 资产风险分析报告 版式）。"""
    s = rep.get("summary") or {}
    L = []
    L.append("# 项目成分安全评估报告（SCA）")
    L.append("")
    L.append("- **报告编号**：%s" % rep.get("id"))
    L.append("- **被检项目**：%s（%s）" % (rep.get("source"), rep.get("source_kind")))
    L.append("- **生成时间**：%s" % rep.get("ts"))
    L.append("- **数据口径**：项目依赖清单 × 本地情报库 CPE 版本区间交叉验证")
    L.append("- **判定依据**：模块 1 情报库（NVD CPE 版本区间 / CISA KEV / CVSS / "
             "官方补丁 / 处置建议），参与比对情报 %s 条" % s.get("scanned_docs", 0))
    L.append("- **方法声明**：离线匹配、不联网、不外发；仅识别依赖清单中的组件与版本，"
             "不做代码审计（SAST 不在范围）")
    L.append("- **保密等级**：内部秘密（Internal Confidential）")
    L.append("")
    L.append("## 一、检测范围")
    L.append("")
    L.append("| 项 | 内容 |")
    L.append("|---|---|")
    L.append("| 项目来源 | %s |" % rep.get("source"))
    L.append("| 解析文件数 | %d |" % (rep.get("files_scanned") or 0))
    L.append("| 识别到的清单 | %d 份（%s） |"
             % (len(rep.get("manifests") or []),
                "、".join(sorted({m.get("kind") or "?" for m in rep.get("manifests") or []})) or "—"))
    L.append("| 组件总数 | %d（%d 个带精确版本） |"
             % (s.get("components", 0), s.get("with_version", 0)))
    L.append("")
    if rep.get("warnings"):
        L.append("> ⚠ 解析告警（不阻断报告）：%s"
                 % "；".join(str(w) for w in rep["warnings"][:6]))
        L.append("")
    L.append("## 二、执行摘要")
    L.append("")
    crit, high, expl = s.get("critical", 0), s.get("high", 0), s.get("exploited", 0)
    level = "高风险" if (crit or expl) else ("中风险" if high else ("低风险" if s.get("cve_hits") else "未发现已知风险"))
    L.append("> **整体风险等级：%s**。" % level)
    L.append("")
    L.append("- 命中 CVE：%d 个（CRITICAL %d / HIGH %d）"
             % (s.get("cve_hits", 0), crit, high))
    if s.get("kev_ids"):
        L.append("- **其中 %d 个在 CISA KEV 在野利用清单：%s**"
                 % (expl, "、".join(s["kev_ids"][:8])))
    L.append("- 风险组件（严重/高）：%d / %d" % (s.get("risk_components", 0),
                                                 s.get("components", 0)))
    L.append("")
    L.append("## 三、组件风险明细（按风险降序，TOP 50）")
    L.append("")
    risky = [c for c in rep.get("components") or [] if c.get("cve_count")]
    if risky:
        L.append("| # | 组件 | 版本 | 生态 | 风险 | CVE 数 | 最高 CVSS | KEV | 最高风险编号 |")
        L.append("|---|---|---|---|---|---:|---:|:--:|---|")
        for i, c in enumerate(risky[:50], 1):
            L.append("| %d | %s | %s | %s | **%s** | %d | %s | %s | %s |"
                     % (i, c["name"], c.get("version") or "未提供",
                        c.get("ecosystem") or "-", c["risk_level"], c["cve_count"],
                        c.get("max_score") or "—",
                        "⚠ %d" % c["kev_count"] if c["kev_count"] else "",
                        c.get("top") or "—"))
        if len(risky) > 50:
            L.append("")
            L.append("> 另有 %d 个风险组件未列出（JSON 版可看全部）。" % (len(risky) - 50))
    else:
        L.append("所有组件均未命中已知 CVE。")
    L.append("")
    L.append("## 四、处置建议（按 SLA）")
    L.append("")
    n = 0
    for c in risky:
        for f in (c.get("findings") or [])[:3]:
            if f["severity"] not in ("CRITICAL", "HIGH"):
                continue
            n += 1
            acts = []
            if f.get("exploited"):
                acts.append("**已在野利用（KEV %s）**，按应急预案立即处置"
                            % (f.get("kev_added") or ""))
            if (f.get("score") or 0) >= 9:
                acts.append("CVSS %.1f，建议 7 天内完成修复" % f["score"])
            elif (f.get("score") or 0) >= 7:
                acts.append("CVSS %.1f，建议 30 天内纳入版本迭代" % f["score"])
            if f.get("remediation"):
                acts.append(str(f["remediation"][0])[:120])
            if not acts:
                acts.append("列入跟踪")
            L.append("%d. [%s][%s %s] %s —— %s"
                     % (n, f["id"], c["name"], c.get("version") or "?",
                        f["severity"], "；".join(acts)))
            if n >= 30:
                break
        if n >= 30:
            L.append("")
            L.append("> 仅列前 30 条，其余见 JSON 明细。")
            break
    if not n:
        L.append("无严重/高危条目，按常规节奏跟踪组件升级即可。")
    L.append("")
    L.append("## 五、口径与边界（不做的就不声称）")
    L.append("")
    L.append("- 匹配置信度：组件带精确版本=「高」（CPE 区间判定）；无版本=「低」"
             "（产品级全区间评估，**需人工确认版本后再派单**）。")
    L.append("- 不在范围：代码级漏洞（SAST）、传递依赖的间接解析"
             "（仅 package-lock.json/Gemfile.lock 提供锁定树）、许可证合规、"
             "运行环境实际部署验证。")
    L.append("- 未在情报库登记的组件漏洞无法命中（漏报可能存在；"
             "情报库规模见「判定依据」）。")
    if rep.get("manifests"):
        L.append("- 识别清单明细：%s"
                 % "；".join("%s(%d 项)" % (m["file"].split("/")[-1], m["count"])
                             for m in rep["manifests"][:10]))
    L.append("")
    return "\n".join(L)
