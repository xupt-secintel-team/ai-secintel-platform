# -*- coding: utf-8 -*-
"""
affected_assets.py —— 受影响资产定位模块
==========================================
输入漏洞描述文本 + CVE 编号，输出受影响资产列表（厂商 / 产品 / 受影响版本 /
不受影响版本 / CPE / 置信度 / 提取方式）。

实现策略：三路并行提取后合并
  1. NVD API（最权威，优先级最高）：按 CVE 请求
     ``https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=XXX``，
     解析 configurations.nodes 提取 CPE 与版本范围，置信度 high 直接采用；
  2. LLM 信息抽取：复用项目已有 DeepSeek 配置（poc_scraper.load_config），
     System prompt 设定为网络安全分析师，严格输出 JSON，附 2 组 few-shot；
  3. CPE 字典匹配：若 data/cpe_dictionary.json 存在则按产品名模糊匹配，否则跳过。

合并逻辑：NVD > LLM > CPE，按 vendor+product 去重；NVD 已有者优先采用，仅 NVD
缺失的才用 LLM（标 medium）/CPE（标 low）；三路均无结果返回空列表。

同一 CVE 的结果缓存到 data/affected_assets_cache.json，避免重复调用（尤其 LLM）。

统一入口：``extract_affected_assets(cve_id, description) -> List[AffectedAsset]``。

本模块纯增量：只 import 既有 poc_scraper.load_config / DEFAULT_UA，不改动任何现有代码。
"""

from __future__ import annotations

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

# —— 模块化结构：数据目录统一由 core/paths.py 解析（本文件可独立运行）——
# 注意：这段 sys.path 引导必须排在 `import requests` 之前 —— 否则没装 requests 时
# 无法 import core/httpcompat.py 做降级，会直接 ModuleNotFoundError 把接口打挂。
import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import paths  # noqa: E402

try:  # 依赖降级：装了 requests 用 requests，没装就用标准库实现（core/httpcompat.py）
    import requests
except ImportError:  # pragma: no cover - 取决于运行环境
    import httpcompat as requests  # noqa: F401  （API 子集兼容，见 core/httpcompat.py）

# 复用项目已有的 DeepSeek 配置加载（不重写客户端配置）
from poc_scraper import DEFAULT_UA, load_config  # noqa: E402
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass


logger = logging.getLogger("affected_assets")
logger.addHandler(logging.NullHandler())

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = paths.DATA_DIR
CACHE_PATH = os.path.join(DATA_DIR, "affected_assets_cache.json")
CPE_DICT_PATH = os.path.join(DATA_DIR, "cpe_dictionary.json")

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 置信度 / 提取方式枚举
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

METHOD_NVD = "nvd_api"
METHOD_LLM = "llm_extract"
METHOD_CPE = "cpe_match"


# ==========================================================================
# 数据模型
# ==========================================================================
@dataclass
class AffectedAsset:
    """单条受影响资产。"""

    vendor: str                             # 厂商（小写规范名）
    product: str                            # 产品（小写规范名）
    affected_versions: List[str] = field(default_factory=list)    # 受影响版本/区间
    unaffected_versions: List[str] = field(default_factory=list)  # 不受影响版本
    cpe: str = ""                           # CPE 2.3 标识
    confidence: str = CONFIDENCE_LOW        # high / medium / low
    extraction_method: str = METHOD_LLM     # nvd_api / llm_extract / cpe_match

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _asset_from_dict(d: object) -> Optional[AffectedAsset]:
    if not isinstance(d, dict):
        return None
    return AffectedAsset(
        vendor=str(d.get("vendor", "") or ""),
        product=str(d.get("product", "") or ""),
        affected_versions=list(d.get("affected_versions") or []),
        unaffected_versions=list(d.get("unaffected_versions") or []),
        cpe=str(d.get("cpe", "") or ""),
        confidence=str(d.get("confidence", CONFIDENCE_LOW) or CONFIDENCE_LOW),
        extraction_method=str(d.get("extraction_method", METHOD_LLM) or METHOD_LLM),
    )


# ==========================================================================
# 工具函数
# ==========================================================================
def _kw_match(text: str, word: str) -> bool:
    """关键词命中：ASCII 用词边界，非 ASCII 用子串（与 poc_scraper 语义一致）。"""
    word = (word or "").strip().lower()
    if not word or not text:
        return False
    if word.isascii():
        return re.search(rf"\b{re.escape(word)}\b", text) is not None
    return word in text


def _make_cpe(vendor: str, product: str, version: str = "") -> str:
    """用厂商/产品（+可选版本）合成 CPE 2.3 字符串；版本未知用 ``*``。"""
    v = (version or "").strip()
    if v:
        # 取区间起点作为 CPE 版本（如 "2.0 - <2.12.2" -> "2.0"）
        v = re.split(r"\s*[-<>=]\s*", v, maxsplit=1)[0].strip()
    v = re.sub(r"[^A-Za-z0-9._-]", "", v) or "*"
    return f"cpe:2.3:a:{vendor}:{product}:{v}:*:*:*:*:*:*:*"


def _parse_json_tolerant(text: str) -> Optional[object]:
    """容错 JSON 解析：剥离 ```json 包裹 / 多余字符 / 取首个 {} 块。"""
    if not text:
        return None
    t = text.strip()
    # 剥离 Markdown 代码块围栏（```json ... ```）
    t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    # 截取第一个 { 到最后一个 } 之间的内容
    s, e = t.find("{"), t.rfind("}")
    if s != -1 and e != -1 and e > s:
        t = t[s:e + 1]
    try:
        return json.loads(t)
    except ValueError:
        # 兜底：尝试修复常见的尾随逗号 / 单引号
        try:
            t2 = re.sub(r",\s*([}\]])", r"\1", t)
            return json.loads(t2)
        except ValueError:
            return None


# ==========================================================================
# 主类
# ==========================================================================
class AffectedAssetExtractor:
    """受影响资产提取器：NVD API / LLM 抽取 / CPE 字典匹配三路并行 + 合并。"""

    _SYSTEM_PROMPT = (
        "你是一名资深网络安全分析师，负责从漏洞描述文本中提取「受影响资产」"
        "（厂商 vendor、产品 product、受影响版本 affected_versions、不受影响版本 "
        "unaffected_versions）。\n\n"
        "规则：\n"
        "1. 严格只输出 JSON，不要任何解释文字，不要 Markdown 代码块。\n"
        '2. 输出结构固定为：{"assets": [{"vendor": "...", "product": "...", '
        '"affected_versions": ["..."], "unaffected_versions": ["..."]}]}\n'
        "3. 厂商与产品名使用英文小写规范命名（如 apache、log4j、microsoft）。\n"
        '4. 版本用字符串数组表示，如 ["2.0 - 2.12.1"]；描述未明确给出版本时置空数组 '
        "[]，严禁臆造。\n"
        '5. 无法识别任何受影响资产时输出 {"assets": []}。\n\n'
        "示例 1：\n"
        "输入：Apache Log4j2 versions 2.0-beta9 through 2.12.1 and 2.13.0 through "
        "2.14.1 are vulnerable to remote code execution via JNDI. Versions 2.12.2, "
        "2.16.0 and later are not affected.\n"
        '输出：{"assets": [{"vendor": "apache", "product": "log4j", '
        '"affected_versions": ["2.0-beta9 - 2.12.1", "2.13.0 - 2.14.1"], '
        '"unaffected_versions": ["2.12.2", "2.16.0"]}]}\n\n'
        "示例 2：\n"
        "输入：An unspecified flaw in a network device allows remote attackers to "
        "execute arbitrary code.\n"
        '输出：{"assets": []}'
    )

    def __init__(self, config: Optional[Dict[str, object]] = None,
                 cache_path: str = CACHE_PATH) -> None:
        self.config = config if config is not None else load_config()
        self.timeout = int(self.config.get("timeout", 15) or 15)
        verify_ssl = bool(self.config.get("verify_ssl", True))
        # 复用项目已有 DeepSeek 客户端配置（不重写）
        self.llm_api_key = str(
            self.config.get("deepseek_api_key", "") or os.environ.get("DEEPSEEK_API_KEY", "") or ""
        ).strip()
        self.llm_base_url = str(
            self.config.get("deepseek_base_url", "")
            or os.environ.get("DEEPSEEK_BASE_URL", "")
            or "https://api.deepseek.com"
        ).rstrip("/")
        self.llm_model = str(self.config.get("deepseek_model", "deepseek-chat") or "deepseek-chat")
        self.cache_path = cache_path

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_UA})
        self.session.verify = verify_ssl
        if not verify_ssl:
            try:  # 仅为关掉告警，缺失不影响功能（requests 会自带 urllib3）
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError as _sw_e:
                _swallow("modules/m2_enrich/backend/affected_assets.py:209", _sw_e)

        self._cache: Dict[str, List[Dict[str, object]]] = self._load_cache()

    # ------------------------------------------------------------------
    # 缓存
    # ------------------------------------------------------------------
    def _load_cache(self) -> Dict[str, List[Dict[str, object]]]:
        if not os.path.isfile(self.cache_path):
            return {}
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError) as e:  # noqa: BLE001
            logger.warning("资产缓存读取失败: %s", e)
            return {}

    def _save_cache(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, ensure_ascii=False, indent=1)
        except OSError as e:  # noqa: BLE001
            logger.warning("资产缓存写入失败: %s", e)

    # ------------------------------------------------------------------
    # 统一入口
    # ------------------------------------------------------------------
    def extract(self, cve_id: str, description: str,
                record: Optional[Dict] = None) -> List[AffectedAsset]:
        """三路并行提取 + 合并；命中缓存直接返回。

        ``record`` 为语料里的完整条目（可选）。当三路均无结果、或缓存里是空结果时，
        用 record 自带的 CPE 做「语料回退」——语料里的 CPE 本就是采集期从 NVD 落库的，
        弱网 / NVD 匿名限流 / 该 CVE 尚未被在线 API 覆盖时，仍能给出受影响资产。
        """
        cve_id = (cve_id or "").strip().upper()
        if not cve_id:
            return []
        cached = self._cache.get(cve_id)
        if cached is not None:
            assets = [a for a in (_asset_from_dict(d) for d in cached) if a]
            if not assets and record:
                assets = self._corpus_extract(record)
            logger.info("命中缓存 %s（%d 条资产）", cve_id, len(assets))
            return assets

        _w = 3
        try:                   # 性能档位：低配机器上并发压到 2
            from envprofile import T
            _w = T.workers(3)
        except Exception:
            pass
        with ThreadPoolExecutor(max_workers=_w) as ex:
            f_nvd = ex.submit(self._nvd_extract, cve_id)
            f_llm = ex.submit(self._llm_extract, cve_id, description)
            f_cpe = ex.submit(self._cpe_match, description)
            nvd = f_nvd.result() or []
            llm = f_llm.result() or []
            cpe = f_cpe.result() or []

        merged = self._merge(nvd, llm, cpe)
        if not merged and record:
            merged = self._corpus_extract(record)
        self._cache[cve_id] = [a.to_dict() for a in merged]
        self._save_cache()
        logger.info("%s 提取受影响资产 %d 条（nvd=%d llm=%d cpe=%d）",
                    cve_id, len(merged), len(nvd), len(llm), len(cpe))
        return merged

    @staticmethod
    def _corpus_extract(record: Optional[Dict]) -> List[AffectedAsset]:
        """语料回退：从 record 的 CPE 结构（vendor/product/version）重建资产。"""
        if not isinstance(record, dict):
            return []
        out: List[AffectedAsset] = []
        seen = set()
        for c in (record.get("cpe") or []):
            if not isinstance(c, dict):
                continue
            vendor = str(c.get("vendor") or "").strip().lower()
            product = str(c.get("product") or "").strip().lower()
            if not vendor or not product:
                continue
            key = (vendor, product)
            if key in seen:
                continue
            seen.add(key)
            ver = str(c.get("version") or "").strip()
            vr = ""
            si, se = c.get("start_incl"), c.get("start_excl")
            ei, ee = c.get("end_incl"), c.get("end_excl")
            start = si if si else ((">" + str(se)) if se else "")
            end = ei if ei else (("<" + str(ee)) if ee else "")
            vr = " - ".join(x for x in (start, end) if x)
            if not vr and ver and ver not in ("*", "-"):
                vr = ver
            asset = AffectedAsset(
                vendor=vendor, product=product,
                affected_versions=[vr] if vr else [],
                cpe="cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*" % (vendor, product,
                                                           re.sub(r"[^A-Za-z0-9._-]", "", ver) or "*"),
                confidence=CONFIDENCE_MEDIUM, extraction_method="corpus_cpe",
            )
            out.append(asset)
        return out

    # ------------------------------------------------------------------
    # 路径 1：NVD API（权威，置信度 high）
    # ------------------------------------------------------------------
    def _nvd_extract(self, cve_id: str) -> List[AffectedAsset]:
        try:
            resp = self.session.get(_NVD_URL, params={"cveId": cve_id},
                                    timeout=self.timeout)
            if resp.status_code != 200:
                logger.warning("NVD 返回 %d", resp.status_code)
                return []
            cve = (resp.json().get("vulnerabilities") or [{}])[0].get("cve", {})
            return self._parse_nvd_cve(cve)
        except Exception as e:  # noqa: BLE001
            logger.warning("NVD 提取失败: %s", e)
            return []

    @staticmethod
    def _version_range(m: Dict[str, object], version: str) -> str:
        """把 cpeMatch 的版本区间拼成可读字符串。"""
        si = m.get("versionStartIncluding")
        se = m.get("versionStartExcluding")
        ei = m.get("versionEndIncluding")
        ee = m.get("versionEndExcluding")
        if not any((si, se, ei, ee)):
            return version if version and version not in ("*", "-") else ""
        start = si or ((">" + str(se)) if se else "")
        end = ei or (("<" + str(ee)) if ee else "")
        if start and end:
            return f"{start} - {end}"
        return str(start or end or version or "")

    @classmethod
    def _parse_nvd_cve(cls, cve: Dict[str, object]) -> List[AffectedAsset]:
        """解析 NVD cve 对象，按 (vendor, product) 归并，区分受影响/不受影响版本。

        与项目既有 ``poc_scraper._fetch_cve_info`` 一致：仅保留「描述中出现的产品」
        作为主资产，过滤掉 AND 节点里捆绑该漏洞组件的大量下游产品（如 log4j 的
        Siemens/Cisco/NetApp 等 100+ 第三方），避免资产列表被噪声淹没；若描述无法
        命中任何产品，则回退返回全部 a 类 CPE。
        """
        desc = ""
        for d in cve.get("descriptions", []) or []:
            if isinstance(d, dict) and d.get("lang") == "en":
                desc = str(d.get("value") or "").lower()
                break

        grouped: Dict[Tuple[str, str], AffectedAsset] = {}
        for cfg in cve.get("configurations", []) or []:
            for node in cfg.get("nodes", []) or []:
                for m in node.get("cpeMatch", []) or []:
                    if not isinstance(m, dict):
                        continue
                    crit = str(m.get("criteria") or "").strip()
                    parts = crit.split(":")
                    # cpe:2.3:a:vendor:product:version:update:edition:lang:sw:tw:th:other
                    if len(parts) < 6 or parts[0] != "cpe" or parts[2] != "a":
                        continue
                    vendor, product, version = parts[3], parts[4], parts[5]
                    if not vendor or not product or product in ("*", "-"):
                        continue
                    key = (vendor.lower(), product.lower())
                    asset = grouped.get(key)
                    if asset is None:
                        asset = AffectedAsset(
                            vendor=vendor, product=product, cpe=crit,
                            confidence=CONFIDENCE_HIGH, extraction_method=METHOD_NVD,
                        )
                        grouped[key] = asset
                    vr = cls._version_range(m, version)
                    if not vr:
                        continue
                    if m.get("vulnerable", True):
                        if vr not in asset.affected_versions:
                            asset.affected_versions.append(vr)
                    else:
                        if vr not in asset.unaffected_versions:
                            asset.unaffected_versions.append(vr)

        assets = list(grouped.values())
        if desc:
            primary = [a for a in assets
                       if a.product.lower() in desc or a.vendor.lower() in desc]
            if primary:
                return primary
        return assets

    # ------------------------------------------------------------------
    # 路径 2：LLM 抽取（复用项目 DeepSeek 配置，置信度 medium）
    # ------------------------------------------------------------------
    def _call_llm(self, system: str, user: str) -> str:
        try:
            resp = self.session.post(
                f"{self.llm_base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.llm_api_key}",
                         "Content-Type": "application/json"},
                json={"model": self.llm_model,
                      "messages": [{"role": "system", "content": system},
                                   {"role": "user", "content": user}],
                      "temperature": 0,
                      "response_format": {"type": "json_object"}},
                timeout=60,
            )
            if resp.status_code != 200:
                logger.warning("LLM 返回 %d: %s", resp.status_code, resp.text[:200])
                return ""
            return str(resp.json()["choices"][0]["message"]["content"])
        except Exception as e:  # noqa: BLE001
            logger.warning("LLM 调用失败: %s", e)
            return ""

    def _llm_extract(self, cve_id: str, description: str) -> List[AffectedAsset]:
        if not self.llm_api_key:
            logger.debug("未配置 DeepSeek API Key，跳过 LLM 抽取")
            return []
        user = f"CVE 编号：{cve_id}\n漏洞描述：\n{description or ''}"
        data = _parse_json_tolerant(self._call_llm(self._SYSTEM_PROMPT, user))
        if not isinstance(data, dict):
            logger.warning("LLM 输出无法解析为 JSON")
            return []
        out: List[AffectedAsset] = []
        for a in data.get("assets") or []:
            if not isinstance(a, dict):
                continue
            vendor = str(a.get("vendor") or "").strip().lower()
            product = str(a.get("product") or "").strip().lower()
            if not vendor or not product:
                continue
            affected = [str(x).strip() for x in (a.get("affected_versions") or []) if str(x).strip()]
            unaffected = [str(x).strip() for x in (a.get("unaffected_versions") or []) if str(x).strip()]
            out.append(AffectedAsset(
                vendor=vendor, product=product,
                affected_versions=affected, unaffected_versions=unaffected,
                cpe=_make_cpe(vendor, product, affected[0] if affected else ""),
                confidence=CONFIDENCE_MEDIUM, extraction_method=METHOD_LLM,
            ))
        return out

    # ------------------------------------------------------------------
    # 路径 3：CPE 字典匹配（无字典则跳过，置信度 low）
    # ------------------------------------------------------------------
    def _cpe_match(self, description: str) -> List[AffectedAsset]:
        if not os.path.isfile(CPE_DICT_PATH):
            logger.debug("未找到 CPE 字典（%s），跳过该路", CPE_DICT_PATH)
            return []
        try:
            with open(CPE_DICT_PATH, "r", encoding="utf-8") as f:
                entries = json.load(f)
        except (OSError, ValueError) as e:  # noqa: BLE001
            logger.warning("CPE 字典读取失败: %s", e)
            return []
        if not isinstance(entries, list):
            return []
        blob = (description or "").lower()
        out: List[AffectedAsset] = []
        for e in entries:
            if not isinstance(e, dict):
                continue
            vendor = str(e.get("vendor") or "").strip()
            product = str(e.get("product") or "").strip()
            if not vendor or not product:
                continue
            if _kw_match(blob, product) or _kw_match(blob, vendor):
                out.append(AffectedAsset(
                    vendor=vendor.lower(), product=product.lower(),
                    cpe=str(e.get("cpe") or "") or _make_cpe(vendor, product),
                    confidence=CONFIDENCE_LOW, extraction_method=METHOD_CPE,
                ))
                if len(out) >= 20:
                    break
        return out

    # ------------------------------------------------------------------
    # 合并：NVD > LLM > CPE，按 (vendor, product) 去重
    # ------------------------------------------------------------------
    @staticmethod
    def _merge(nvd: Sequence[AffectedAsset], llm: Sequence[AffectedAsset],
               cpe: Sequence[AffectedAsset]) -> List[AffectedAsset]:
        merged: Dict[Tuple[str, str], AffectedAsset] = {}
        for a in nvd:  # 权威，直接采用
            merged[(a.vendor.lower(), a.product.lower())] = a
        for a in llm:  # 仅 NVD 缺失者采用（confidence=medium）
            merged.setdefault((a.vendor.lower(), a.product.lower()), a)
        for a in cpe:  # 仅前两路均缺失者采用（confidence=low）
            merged.setdefault((a.vendor.lower(), a.product.lower()), a)
        return list(merged.values())


# ==========================================================================
# 统一入口
# ==========================================================================
def extract_affected_assets(
    cve_id: str,
    description: str,
    config: Optional[Dict[str, object]] = None,
    record: Optional[Dict] = None,
) -> List[AffectedAsset]:
    """统一入口：输入 CVE 编号 + 描述文本，输出受影响资产列表。

    :param cve_id: CVE 编号，如 ``"CVE-2021-44228"``。
    :param description: 漏洞描述文本。
    :param config: 配置字典；缺省从 ``poc_scraper_config.json`` 读取。
    :param record: 语料完整条目（可选），三路无结果时用作语料 CPE 回退。
    :return: 三路提取并去重合并后的受影响资产列表；均无结果时返回空列表。
    """
    return AffectedAssetExtractor(config=config).extract(cve_id, description, record)


# ==========================================================================
# 持久化（SQLite，与项目 save_poc_results_db 同风格）
# ==========================================================================
def save_affected_assets(
    assets: Sequence[AffectedAsset],
    cve_id: str = "",
    db_path: Optional[str] = None,
) -> str:
    """将受影响资产写入 SQLite（标准库 sqlite3，零额外依赖）。

    版本列表以 JSON 字符串落库；``(cve_id, vendor, product)`` 唯一。

    :return: 数据库文件路径。
    """
    import sqlite3

    db_path = db_path or os.path.join(DATA_DIR, "affected_assets.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS affected_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT, vendor TEXT, product TEXT,
                affected_versions TEXT, unaffected_versions TEXT,
                cpe TEXT, confidence TEXT, extraction_method TEXT,
                UNIQUE(cve_id, vendor, product)
            )
            """
        )
        for a in assets:
            conn.execute(
                """
                INSERT OR REPLACE INTO affected_assets
                (cve_id, vendor, product, affected_versions, unaffected_versions,
                 cpe, confidence, extraction_method)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    cve_id, a.vendor, a.product,
                    json.dumps(a.affected_versions, ensure_ascii=False),
                    json.dumps(a.unaffected_versions, ensure_ascii=False),
                    a.cpe, a.confidence, a.extraction_method,
                ),
            )
        conn.commit()
    finally:
        conn.close()
    logger.info("已写入 %d 条受影响资产到 SQLite %s", len(assets), db_path)
    return db_path


# ==========================================================================
# 可选工具：从 nvd_cache.json 一次性构建 CPE 字典（供 cpe_match 路径使用）
# ==========================================================================
def build_cpe_dictionary(nvd_cache_path: Optional[str] = None,
                         out_path: str = CPE_DICT_PATH) -> None:
    """（可选，一次性维护工具）从 nvd_cache.json 抽取唯一 ``vendor:product`` 构建 CPE 字典。

    nvd_cache.json 体积较大（约 287MB），此函数会整体载入，建议一次性执行。
    生成的 ``data/cpe_dictionary.json`` 即为 :meth:`AffectedAssetExtractor._cpe_match`
    所用的字典。
    """
    nvd_cache_path = nvd_cache_path or os.path.join(DATA_DIR, "nvd_cache.json")
    if not os.path.isfile(nvd_cache_path):
        print(f"nvd_cache.json 不存在（{nvd_cache_path}），无法构建 CPE 字典")
        return
    print("载入 nvd_cache.json（较大，请稍候）...")
    with open(nvd_cache_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    seen: Dict[Tuple[str, str], Dict[str, str]] = {}

    def walk(cve: object) -> None:
        if not isinstance(cve, dict):
            return
        for cfg in cve.get("configurations", []) or []:
            for node in cfg.get("nodes", []) or []:
                for m in node.get("cpeMatch", []) or []:
                    if not isinstance(m, dict):
                        continue
                    crit = str(m.get("criteria") or "").strip()
                    parts = crit.split(":")
                    if len(parts) < 6 or parts[2] != "a":
                        continue
                    vendor, product = parts[3], parts[4]
                    if not vendor or not product or product in ("*", "-"):
                        continue
                    key = (vendor.lower(), product.lower())
                    seen.setdefault(key, {"vendor": vendor, "product": product, "cpe": crit})

    # nvd_cache 结构：{"done": [...], "<keyword>": [<cve>, ...]}
    for key, val in data.items():
        if key == "done" or not isinstance(val, list):
            continue
        for cve in val:
            walk(cve)

    entries = sorted(seen.values(), key=lambda x: (x["vendor"], x["product"]))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=1)
    print(f"已构建 CPE 字典 {out_path}，共 {len(entries)} 个 vendor:product")


# ==========================================================================
# 演示 / 自测入口
# ==========================================================================
if __name__ == "__main__":
    import io
    import sys

    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    demo_desc = (
        "Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.14.1 JNDI "
        "features used in configuration, log messages, and parameters do not "
        "protect against attacker controlled LDAP and other JNDI related endpoints."
    )
    assets = extract_affected_assets("CVE-2021-44228", demo_desc)
    print(f"受影响资产 {len(assets)} 条：")
    for a in assets:
        print(f"  - {a.vendor}/{a.product} "
              f"affected={a.affected_versions} unaffected={a.unaffected_versions} "
              f"confidence={a.confidence} method={a.extraction_method}")
        print(f"    cpe={a.cpe}")
