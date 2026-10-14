# -*- coding: utf-8 -*-
"""
test_affected_assets.py —— 受影响资产定位模块测试用例
======================================================
分两部分：
  1. 离线单元测试（确定性，不依赖网络）：NVD 解析 / 容错 JSON / 合并优先级 /
     版本区间格式化 / CPE 合成；
  2. 在线演示（容错）：用 CVE-2021-44228 和一个描述模糊的 CVE 走完整入口，
     验证结构合法且不抛异常（网络/未配 Key 时允许结果为空）。

运行：::

    python test_affected_assets.py
"""

import io
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from affected_assets import (  # noqa: E402
    AffectedAsset, AffectedAssetExtractor, extract_affected_assets,
    _asset_from_dict, _make_cpe, _parse_json_tolerant,
    CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW,
    METHOD_NVD, METHOD_LLM, METHOD_CPE,
)

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                    datefmt="%H:%M:%S")


# --------------------------------------------------------------------------
# 离线单元测试
# --------------------------------------------------------------------------
def _mock_log4j_cve():
    """构造 CVE-2021-44228 的 NVD cve 对象（configurations 子集）。"""
    def match(criteria, vulnerable, **rng):
        m = {"criteria": criteria, "vulnerable": vulnerable}
        m.update(rng)
        return m

    return {
        "configurations": [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [
                    match("cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*",
                          True, versionStartIncluding="2.0-beta9",
                          versionEndExcluding="2.12.2"),
                    match("cpe:2.3:a:apache:log4j:2.13.0:*:*:*:*:*:*:*",
                          True, versionStartIncluding="2.13.0",
                          versionEndExcluding="2.15.0"),
                    match("cpe:2.3:a:apache:log4j:2.12.2:*:*:*:*:*:*:*",
                          False, versionStartIncluding="2.12.2",
                          versionEndExcluding="2.16.0"),
                ],
            }],
        }],
    }


def test_parse_nvd():
    assets = AffectedAssetExtractor._parse_nvd_cve(_mock_log4j_cve())
    assert len(assets) == 1, f"应为 1 个资产，实际 {len(assets)}"
    a = assets[0]
    assert a.vendor == "apache" and a.product == "log4j", (a.vendor, a.product)
    assert a.confidence == CONFIDENCE_HIGH and a.extraction_method == METHOD_NVD
    assert any("2.0-beta9" in v for v in a.affected_versions), a.affected_versions
    assert any("2.13.0" in v for v in a.affected_versions), a.affected_versions
    assert len(a.unaffected_versions) >= 1, a.unaffected_versions
    assert a.cpe.startswith("cpe:2.3:a:apache:log4j:"), a.cpe
    print("✓ test_parse_nvd 通过:", a.vendor, a.product, a.affected_versions, a.unaffected_versions)


def test_json_tolerant():
    raw = '```json\n{"assets": [{"vendor": "apache", "product": "log4j", ' \
          '"affected_versions": ["2.0"], "unaffected_versions": []}]}\n```  '
    obj = _parse_json_tolerant(raw)
    assert obj and obj["assets"][0]["product"] == "log4j"
    # 带尾随逗号（常见 LLM 输出瑕疵）
    raw2 = '{"assets": [{"vendor": "microsoft", "product": "exchange", "affected_versions": ["2016",], "unaffected_versions": [],},]}'
    obj2 = _parse_json_tolerant(raw2)
    assert obj2 is not None
    # 完全非法
    assert _parse_json_tolerant("这不是 JSON") is None
    print("✓ test_json_tolerant 通过")


def test_merge_priority():
    nvd = [AffectedAsset(vendor="apache", product="log4j",
                         confidence=CONFIDENCE_HIGH, extraction_method=METHOD_NVD)]
    llm = [AffectedAsset(vendor="apache", product="log4j",
                         confidence=CONFIDENCE_MEDIUM, extraction_method=METHOD_LLM),
           AffectedAsset(vendor="microsoft", product="exchange",
                         confidence=CONFIDENCE_MEDIUM, extraction_method=METHOD_LLM)]
    cpe = [AffectedAsset(vendor="microsoft", product="exchange",
                         confidence=CONFIDENCE_LOW, extraction_method=METHOD_CPE),
           AffectedAsset(vendor="oracle", product="weblogic",
                         confidence=CONFIDENCE_LOW, extraction_method=METHOD_CPE)]
    merged = AffectedAssetExtractor._merge(nvd, llm, cpe)
    by = {(a.vendor, a.product): a for a in merged}
    assert len(merged) == 3, f"应去重为 3 个，实际 {len(merged)}"
    assert by[("apache", "log4j")].extraction_method == METHOD_NVD, "NVD 应优先于 LLM"
    assert by[("apache", "log4j")].confidence == CONFIDENCE_HIGH
    assert by[("microsoft", "exchange")].extraction_method == METHOD_LLM, "LLM 应优先于 CPE"
    assert by[("oracle", "weblogic")].extraction_method == METHOD_CPE
    print("✓ test_merge_priority 通过")


def test_version_range_and_cpe():
    m = {"versionStartIncluding": "2.13.0", "versionEndExcluding": "2.15.0"}
    assert AffectedAssetExtractor._version_range(m, "2.13.0") == "2.13.0 - <2.15.0"
    assert AffectedAssetExtractor._version_range({"versionEndIncluding": "1.2.14"}, "1.2.14") == "1.2.14"
    assert _make_cpe("apache", "log4j", "2.0 - <2.12.2") == \
        "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"
    assert _make_cpe("apache", "log4j") == "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
    print("✓ test_version_range_and_cpe 通过")


# --------------------------------------------------------------------------
# 在线演示（容错）
# --------------------------------------------------------------------------
def _assert_struct(assets, label):
    assert isinstance(assets, list), "返回值应为 list"
    for a in assets:
        assert isinstance(a, AffectedAsset)
        assert a.vendor and a.product, f"vendor/product 不应为空: {a}"
        assert a.confidence in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW)
        assert a.extraction_method in (METHOD_NVD, METHOD_LLM, METHOD_CPE)
        # 往返序列化
        assert _asset_from_dict(a.to_dict()).product == a.product
    print(f"[{label}] 返回 {len(assets)} 条资产")
    for a in assets:
        print(f"    - {a.vendor}/{a.product} affected={a.affected_versions} "
              f"unaffected={a.unaffected_versions} conf={a.confidence} "
              f"method={a.extraction_method}")


def test_live_log4j():
    desc = (
        "Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.14.1 JNDI "
        "features used in configuration, log messages, and parameters do not "
        "protect against attacker controlled LDAP and other JNDI related endpoints. "
        "An attacker who can control log messages or log message parameters can "
        "execute arbitrary code loaded from LDAP servers when message lookup "
        "substitution is enabled."
    )
    assets = extract_affected_assets("CVE-2021-44228", desc)
    _assert_struct(assets, "CVE-2021-44228")


def test_live_vague():
    # 描述模糊：无厂商/产品/版本，且 CVE 不存在 -> NVD/LLM/CPE 三路均无结果，期望空列表
    assets = extract_affected_assets("CVE-2099-0001",
                                     "An unspecified flaw may allow remote code execution.")
    _assert_struct(assets, "描述模糊的 CVE-2099-0001")
    # 未配 DeepSeek Key、无 CPE 字典、NVD 无该 CVE 时，此处应为空列表（三路均无结果）
    assert assets == [], "三路均无结果时应返回空列表"
    print("    （三路均无结果，正确返回空列表）")


def main():
    print("=== 受影响资产定位模块测试 ===\n")
    test_parse_nvd()
    test_json_tolerant()
    test_merge_priority()
    test_version_range_and_cpe()
    print("\n--- 在线演示（网络/未配 Key 时允许为空）---")
    test_live_log4j()
    test_live_vague()
    print("\n测试通过。")


if __name__ == "__main__":
    main()
