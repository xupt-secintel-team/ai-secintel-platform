# -*- coding: utf-8 -*-
"""
evaluate_qa.py — 问答模块评测脚本
跑一遍测试问题，统计回答质量指标
"""
import urllib.request
import urllib.parse
import json
import io
import os
import sys
import time
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

# 安全 UTF-8 输出设置：用 reconfigure 而非重建 TextIOWrapper，
# 否则模块被 import 时会关闭原 stdout（合并/复用场景下的隐患）
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception as _sw_e:
    _swallow("modules/m3_qa/backend/qa/evaluate.py:17", _sw_e)

# 评测目标服务地址。
# 原先硬编码 8849，而服务默认端口是 8848（config.json / 启动脚本都是 8848）——
# 评测脚本一直打在一个默认不存在的端口上，测出来的数字毫无意义。
# 现在跟 qa 其余模块一致走 AISEC_MAIN_SERVER，可用环境变量覆盖：
#   AISEC_MAIN_SERVER=http://127.0.0.1:8848 py -3 tools/评测问答.py
QA_SERVER = os.environ.get("AISEC_QA_SERVER") or os.environ.get("AISEC_MAIN_SERVER") \
    or "http://127.0.0.1:8848"

# 测试问题集（覆盖各类型）
TEST_CASES = [
    # CVE详情类
    {"q": "CVE-2024-5565", "type": "cve_detail", "expect_has": ["CVE-2024-5565", "CVSS"]},
    # 组件查询类
    {"q": "log4j有哪些漏洞", "type": "affected_products", "expect_has": ["log4j"]},
    # 政策法规类
    {"q": "数据安全法", "type": "policy", "expect_has": ["数据安全"]},
    # 攻击技术类
    {"q": "prompt injection", "type": "attack", "expect_has": ["CVE"]},
    # 修复建议类
    {"q": "怎么修复log4j漏洞", "type": "fix_advice", "expect_has": ["修复", "升级"]},
    # 中文通用查询
    {"q": "AI安全有哪些常见风险", "type": "general", "expect_has": [""]},
    # 英文查询
    {"q": "what is RAG security vulnerability", "type": "general", "expect_has": ["CVE"]},
]


def run_test():
    print("=" * 50)
    print("问答模块评测")
    print("=" * 50)

    passed = 0
    total = len(TEST_CASES)
    total_time = 0

    for i, tc in enumerate(TEST_CASES, 1):
        q = tc["q"]
        t0 = time.time()
        try:
            d = json.load(urllib.request.urlopen(
                QA_SERVER + "/api/chat?" + urllib.parse.urlencode({"q": q}), timeout=30))
            elapsed = time.time() - t0
            total_time += elapsed

            answer = d.get("answer", "")
            sources = d.get("sources", [])

            # 检查期望关键词是否在回答里
            hit = all(kw in answer for kw in tc["expect_has"] if kw)
            status = "PASS" if hit else "PARTIAL"

            if hit:
                passed += 1

            print(f"\n[{i}/{total}] {status} | {q}")
            print(f"  耗时: {elapsed*1000:.0f}ms | 引用来源: {len(sources)} | 找到{d.get('total_found')}条")
            print(f"  回答开头: {answer[:100].replace(chr(10), ' ')}...")

        except Exception as e:
            print(f"\n[{i}/{total}] FAIL | {q}")
            print(f"  错误: {e}")

    print("\n" + "=" * 50)
    print(f"评测结果：{passed}/{total} 通过 ({passed/total*100:.1f}%)")
    print(f"平均响应时间: {total_time/total*1000:.0f}ms")
    print("=" * 50)


if __name__ == "__main__":
    run_test()
