# -*- coding: utf-8 -*-
"""
test_poc_scraper.py —— POC 抓取模块测试用例
============================================
使用 CVE-2021-44228（Log4j / Log4Shell）验证 search_poc 能否抓到结果，
并输出深度优化的完整过程（关键词、query 命中数、分类、评分、去重统计）。

运行：::

    python test_poc_scraper.py

说明：
    - 结果数量取决于网络可达性与是否配置 GitHub Token；即便抓不到结果，
      模块也应能正常结束而不抛异常（这是本用例的核心断言之一）。
    - 会对「结果类型 / URL 去重 / 字段完整性 / poc_type 合法性」做基础断言。
    - 开启 INFO 日志以观察每个阶段的处理过程。
"""

import io
import logging
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))

from poc_scraper import (  # noqa: E402
    POCResult, POC_TYPE_LABELS, search_poc, save_poc_results,
)

# 与项目其它脚本一致：Windows 下显式按 UTF-8 输出
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)


def main() -> None:
    """测试入口。"""
    cve = "CVE-2021-44228"
    print(f"=== 测试 search_poc({cve}) ===\n")

    t0 = time.time()
    results = search_poc(cve)
    elapsed = time.time() - t0

    # ---------- 基础断言 ----------
    assert isinstance(results, list), "返回值应为 list"
    assert all(isinstance(r, POCResult) for r in results), "每条结果应为 POCResult"
    urls = [r.url for r in results if r.url]
    assert len(urls) == len(set(urls)), "结果应按 URL 去重"
    for r in results:
        assert r.poc_id and r.source and r.title, f"poc_id/source/title 不应为空: {r}"
        assert r.reliability in ("高", "中", "低"), f"reliability 取值非法: {r.reliability}"
        assert r.poc_type in POC_TYPE_LABELS, f"poc_type 取值非法: {r.poc_type}"
        assert r.fetched_at, "fetched_at 不应为空"

    print(f"\n抓取耗时 {elapsed:.1f}s，去重后共 {len(results)} 条结果\n")

    if not results:
        print("⚠️ 未抓到结果（可能网络受限 / 未配置 Token 触发 GitHub 限流）。")
        print("  模块本身已正常执行且未抛异常，测试通过（数据源可用时才有结果）。")
        return

    # ---------- 统计 ----------
    gh = [r for r in results if r.source == "github"]
    type_counter = Counter(r.poc_type for r in results)
    code_rate = 100.0 * sum(1 for r in results if r.code_content) / len(results)

    print("=" * 60)
    print("统计汇总")
    print("=" * 60)
    print(f"总数: {len(results)}  (GitHub {len(gh)} / 其他 {len(results) - len(gh)})")
    print(f"代码抓取率: {code_rate:.0f}%")
    print("按 poc_type 分布:")
    for typ, label in POC_TYPE_LABELS.items():
        if type_counter.get(typ):
            print(f"  {label:12s} ({typ:16s}): {type_counter[typ]} 条")
    print()

    # ---------- 按 poc_type 分组展示（exploit_code 在前） ----------
    order = ["exploit_code", "payload", "scanner", "detection_script",
             "environment", "analysis", "other"]
    grouped = defaultdict(list)
    for r in results:
        grouped[r.poc_type].append(r)

    print("=" * 60)
    print("结果明细（按 poc_type 分组，组内按得分降序）")
    print("=" * 60)
    for typ in order:
        items = grouped.get(typ, [])
        if not items:
            continue
        print(f"\n◆ {POC_TYPE_LABELS.get(typ, typ)} ({typ}) — {len(items)} 条")
        for i, r in enumerate(items, 1):
            print(f"  [{i}] {r.title[:70]}")
            print(f"      得分={r.score:.3f} 可靠性={r.reliability} verified={r.verified} "
                  f"star={r.stars} lang={r.language or '-'}")
            print(f"      {r.url}")
            if r.code_content:
                print(f"      code_content {len(r.code_content)} 字符")

    # ---------- 持久化验证 ----------
    print()
    path = save_poc_results(results)
    print(f"已保存 {len(results)} 条结果 -> {path}")
    print("\n测试通过。")
    print("来源分布:", dict(Counter(r.source for r in results)))


if __name__ == "__main__":
    main()
