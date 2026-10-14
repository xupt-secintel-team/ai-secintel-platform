# -*- coding: utf-8 -*-
"""
检查依赖.py —— 运行前依赖自检（把"能不能跑"变成开机可见的信息）
==============================================================
背景：交付包此前没有依赖清单，换机器后 `/api/assets` 直接
`No module named 'requests'` 崩溃，而文档写的是"3 步跑起来"。
本脚本把依赖状态前置暴露出来，并给出对应的降级行为说明。

用法：
    py -3 tools/检查依赖.py            # 人看的报告
    py -3 tools/检查依赖.py --json     # 机器可读（供自测/评测脚本引用）
    py -3 tools/检查依赖.py --install  # 打印一键安装命令（不会自动执行）

退出码：0 = 核心依赖齐备；1 = 缺核心依赖（仍可跑，但富化能力会降级）
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys

# (模块名, pip 包名, 档次, 缺失时的后果)
DEPS = [
    ("requests", "requests", "core",
     "受影响资产定位 /api/assets、POC 搜索 /api/poc 会降级到标准库 core/httpcompat.py（可用但更弱）"),
    ("urllib3", "urllib3", "core",
     "关闭 SSL 校验时的告警抑制失效（仅影响日志噪音）"),
    ("bs4", "beautifulsoup4", "enhance",
     "PacketStorm 页面解析与详情页作者抽取跳过，其余 POC 数据源不受影响"),
    ("numpy", "numpy", "enhance",
     "语义向量索引不可用，问答自动降级为纯关键词检索（功能完整，语义召回失效）"),
    ("openai", "openai", "optional",
     "大模型问答 / 智能体工具调用不可用，问答走检索证据模板（零 token）"),
    ("torch", "torch", "optional",
     "本地嵌入模型不可用，无法新建语义索引（已有索引仍可检索？需 numpy）"),
    ("transformers", "transformers", "optional",
     "本地嵌入模型不可用，无法新建语义索引"),
    ("sentencepiece", "sentencepiece", "optional",
     "e5 系列 tokenizer 可能加载失败（影响新建语义索引）"),
    # —— 报告导出（m2_enrich 的 CMDB 报告下载 / 邮件投递）——
    # 注意：openpyxl 缺失不是"优雅降级"，是**功能直接报错**：
    # 页面上点「下载简略版」或勾选「发送 xlsx」会抛 RuntimeError。
    ("openpyxl", "openpyxl", "report",
     "CMDB 简略版处置台账（.xlsx）无法导出 —— 点「下载简略版 / 发送 xlsx」会直接报错"),
    ("markdown", "markdown", "report",
     "邮件正文降级为等宽纯文本（内容不丢，但标题/表格不渲染成样式）"),
]

LEVEL_TEXT = {"core": "核心", "enhance": "增强", "optional": "可选", "report": "报告导出"}


def probe(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError):
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="AI-SecIntel 依赖自检")
    ap.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    ap.add_argument("--install", action="store_true", help="只打印一键安装命令")
    args = ap.parse_args()

    rows = []
    for mod, pkg, level, impact in DEPS:
        ok = probe(mod)
        rows.append({"module": mod, "package": pkg, "level": level,
                     "level_text": LEVEL_TEXT[level], "installed": ok, "impact": impact})

    missing_core = [r for r in rows if r["level"] == "core" and not r["installed"]]
    missing_enh = [r for r in rows if r["level"] == "enhance" and not r["installed"]]
    missing_opt = [r for r in rows if r["level"] == "optional" and not r["installed"]]
    missing_rep = [r for r in rows if r["level"] == "report" and not r["installed"]]

    if args.json:
        print(json.dumps({"rows": rows,
                          "missing_core": [r["module"] for r in missing_core],
                          "missing_enhance": [r["module"] for r in missing_enh],
                          "missing_optional": [r["module"] for r in missing_opt],
                          "missing_report": [r["module"] for r in missing_rep]},
                         ensure_ascii=False, indent=2))
        return 0 if not missing_core else 1

    if args.install:
        packs = [r["package"] for r in rows if not r["installed"]]
        if not packs:
            print("所有依赖已安装，无需操作。")
            return 0
        print("一键安装命令：")
        print("    pip install " + " ".join(packs))
        if "torch" in packs:
            print("    # torch 建议装 CPU 版：")
            print("    pip install torch --index-url https://download.pytorch.org/whl/cpu")
        return 0

    print("=" * 72)
    print(f"依赖自检 · Python {sys.version.split()[0]}")
    print("=" * 72)
    for r in rows:
        flag = "✅ 已装" if r["installed"] else "⬜ 缺失"
        print(f"  [{r['level_text']}] {r['module']:<14} {flag}")
        if not r["installed"]:
            print(f"          └─ 影响：{r['impact']}")
    print("-" * 72)
    if missing_core:
        print(f"!! 缺 {len(missing_core)} 个核心依赖：{', '.join(r['package'] for r in missing_core)}")
        print("   富化接口会自动降级（不崩溃），但要完整能力请执行：")
        print("   pip install " + " ".join(r["package"] for r in missing_core))
    else:
        print("核心依赖齐备，主体 + 富化全功能可用。")
    if missing_enh:
        print(f"· 增强依赖缺 {len(missing_enh)} 个（自动降级）："
              f"{', '.join(r['package'] for r in missing_enh)}")
    if missing_rep:
        print(f"!! 报告导出依赖缺 {len(missing_rep)} 个（不是降级，相关按钮会报错）："
              f"{', '.join(r['package'] for r in missing_rep)}")
        print("   修法： pip install " + " ".join(r["package"] for r in missing_rep))
    if missing_opt:
        print(f"· 可选依赖缺 {len(missing_opt)} 个（按需安装）："
              f"{', '.join(r['package'] for r in missing_opt)}")
    print("=" * 72)
    return 0 if not missing_core else 1


if __name__ == "__main__":
    raise SystemExit(main())
