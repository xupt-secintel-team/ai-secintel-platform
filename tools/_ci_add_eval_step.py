# -*- coding: utf-8 -*-
"""把「统一评测门禁」插入 运行CI.bat，作为第 9 步。

为什么要插（评审失分点 1）：
  仓库里 8 个 `评测*.py` 全部靠人工手动跑，没有任何门禁 —— 评审无法判断
  "你报的 87% 富化准确率是哪天、用哪份真值算的"。加一步 runner 到 CI，
  让"富化准确率 ≥85% / 响应 ≤5s"从口头承诺变成**每次提交自动验证的红绿灯**。

必须保持 GBK 无 BOM（MEMORY 里记着：cmd 解析 bat 永远按系统 ANSI 看，
加 UTF-8 BOM 反而会把 BOM 字节和 @echo off 连成一条命令）。
所以这个脚本读进来是 GBK、替换、再按 GBK 无 BOM 写回。
"""
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BAT = os.path.join(ROOT, "运行CI.bat")

NEW_STEP = (
    'echo [9/9] 统一评测门禁（富化准确率 / 检索召回 / 时延 P95）\r\n'    'rem 2026-10-08 加（评审失分点：指标无 ground-truth 自证）。\r\n'
    'rem 跑 tools/评测门禁.py：对 评测集/gold_v*.json（NVD 官方原始响应为真值）\r\n'
    'rem 逐字段比富化结果，并实测检索召回与时延；不达阈值返回非 0 → CI 变红。\r\n'
    'rem 需要本机语料 data/corpus.json（283MB，不在版本库里），\r\n'
    'rem 所以这一步只在本地 CI 跑；GitHub CI 改跑 tools/_test_goldset.py（标注集自洽性）。\r\n'
    'rem 首次运行若 .idxcache 失效会重建索引（实测约 13 分钟），属一次性。\r\n'
    '%PY% tools\\评测门禁.py >nul 2>&1\r\n'
    'if errorlevel 1 (echo   ^> 评测门禁不达标（跑 tools\\评测门禁.py 看详情）'
    ' & goto :end) else (echo   ^> 评测门禁通过)\r\n'
)

STEP9 = NEW_STEP + "\r\n"

MARK_END = "echo.\r\necho ============================================\r\necho   全部通过 [OK]"


def main() -> int:
    with open(BAT, "rb") as f:
        raw = f.read()
    if raw[:3] == b"\xef\xbb\xbf":
        print("[ci] 警告：运行CI.bat 带 UTF-8 BOM，先去掉再改")
        return 2
    text = raw.decode("gbk")

    if "[9/9]" in text:
        print("[ci] 第 9 步已存在，跳过")
        return 0

    if "[8/8]" not in text:
        print("[ci] 找不到 [8/8]，无法定位插入点")
        return 2
    # 刻意**不**把 [8/8] 改成 [9/9]：新步骤插在原第 8 步**之后**，
    # 原第 8 步（启动阻塞检查）编号不变。曾一度全局替换导致两步都印 [9/9]。

    # 插入到"全部通过"横幅之前
    if MARK_END not in text:
        print("[ci] 找不到结束横幅，无法定位插入点")
        return 2
    text = text.replace(MARK_END, STEP9 + MARK_END, 1)

    # 总步数 8 → 9：前面 8 步的 "[N/8]" 要同步成 "[N/9]"，
    # 否则界面上会是 1/8…8/8 然后 9/9，看着像坏了。
    for n in range(1, 9):
        text = text.replace("[%d/8]" % n, "[%d/9]" % n)

    with open(BAT, "wb") as f:
        f.write(text.encode("gbk"))     # 无 BOM
    print("[ci] 已插入第 9 步：统一评测门禁")
    print("[ci] 步骤编号已同步为 1/9 … 9/9")
    return 0


if __name__ == "__main__":
    sys.exit(main())
