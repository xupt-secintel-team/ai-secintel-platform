#!/usr/bin/env bash
# =====================================================================
#  AI-SecIntel 2.0 · 一键安装（Linux / macOS）
# =====================================================================
#  用法：
#      ./安装.sh               # 体检 → 建 .venv → 选源 → 装依赖 → 自检
#      ./安装.sh --full        # 连 torch / transformers 一起装（约 700MB）
#      ./安装.sh --no-venv     # 装进系统 Python，不建虚拟环境
#      ./安装.sh --offline     # 离线：只检测不联网
#      ./安装.sh --check       # 只体检，不装东西
#
#  macOS 双击场景：双击 安装.command（本文件的可执行副本）
# =====================================================================
set -u
cd "$(dirname "$0")" || exit 1

echo ""
echo " ============================================================"
echo "   AI-SecIntel 2.0 | 一键安装"
echo " ============================================================"
echo ""

# ── 0. 找 Python 3.7+ ──────────────────────────────────────────────────
PYEXE=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
        if "$cand" -c 'import sys;sys.exit(0 if sys.version_info[:2]>=(3,7) else 1)' >/dev/null 2>&1; then
            PYEXE="$cand"; break
        fi
    fi
done

if [ -z "$PYEXE" ]; then
    echo " [!] 没有找到 Python 3.7 及以上版本。"
    echo ""
    echo "     请安装后重新运行本脚本："
    echo "       macOS : brew install python@3.11"
    echo "       Ubuntu: sudo apt install python3 python3-venv python3-pip"
    echo "       CentOS: sudo yum install python3 python3-pip"
    echo ""
    read -r -p " 按回车键退出..." _
    exit 1
fi

echo " [i] 使用解释器：$PYEXE ($("$PYEXE" -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])'))"
echo ""

# ── 1. 交给 bootstrap.py ───────────────────────────────────────────────
"$PYEXE" bootstrap.py "$@"
RC=$?

echo ""
if [ "$RC" = "0" ]; then
    echo " ============================================================"
    echo "   安装完成。下一步："
    if [ "$(uname -s)" = "Darwin" ]; then
        echo "     双击 start.command   或执行 ./start.sh"
    else
        echo "     执行 ./start.sh"
    fi
    echo " ============================================================"
elif [ "$RC" = "2" ]; then
    echo " ============================================================"
    echo "   Python 版本不达标，请先安装 Python 3.7+ 后重试"
    echo " ============================================================"
else
    echo " ============================================================"
    echo "   安装未完全成功，但系统可在降级模式下运行。"
    echo "   仍可执行 ./start.sh；要完整能力请手动执行："
    echo "       pip3 install -r requirements.txt"
    echo " ============================================================"
fi
echo ""
exit $RC
