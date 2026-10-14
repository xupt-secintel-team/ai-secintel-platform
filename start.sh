#!/usr/bin/env bash
# =====================================================================
#  AI-SecIntel 2.0 · 一键启动（Linux / macOS）
# =====================================================================
#  用法：
#      ./start.sh                 # 首次运行会自动配置环境，之后直接启动
#      ./start.sh 8899            # 指定端口
#      ./start.sh --no-live       # 不起实时监测线程
#      ./start.sh --setup         # 只做环境配置，不启动服务
#      ./start.sh --low           # 强制低配档（慢机器/评审用笔记本）
#
#  双击场景（macOS）：直接双击 start.command（本文件的可执行副本）
# =====================================================================
set -u
cd "$(dirname "$0")" || exit 1

export PYTHONDONTWRITEBYTECODE=1
export NO_PROXY=127.0.0.1,localhost
export no_proxy=127.0.0.1,localhost

# ── 0. 选解释器：优先项目内的 .venv（bootstrap 建的），其次系统 python3 ──
PYEXE=""
if [ -x ".venv/bin/python" ]; then
    PYEXE=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYEXE="python3"
elif command -v python >/dev/null 2>&1; then
    PYEXE="python"
fi

if [ -z "$PYEXE" ]; then
    echo "[!] 未找到 Python。请先安装 Python 3.7+："
    echo "    macOS : brew install python@3.11"
    echo "    Ubuntu: sudo apt install python3 python3-venv python3-pip"
    echo "    CentOS: sudo yum install python3 python3-pip"
    exit 1
fi

# ── 1. 低配档开关（--low）：慢机器上手工降档 ──────────────────────────
ARGS=()
for a in "$@"; do
    case "$a" in
        --low)   export AISEC_PERF_TIER=low; echo "[i] 已强制低配档（慢机器友好）" ;;
        --mid)   export AISEC_PERF_TIER=mid; echo "[i] 已强制中配档" ;;
        --high)  export AISEC_PERF_TIER=high; echo "[i] 已强制高配档" ;;
        *)       ARGS+=("$a") ;;
    esac
done

# ── 2. 环境自检 + 首次自动配置 ─────────────────────────────────────────
# 没有 .venv 且没有环境档案时，判定为"首次运行"，先跑 bootstrap 把依赖装好。
if [ ! -f ".aisec_env.json" ] && [ ! -x ".venv/bin/python" ]; then
    echo "[i] 首次运行：开始自动配置环境（约 1-3 分钟，视网速而定）..."
    "$PYEXE" bootstrap.py || {
        echo "[!] 环境配置未完成，但系统可在降级模式下运行，继续启动..."
    }
fi

if [ -x ".venv/bin/python" ]; then
    PYEXE=".venv/bin/python"
fi

# ── 3. 加载本机密钥（secrets.env 已被 .gitignore 排除，不进仓库）────────
if [ -f "secrets.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . ./secrets.env
    set +a
    echo "[i] 已加载 secrets.env（密钥 / 代理）"
fi

# ── 4. 打印环境画像（让"慢机器为什么慢"变成可见信息）───────────────────
"$PYEXE" core/envprofile.py 2>/dev/null || true

# ── 5. 启动 ────────────────────────────────────────────────────────────
if [ "${1:-}" = "--setup" ]; then
    echo "[✓] 环境配置模式，不启动服务。"
    exit 0
fi

echo "[i] 正在启动：core/server.py ${ARGS[*]:-}"
echo "[i] 控制台地址： http://127.0.0.1:${1:-8848}/"
exec "$PYEXE" -u core/server.py "${ARGS[@]}"
