#!/bin/sh
# CI 步骤 2-9 原生复刻（避开 cmd 括号路径问题）
cd "$(dirname "$0")/.." || exit 1
PY=.venv/Scripts/python.exe
NODE="/c/Users/张洺豪/.workbuddy/binaries/node/versions/22.22.2-6/node.exe"
export PYTHONDONTWRITEBYTECODE=1

echo "=== [2/9] 前端桩测试（Node）==="
if [ -x "$NODE" ]; then
  F2=0
  for f in tools/_test_*.js; do
    if ! "$NODE" "$f" >/dev/null 2>&1; then echo "  [FAIL] $f"; F2=1; fi
  done
  [ $F2 -eq 0 ] && echo "  > 前端测试全部通过" || echo "  > 有前端测试失败"
else
  echo "  [!] node 不可用，跳过"
fi

echo "=== [3/9] 前端组装一致性校验 ==="
"$PY" tools/组装前端.py --check 2>&1 | tail -3

echo "=== [4/9] 语法编译检查（core + modules）==="
"$PY" -m compileall -q core modules && echo "  > 语法检查通过" || echo "  > 存在语法错误"

echo "=== [5/9] 前端可读性检查（对比度）==="
"$PY" tools/检查对比度.py 2>&1 | tail -3

echo "=== [6/9] 交付可移植性检查 ==="
"$PY" tools/_test_portability.py 2>&1 | tail -3

echo "=== [7/9] 批处理编码检查 ==="
"$PY" tools/_fix_bat_encoding.py --check 2>&1 | tail -3

echo "=== [8/9] 启动阻塞检查 ==="
"$PY" tools/_test_startup_block.py 2>&1 | tail -3

echo "=== [9/9] 统一评测门禁 ==="
"$PY" tools/评测门禁.py 2>&1 | tail -6

echo "=== STEPS 2-9 DONE ==="
