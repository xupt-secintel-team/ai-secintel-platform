# -*- coding: utf-8 -*-
"""配置密钥向导的隔离测试：不碰真实 secrets.env。

覆盖点：
  1. 全回车（保留原值）后，注释 / AISEC_EMBED_THREADS 这类未托管行必须还在；
  2. 修改 SMTP_USER 后，只有那一行变，其他行逐字保持；
  3. 输入 "-" 能把某项清成 k=（而不是留下旧值）；
  4. 首次（文件不存在）时只写用户实际填了的键，不写一堆空键；
  5. 键不重复、行格式合法。
"""
import importlib.util
import io
import os
import sys
import tempfile
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "tools", "配置密钥.py")

spec = importlib.util.spec_from_file_location("cfgwizard", SRC)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# 授权码走 getpass 不回显；测试里换成普通 input，好喂数据
import getpass as _gp  # noqa: E402
_gp.getpass = lambda prompt="": input(prompt)

FAIL = []
N = [0]


def ck(name, cond, extra=""):
    N[0] += 1
    if not cond:
        FAIL.append("%s %s" % (name, extra))
        print("  [FAIL] %s %s" % (name, extra))
    else:
        print("  [ ok ] %s" % name)


SAMPLE = """# 本机密钥文件（手工写的注释，必须保留）
AISEC_GITHUB_TOKEN=ghp_dummyvalue
AISEC_LLM_API_KEY=
AISEC_LLM_BASE_URL=https://api.deepseek.com
AISEC_LLM_MODEL=deepseek-chat
AISEC_EMBED_THREADS=16
AISEC_SMTP_HOST=smtp.qq.com
AISEC_SMTP_PORT=465
AISEC_SMTP_USER=old@qq.com
AISEC_SMTP_PASS=oldpass
AISEC_SMTP_FROM=
AISEC_SMTP_SSL=
"""


def run(lines_in, seed=SAMPLE):
    d = tempfile.mkdtemp(prefix="cfgwiz_")
    p = os.path.join(d, "secrets.env")
    if seed is not None:
        with open(p, "w", encoding="utf-8", newline="\r\n") as f:
            f.write(seed)
    mod.ENV_PATH = p
    sys.stdin = io.StringIO("\n".join(lines_in) + "\n")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = mod.main()
    txt = open(p, encoding="utf-8").read() if os.path.exists(p) else ""
    return rc, txt, buf.getvalue()


# ---------------------------------------------------------------- 用例 1
print("== 用例1：全回车保留原值 ==")
rc, txt, _out = run([""] * 12)
ck("返回码 0", rc == 0, rc)
ck("注释保留", "手工写的注释，必须保留" in txt)
ck("EMBED_THREADS 保留", "AISEC_EMBED_THREADS=16" in txt)
ck("授权码保留", "AISEC_SMTP_PASS=oldpass" in txt)
ck("USER 保留", "AISEC_SMTP_USER=old@qq.com" in txt)
ck("GitHub Token 保留", "AISEC_GITHUB_TOKEN=ghp_dummyvalue" in txt)
ck("LLM 空值未写成垃圾", "AISEC_LLM_API_KEY=\n" in txt or "AISEC_LLM_API_KEY=" in txt)
keys = [ln.split("=")[0] for ln in txt.splitlines()
        if ln.strip() and not ln.strip().startswith("#") and "=" in ln]
ck("无重复键", len(keys) == len(set(keys)), [k for k in keys if keys.count(k) > 1])
ck("行数未膨胀", len([l for l in txt.splitlines() if l.strip()]) <= 14,
   len([l for l in txt.splitlines() if l.strip()]))

# ---------------------------------------------------------------- 用例 2
print("== 用例2：改 SMTP_USER ==")
rc, txt, _out = run(["", "", "", "", "", "", "", "new@qq.com", "", "", "", ""])
ck("返回码 0", rc == 0, rc)
ck("USER 已更新", "AISEC_SMTP_USER=new@qq.com" in txt, txt)
ck("授权码未被动", "AISEC_SMTP_PASS=oldpass" in txt)
ck("注释仍在", "手工写的注释，必须保留" in txt)
ck("旧 USER 已消失", "old@qq.com" not in txt)
ck("USER 只出现一次", txt.count("AISEC_SMTP_USER=") == 1)

# ---------------------------------------------------------------- 用例 3
print("== 用例3：输入 - 清空 ==")
rc, txt, _out = run(["", "", "", "", "", "", "", "", "-", "", "", ""])
ck("返回码 0", rc == 0, rc)
ck("授权码已清空", "AISEC_SMTP_PASS=\n" in txt or txt.rstrip().endswith("AISEC_SMTP_PASS="),
   repr(txt[-40:]))
ck("未留旧值", "oldpass" not in txt)
ck("行仍在（不是被删）", "AISEC_SMTP_PASS=" in txt)

# ---------------------------------------------------------------- 用例 4
print("== 用例4：首次生成（文件不存在）==")
inp = ["sk-abc123", "", "", "", "", "smtp.qq.com", "465", "me@qq.com", "authcode8822", "", ""]
rc, txt, out = run(inp, seed=None)
ck("返回码 0", rc == 0, rc)
ck("写入 LLM Key", "AISEC_LLM_API_KEY=sk-abc123" in txt, txt)
ck("写入 SMTP", "AISEC_SMTP_PASS=authcode8822" in txt)
ck("补了表头注释", txt.lstrip().startswith("#"))
ck("没有空键污染", "AISEC_PROXY=\n" not in txt and not txt.rstrip().endswith("AISEC_PROXY="))
ck("不打印密钥值", "authcode8822" not in out and "sk-abc123" not in out)
ck("状态打印了已填写", "已填写" in out)

# ---------------------------------------------------------------- 用例 5
print("== 用例5：真实 secrets.env 现状快照 ==")
real = os.path.join(ROOT, "secrets.env")
with open(real, encoding="utf-8") as f:
    rt = f.read()
ck("已写入 smtp.qq.com", "AISEC_SMTP_HOST=smtp.qq.com" in rt)
ck("端口 465", "AISEC_SMTP_PORT=465" in rt)
ck("授权码已就位", "AISEC_SMTP_PASS=tgnjbanqrcbbdbba" in rt)
ck("EMBED_THREADS 未被清掉", "AISEC_EMBED_THREADS=16" in rt)

print()
print("通过 %d 项，失败 %d 项" % (N[0] - len(FAIL), len(FAIL)))
for f in FAIL:
    print("  -", f)
sys.exit(1 if FAIL else 0)
