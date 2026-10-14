# -*- coding: utf-8 -*-
"""
build_installer.py —— 把项目打成可分发的安装包（zip）
====================================================================
用户诉求：「弄成安装包，可以自动配置环境、安装文件」

产出
----
    dist/AI-SecIntel_v2.0_安装包_YYYYMMDD.zip

解压后顶层长这样（拿到的人只需要看 README_安装.md）：

    AI-SecIntel_2.0/
    ├─ 安装.bat          Windows 双击 → 自动配环境（体检/建 .venv/选源/装依赖/自检）
    ├─ 安装.command      macOS 双击（安装.sh 的可执行副本）
    ├─ 安装.sh           Linux 命令行
    ├─ 启动服务.bat      Windows 双击 → 起服务
    ├─ start.command     macOS 双击（start.sh 的可执行副本）
    ├─ start.sh          Linux / macOS 命令行
    ├─ bootstrap.py      安装程序的本体（上面几个脚本都是它的外壳）
    ├─ README_安装.md    三系统安装 / 慢机器降档 / 常见问题
    ├─ core/ modules/ frontend/ tools/    程序本体
    └─ config.json requirements.txt

为什么默认不带 data/
--------------------
语料 274MB + 索引缓存 286MB + 富化缓存 200MB = 1.8GB。打进 zip 后
压缩要十几分钟、解压同样久，而赛方机器多半还要再拷一次——性价比极低。
所以默认打"代码包"，语料由安装后联网抓取（`fetch_corpus.py`）
或直接拷现成的 data/ 目录。确需离线交付时用 `--with-data`。

用法
----
    python tools/build_installer.py                # 打代码包（几 MB）
    python tools/build_installer.py --with-data    # 连语料一起打（1.8GB+，很慢）
    python tools/build_installer.py --out D:/x.zip # 指定输出路径
    python tools/build_installer.py --list         # 只列清单，不打包

注意：`.command` 文件必须带可执行权限位，否则 macOS 双击会提示
「无法打开，因为它来自身份不明的开发者」之外的权限错误——
这里在写入 zip 时手工置 `external_attr`（zipfile 默认不给权限位）。
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "core"))

try:
    import compat
except Exception:                                    # pragma: no cover
    from core import compat                          # type: ignore

compat.ensure_utf8_stdio()

VERSION = "2.3"

# ── 打进包的内容 ────────────────────────────────────────────────────────────
INCLUDE_DIRS = ["core", "modules", "frontend", "tools"]
INCLUDE_FILES = [
    "bootstrap.py", "config.json", "requirements.txt",
    "安装.bat", "安装.sh", "启动服务.bat", "启动服务_守护.bat", "start.sh",
    "README_安装.md", "README.md", "部署与运维.md",
    # ── 评审 / 交付文档 ────────────────────────────────────────────────
    # 这几个在 README 里被反引用（"详见 xxx.md"），不打进包的话，
    # 拿到包的人点开就是死链，评审时很减分。
    "技术方案与系统设计文档.md", "架构设计图.md", "演示脚本_5分钟.md",
    "交付总览.md", "修复说明.md", "加强说明.md", "加强说明_v2.2.md",
    "版本核查报告.md", "结构说明与协作规范.md", "缺口补齐对照表.md",
    # ── 可选能力 / 守护模式入口 ────────────────────────────────────────
    "下载嵌入模型.bat", "下载翻译模型.bat", "安装语义依赖.bat",
    "设置密钥.bat", "运行自测.bat", "运行CI.bat",
    # ── 防止使用者 git 管理时把 secrets.env / .venv 提交上去 ────────────
    ".gitignore",
]

# 需要顺带生成 .command 副本的 shell 脚本（macOS 双击用）
COMMAND_COPIES = [("start.sh", "start.command"),
                  ("安装.sh", "安装.command")]

# ── 一律排除 ────────────────────────────────────────────────────────────────
EXCLUDE_DIR_NAMES = {
    ".venv", "venv", "env", "__pycache__", ".git", ".github",
    ".workbuddy", ".idea", ".vscode", "node_modules",
    "_video_frames_ui", "_archive",
}
# 这些是开发过程产物，不属于交付面（评测/测试报告/交付物体积大且评审不看）
EXCLUDE_TOP_LEVEL = {"data", "output", "测试报告", "评测", "交付物",
                     "交付文档", ".pytest_cache", "dist"}
EXCLUDE_FILE_SUFFIX = {".pyc", ".pyo", ".pyd", ".so", ".dylib"}
# 开发过程的终端会话 dump / 调试日志，不属于交付面。
# 历史上 POC.txt 就是这样混进包的，里面带着一整段 PowerShell 会话
# （含真实 GitHub 令牌与开发者桌面路径）。源码已脱敏，这里再排除，双保险。
EXCLUDE_FILE_NAMES = {"POC.txt"}
# 含密钥，绝不进包（改为生成空模板）
SECRET_FILES = {"secrets.env"}

# ── 打包前的密钥闸门 ────────────────────────────────────────────────────────
# 交付包一旦外发即视为泄露，删文件救不回已扩散的凭据。
# 所以宁可在打包阶段直接失败，也不能让密钥混进去。
# 命中下面任一条 → 中止打包（不是警告，是中止）。
SECRET_PATTERNS = [
    ("GitHub 细粒度令牌", re.compile(r'github_pat_[A-Za-z0-9_]{20,}')),
    ("GitHub 经典令牌", re.compile(r'ghp_[A-Za-z0-9]{20,}')),
    ("OpenAI / DeepSeek Key", re.compile(r'sk-[A-Za-z0-9]{20,}')),
    ("硬编码 API Key", re.compile(r'(?i)api[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9_\-]{20,}')),
    ("硬编码 Token 赋值", re.compile(r'(?i)(?:^|[^a-z])token\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']')),
]
# 只提示、不阻断：本机路径不算凭据，但交付包里出现他人用户名很难看
WARN_PATTERNS = [
    ("本机用户目录", re.compile(r'[A-Za-z]:\\+Users\\+[A-Za-z0-9._\-]+\\+')),
]


def scan_secrets(files):
    """扫描待打包文件，返回 (阻断列表, 警告列表)。"""
    blocks, warns = [], []
    for fp, rel in files:
        try:
            with open(fp, "rb") as f:
                raw = f.read()
        except Exception:
            continue
        if b"\x00" in raw[:8192]:          # 二进制（pickle / 模型等）跳过
            continue
        try:
            text = raw.decode("utf-8")
        except Exception:
            continue
        for name, pat in SECRET_PATTERNS:
            m = pat.search(text)
            if m:
                blocks.append((rel, name, text[:m.start()].count("\n") + 1,
                               m.group(0)[:16] + "..."))
        for name, pat in WARN_PATTERNS:
            m = pat.search(text)
            if m:
                warns.append((rel, name, text[:m.start()].count("\n") + 1,
                              m.group(0)[:48]))
    return blocks, warns

SECRETS_TEMPLATE = """# AI-SecIntel 密钥与代理配置（模板）
# =====================================================================
# 本文件会被 .gitignore 排除，不会进仓库 / 安装包。
# 复制一份改名为 secrets.env 后填写；不填也能跑（问答走检索证据模板，零 token）。
#
# 用法：双击「设置密钥.bat」（Windows）或直接编辑本文件。
# =====================================================================

# ── 大模型（可选）：填了就有自然语言答案与智能体工具调用 ──────────────
AISEC_LLM_API_KEY=
AISEC_LLM_BASE_URL=https://api.deepseek.com/v1
AISEC_LLM_MODEL=deepseek-chat

# ── GitHub Token（可选）：填了 POC 搜索速率从 6/分钟 提到 30/分钟 ──────
AISEC_GITHUB_TOKEN=

# ── 代理（可选）：留空则由程序自动探测本机监听端口 ────────────────────
# 只有公司内网需要科学上网时才填，形如 http://127.0.0.1:7890
AISEC_PROXY=
"""


def _should_skip_dir(name, rel_path):
    if name in EXCLUDE_DIR_NAMES:
        return True
    # 顶层才排除（子目录里可能有同名业务目录）
    if rel_path == "" and name in EXCLUDE_TOP_LEVEL:
        return True
    return False


def collect(with_data=False):
    """收集要打包的文件，返回 [(绝对路径, 包内相对路径)]。"""
    out = []
    for d in INCLUDE_DIRS:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(
                n for n in dirnames
                if not _should_skip_dir(n, os.path.relpath(dirpath, ROOT).replace("\\", "/")))
            for fn in sorted(filenames):
                if os.path.splitext(fn)[1] in EXCLUDE_FILE_SUFFIX:
                    continue
                if fn in SECRET_FILES or fn in EXCLUDE_FILE_NAMES:
                    continue
                fp = os.path.join(dirpath, fn)
                rel = os.path.relpath(fp, ROOT).replace("\\", "/")
                out.append((fp, rel))
    missing = []
    for fn in INCLUDE_FILES:
        fp = os.path.join(ROOT, fn)
        if os.path.isfile(fp):
            out.append((fp, fn))
        else:
            missing.append(fn)
    if missing:
        # 静默跳过是危险的：README 里引用着这些文件，不打进去就成了死链，
        # 而且打包日志看上去一切正常，直到别人拿到包才发现。
        print("[!] 白名单中的以下文件在源目录不存在，不会随包分发：")
        for m in missing:
            print("     ", m)

    if with_data:
        base = os.path.join(ROOT, "data")
        if os.path.isdir(base):
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = [n for n in dirnames if n not in EXCLUDE_DIR_NAMES]
                for fn in filenames:
                    fp = os.path.join(dirpath, fn)
                    out.append((fp, os.path.relpath(fp, ROOT).replace("\\", "/")))
    return out


def build(out_path=None, with_data=False, list_only=False):
    files = collect(with_data=with_data)

    # ── 密钥闸门：写 zip 之前必须先过这一关 ────────────────────────────
    blocks, warns = scan_secrets(files)
    if warns:
        print("[!] 疑似本机绝对路径（非阻断，但建议清理）：%d 处" % len(warns))
        for rel, name, line, s in warns[:15]:
            print("     %s:%d  [%s]  %s" % (rel, line, name, s))
        if len(warns) > 15:
            print("     ... 其余 %d 处省略" % (len(warns) - 15))
    if blocks:
        print()
        print("!! 中止打包：以下文件疑似含有凭据，绝不能随包外发")
        for rel, name, line, s in blocks:
            print("     %s:%d  [%s]  %s" % (rel, line, name, s))
        print()
        print("   处理方式：脱敏后再打包，或把该文件加入 EXCLUDE_FILE_NAMES。")
        print("   注意：如果凭据已经随旧包外发过，请先去平台吊销，删文件救不回。")
        return 2
    if blocks == [] and warns == []:
        print("[✓] 密钥扫描通过：未发现凭据，未发现本机绝对路径")

    if list_only:
        print("待打包文件 %d 个：" % len(files))
        for _fp, rel in files:
            print("   ", rel)
        return 0

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    t0 = time.time()
    n = 0
    total = 0
    # ZIP_DEFLATED 压缩；大文件（语料）用 ZIP_STORED 反而更慢更大，这里统一压缩
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for fp, rel in files:
            try:
                zi = zipfile.ZipInfo(rel, date_time=time.localtime()[:6])
                zi.compress_type = zipfile.ZIP_DEFLATED
                # 关键：zipfile 默认不写权限位，macOS 解压后 .command 不可执行
                if rel.endswith((".sh", ".command")):
                    zi.external_attr = 0o755 << 16
                else:
                    zi.external_attr = 0o644 << 16
                with open(compat.long_path(fp), "rb") as f:
                    data = f.read()
                z.writestr(zi, data)
                total += len(data)
                n += 1
            except Exception as _e:
                print("  !! 跳过 %s：%s" % (rel, _e))

        # .command 副本（macOS 双击入口）
        for src, dst in COMMAND_COPIES:
            sfp = os.path.join(ROOT, src)
            if not os.path.isfile(sfp):
                continue
            with open(sfp, "rb") as f:
                body = f.read()
            zi = zipfile.ZipInfo(dst, date_time=time.localtime()[:6])
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o755 << 16
            z.writestr(zi, body)

        # 密钥模板（提醒用，不含真实密钥）
        zi = zipfile.ZipInfo("secrets.env.example", date_time=time.localtime()[:6])
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = 0o644 << 16
        z.writestr(zi, SECRETS_TEMPLATE.encode("utf-8"))

    size = os.path.getsize(out_path) if os.path.isfile(out_path) else 0
    dt = time.time() - t0
    print("=" * 68)
    print("  安装包已生成")
    print("=" * 68)
    print("  路径：%s" % out_path)
    print("  文件：%d 个（原始 %.1f MB）→ 压缩后 %.2f MB · 耗时 %.1fs"
          % (n, total / 1024.0 / 1024.0, size / 1024.0 / 1024.0, dt))
    print("  含语料：%s" % ("是" if with_data else "否（安装后需联网抓取或拷入 data/）"))
    print("=" * 68)
    print("  交付方式：解压后按 README_安装.md 双击对应系统的安装脚本即可")
    return 0


def main():
    ap = argparse.ArgumentParser(description="打包 AI-SecIntel 安装包")
    ap.add_argument("--with-data", action="store_true", help="连 data/ 语料一起打（1.8GB+，很慢）")
    ap.add_argument("--out", default="", help="输出 zip 路径")
    ap.add_argument("--list", action="store_true", help="只列清单不打包")
    args = ap.parse_args()

    if args.out:
        out = args.out
    else:
        stamp = time.strftime("%Y%m%d")
        suffix = "_含语料" if args.with_data else ""
        out = os.path.join(ROOT, "dist",
                           "AI-SecIntel_v%s_安装包_%s%s.zip" % (VERSION, stamp, suffix))
    return build(out, with_data=args.with_data, list_only=args.list)


if __name__ == "__main__":
    raise SystemExit(main())
