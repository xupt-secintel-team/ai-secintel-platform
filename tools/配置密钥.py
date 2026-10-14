# -*- coding: utf-8 -*-
"""
配置密钥.py —— 把 LLM Key / GitHub Token / 代理 / 邮件 写进本机 secrets.env
========================================================================
由「设置密钥.bat」双击调用（也可以直接  py -3 tools/配置密钥.py）。

设计原则（都是为了"密钥不落到不该落的地方"）：
  · 只写本机 secrets.env，文件已被 .gitignore 排除；
  · 不打印任何密钥值，只报"填写了 / 没填"；
  · 输入内容不做拼接、不写进任何代码文件、不发网络请求；
  · 每项直接回车 = 保留原值（首次则跳过），可反复重跑；
  · ★ 就地更新：只改本向导负责的那些行，其余行（注释、AISEC_EMBED_THREADS
    这类手工加的配置）原样保留 —— 早期版本是整体覆写，跑一次就会把
    别处写进去的配置和注释全删掉，属于数据丢失，已修正。
  · 写完后自查一遍格式（每行必须 NAME=value，值里不许有换行），不合法就报错不落盘。
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ENV_PATH = os.path.join(ROOT, "secrets.env")

KEYS = [
    ("AISEC_LLM_API_KEY", "大模型 API Key（DeepSeek 等）"),
    ("AISEC_LLM_BASE_URL", "接口地址"),
    ("AISEC_LLM_MODEL", "模型名"),
    ("AISEC_GITHUB_TOKEN", "GitHub Token（POC 搜索提速）"),
    ("AISEC_PROXY", "代理地址"),
    ("AISEC_SMTP_HOST", "SMTP 服务器"),
    ("AISEC_SMTP_PORT", "SMTP 端口"),
    ("AISEC_SMTP_USER", "发件邮箱账号"),
    ("AISEC_SMTP_PASS", "SMTP 授权码"),
    ("AISEC_SMTP_FROM", "发件人显示地址"),
    ("AISEC_SMTP_SSL", "强制 SSL（1/0）"),
]
DEFAULTS = {
    "AISEC_LLM_BASE_URL": "https://api.deepseek.com",
    "AISEC_LLM_MODEL": "deepseek-chat",
}
# 值可以明文回显的键（不是密钥）；其余只显示"已填写（N 个字符）"
PLAIN_SHOW = {
    "AISEC_LLM_BASE_URL", "AISEC_LLM_MODEL", "AISEC_PROXY",
    "AISEC_SMTP_HOST", "AISEC_SMTP_PORT", "AISEC_SMTP_USER",
    "AISEC_SMTP_FROM", "AISEC_SMTP_SSL",
}
# 输入时不回显的键（授权码 / API Key 这类被旁人瞄一眼就麻烦的）
SECRET_KEYS = {"AISEC_LLM_API_KEY", "AISEC_GITHUB_TOKEN", "AISEC_SMTP_PASS"}

MANAGED = {k for k, _ in KEYS}
LINE_RE = re.compile(r"^[A-Z_][A-Z0-9_]*=.+$")
_KV_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")


def read_env():
    """读回已有配置（键 → 值），用于"回车保留原值"。"""
    cur = {}
    if not os.path.exists(ENV_PATH):
        return cur
    with open(ENV_PATH, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip().lstrip("\ufeff")
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cur[k.strip()] = v.strip()
    return cur


def read_env_lines():
    """读回 secrets.env 的原始行（含注释与空行），用于就地更新。"""
    if not os.path.exists(ENV_PATH):
        return []
    with open(ENV_PATH, encoding="utf-8", errors="replace") as f:
        return [ln.rstrip("\r\n") for ln in f]


def _split_kv(line):
    """从一行里取 key；不是 NAME=value 就返回 None（注释/空行）。"""
    s = line.strip().lstrip("\ufeff")
    if not s or s.startswith("#"):
        return None
    m = _KV_RE.match(s)
    return m.group(1) if m else None


def ask(key, label, cur, hint=""):
    old = cur.get(key, "")
    shown = "已填写" if old else ("默认 " + DEFAULTS[key] if key in DEFAULTS and not old else "未填写")
    tip = f"（当前：{shown}）" if old else (f"（回车用默认 {DEFAULTS[key]}）" if key in DEFAULTS else "（回车跳过）")
    prompt = f"  {label} {tip}{hint}: "
    try:
        if key in SECRET_KEYS:
            # 授权码不回显：现场可能有人看着屏幕
            import getpass
            try:
                raw = getpass.getpass(prompt)
            except Exception:  # noqa: BLE001  某些终端不支持，退回普通输入
                raw = input(prompt)
        else:
            raw = input(prompt)
    except EOFError:
        raw = ""
    v = (raw or "").strip().strip('"').strip("'")
    if not v:
        return old if old else DEFAULTS.get(key, "")
    return v


def main():
    print("=" * 60)
    print("  AI-SecIntel 2.0  本机密钥配置")
    print("=" * 60)
    print()
    print("  · 只写本机 secrets.env（已在 .gitignore 里，不会进仓库、不会上传）")
    print("  · 不显示、不打印你的密钥；每项回车 = 保留原值 / 跳过")
    print("  · 只改本向导负责的字段，文件里其他内容（注释、自定义配置）原样保留")
    print("  · 想清空某项：输入一个减号 -   ；想全部清空：直接删掉 secrets.env")
    print()

    cur = read_env()
    if cur:
        print(f"  发现已有配置：{'、'.join(cur.keys())}")
        print()

    out = {}
    print(" ① 大模型（配了问答才有自然语言答案）")
    out["AISEC_LLM_API_KEY"] = ask("AISEC_LLM_API_KEY", "大模型 API Key", cur)
    out["AISEC_LLM_BASE_URL"] = ask("AISEC_LLM_BASE_URL", "接口地址    ", cur)
    out["AISEC_LLM_MODEL"] = ask("AISEC_LLM_MODEL", "模型名      ", cur)
    print()
    print(" ② GitHub Token（可选，POC 完整搜索 10/分钟 → 30/分钟）")
    out["AISEC_GITHUB_TOKEN"] = ask("AISEC_GITHUB_TOKEN", "GitHub Token", cur)
    print()
    print(" ③ 代理（可选；本机开着 Clash 时留空会自动探测 7890/7897）")
    out["AISEC_PROXY"] = ask("AISEC_PROXY", "代理地址    ", cur)
    print()
    print(" ④ 邮件投递（可选：CMDB 报告发到邮箱；不填则该功能自动隐藏）")
    print("     ★ QQ / 163 / Foxmail 填【授权码】，不是登录密码！")
    print("       QQ 邮箱 → 设置 → 账户 → POP3/IMAP/SMTP 服务 → 开启 → 生成授权码")
    print()
    out["AISEC_SMTP_HOST"] = ask("AISEC_SMTP_HOST", "SMTP 服务器 ", cur, "（如 smtp.qq.com）")
    out["AISEC_SMTP_PORT"] = ask("AISEC_SMTP_PORT", "SMTP 端口   ", cur, "（回车=按域名猜：QQ/163=465、Gmail=587）")
    out["AISEC_SMTP_USER"] = ask("AISEC_SMTP_USER", "发件邮箱账号", cur, "（完整地址，如 12345678@qq.com）")
    out["AISEC_SMTP_PASS"] = ask("AISEC_SMTP_PASS", "SMTP 授权码 ", cur, "（输入时不回显）")
    out["AISEC_SMTP_FROM"] = ask("AISEC_SMTP_FROM", "发件人显示地址", cur, "（回车=同账号）")
    out["AISEC_SMTP_SSL"] = ask("AISEC_SMTP_SSL", "强制 SSL    ", cur, "（回车=自动）")
    print()

    # "-" = 显式清空；其余按输入/保留取值
    final = {}
    for k, _ in KEYS:
        v = (out.get(k) or "").strip()
        final[k] = "" if v == "-" else v

    # 落盘前自查：值里不许有换行/回车，非空值必须符合 NAME=value
    for k, v in final.items():
        if "\n" in v or "\r" in v:
            print(f"[!] {k} 的值里含换行，已拒绝写入（请粘贴单行值）")
            return 2
        if v and not LINE_RE.match(f"{k}={v}"):
            print(f"[!] {k} 的值不合法，已拒绝写入")
            return 2

    old_lines = read_env_lines()
    lines = []
    seen = set()
    for raw in old_lines:
        k = _split_kv(raw)
        if k in MANAGED:
            seen.add(k)
            lines.append(f"{k}={final[k]}")      # 就地替换（含清空成 k=）
        else:
            lines.append(raw)                    # 注释 / 未托管配置：原样保留
    added = False
    for k, _ in KEYS:
        if k not in seen and final[k]:
            if not added and lines:
                lines.append("")
                added = True
            lines.append(f"{k}={final[k]}")
    if not old_lines:
        lines = [
            "# AI-SecIntel 2.0 本机密钥（自动生成：设置密钥.bat）",
            "# 每行 NAME=value，不加 set、不加引号；已在 .gitignore 里排除，切勿提交",
        ] + lines
    while lines and not lines[-1].strip():
        lines.pop()

    with open(ENV_PATH, "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(lines) + "\n")

    print("-" * 60)
    print(f"  已写入：{ENV_PATH}")
    for k, label in KEYS:
        v = final.get(k, "")
        if not v:
            state = "未配置"
        elif k in PLAIN_SHOW:
            state = f"已配置（{v}）"
        else:
            state = f"已填写（{len(v)} 个字符，值不显示）"
        print(f"   {label:28s}：{state}")
    print("-" * 60)
    print("  下一步：双击「启动服务.bat」——启动时会打印「已加载本机 secrets.env」")
    print("  邮件功能：启动后可在 CMDB 分析页勾选「发送到邮箱」，或在 /api/cmdb_scan/mail 查看状态")
    print("  安全提醒：secrets.env 是本机明文文件，别拷给别人、别放共享盘/仓库。")
    print()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[已取消，未写入]")
        sys.exit(1)
