# -*- coding: utf-8 -*-
"""验证 LLM Key：① 文件解析 ② SDK 依赖 ③ 加载链路 ④ 直连有效性（1 token）

密钥值一律不打印，只打印长度/模型名。
"""
import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
try:
    import loopback
    loopback.enable()
except Exception:  # noqa: BLE001
    pass

kv = {}
with open(os.path.join(ROOT, "secrets.env"), encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip().lstrip("\ufeff")
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        kv[k.strip()] = v.strip().strip('"').strip("'")

key = kv.get("AISEC_LLM_API_KEY", "")
base = kv.get("AISEC_LLM_BASE_URL", "")
model = kv.get("AISEC_LLM_MODEL", "") or "deepseek-chat"
print("① 文件解析: key 长度=%d（前缀 %s…）｜base=%s｜model=%s"
      % (len(key), key[:3], base, model))

try:
    import openai
    print("② openai SDK: %s" % getattr(openai, "__version__", "?"))
    _has_sdk = True
except Exception as e:  # noqa: BLE001
    print("② openai SDK 不可用: %s" % e)
    _has_sdk = False

try:
    import server as srv
    loaded = srv._load_secrets_env()
    print("③ _load_secrets_env() 补载: %s" % (loaded,))
    print("③ os.environ 中 AISEC_LLM_API_KEY 长度: %d"
          % len(os.environ.get("AISEC_LLM_API_KEY") or ""))
    print("③ os.environ 中 BASE_URL: %s" % os.environ.get("AISEC_LLM_BASE_URL"))
except Exception as e:  # noqa: BLE001
    print("③ 加载链路检查失败: %r" % e)

print("④ 直连 API 实测（max_tokens=1）…")
t0 = time.time()
try:
    if _has_sdk:
        from openai import OpenAI
        client = OpenAI(base_url=base or "https://api.deepseek.com",
                        api_key=key, max_retries=0)
        resp = client.chat.completions.create(
            model=model, messages=[{"role": "user", "content": "ping"}],
            max_tokens=1, timeout=30)
        print("④ OK（SDK） %.1fs · model=%s" % (time.time() - t0, resp.model))
    else:
        body = json.dumps({"model": model,
                           "messages": [{"role": "user", "content": "ping"}],
                           "max_tokens": 1}).encode()
        req = urllib.request.Request(
            (base or "https://api.deepseek.com").rstrip("/") + "/chat/completions",
            data=body,
            headers={"Authorization": "Bearer " + key,
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
        print("④ OK（raw） %.1fs · model=%s" % (time.time() - t0, d.get("model")))
except Exception as e:  # noqa: BLE001
    print("④ 直连 API 失败: %r" % e)
