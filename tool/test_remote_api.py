#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TVBox 远程解密接口 - 通用请求模式测试脚本
"""

import sys
import os
import json
import time
import base64
import binascii
import requests
from urllib.parse import urlparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ==================== 基础解密与校验逻辑 ====================

def ab2str(data: bytes) -> str:
    return data.decode('utf-8', errors='ignore')

def decrypt_tvbox_text(content: str) -> str:
    data = content.strip()
    if not all(c in "0123456789abcdefABCDEF" for c in data):
        raise ValueError("不是有效的十六进制")
    marker = "2324"
    idx = data.find(marker)
    if idx == -1:
        raise ValueError("未找到标记 #$")
    
    prefix_hex = data[:idx + len(marker)]
    cipher_hex = data[idx + len(marker):-26]
    iv_hex = data[-26:]

    if prefix_hex.startswith("2423"):
        key_hex = prefix_hex[4:-4]
    else:
        key_hex = prefix_hex[:-len(marker)]

    key_raw = bytes.fromhex(key_hex).decode('utf-8', errors='ignore')
    iv_raw = bytes.fromhex(iv_hex).decode('utf-8', errors='ignore')

    key_bytes = key_raw.ljust(16, '0').encode('utf-8')[:16]
    iv_bytes = iv_raw.ljust(16, '0').encode('utf-8')[:16]

    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    ciphertext = binascii.unhexlify(cipher_hex)
    plaintext_padded = cipher.decrypt(ciphertext)

    try:
        plaintext = unpad(plaintext_padded, AES.block_size).decode('utf-8', errors='ignore')
    except ValueError:
        plaintext = plaintext_padded.decode('utf-8', errors='ignore')
    return plaintext

def process_data_and_check(data: bytes) -> str:
    """本地解密并校验是否包含 sites 或 spider"""
    text = ab2str(data).strip()
    
    # 如果是密文，尝试解密
    if all(c in "0123456789abcdefABCDEF" for c in text.replace(' ', '')) and '2324' in text:
        print("    [本地处理] 检测到密文，尝试解密...")
        text = decrypt_tvbox_text(text)
    else:
        print("    [本地处理] 检测到明文，直接校验...")

    if "sites" not in text and "spider" not in text:
        raise ValueError("解密或校验失败：内容不包含 sites/spider 关键字")
        
    return text

def _is_challenge(content: bytes) -> bool:
    head = content[:600]
    return b"_guard/html.js" in head or b"js=p456" in head

# ==================== 核心请求引擎 ====================

def _build_and_send(endpoint: str, mode: str, target_url: str) -> bytes:
    """根据模式构建并发起请求"""
    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
    }
    
    parsed = urlparse(endpoint)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    base_headers["Origin"] = origin
    base_headers["Referer"] = origin + "/"

    print(f"    -> 发送请求 [模式: {mode}] 到 {endpoint}")

    if mode == "GET_QUERY":
        resp = requests.get(endpoint, params={"url": target_url}, headers=base_headers, timeout=30)
    elif mode == "GET_PATH":
        b64_url = base64.b64encode(target_url.encode()).decode().rstrip("=")
        resp = requests.get(f"{endpoint.rstrip('/')}/{b64_url}", headers=base_headers, timeout=30)
    elif mode == "POST_FORM":
        resp = requests.post(endpoint, data={"url": target_url}, headers=base_headers, timeout=30)
    elif mode == "POST_JSON":
        base_headers["Content-Type"] = "application/json"
        resp = requests.post(endpoint, json={"url": target_url}, headers=base_headers, timeout=30)
    elif mode == "POST_JSON_NESTED":
        base_headers["Content-Type"] = "application/json"
        payload = {"action": "fetch", "params": {"url": target_url}, "ts": int(time.time())}
        resp = requests.post(endpoint, json=payload, headers=base_headers, timeout=30)
    elif mode == "POST_JSON_ARRAY":
        base_headers["Content-Type"] = "application/json"
        resp = requests.post(endpoint, json=[target_url], headers=base_headers, timeout=30)
    else:
        raise NotImplementedError(f"未知模式: {mode}")

    resp.raise_for_status()
    if _is_challenge(resp.content):
        raise RuntimeError("接口返回了 JS 挑战页")
    if not resp.content.strip():
        raise RuntimeError("接口返回空内容")
        
    return resp.content

def test_remote_configs(target_url: str, configs: list):
    """遍历测试所有配置"""
    print(f"\n🎯 目标地址: {target_url}")
    print(f"📦 测试接口数量: {len(configs)}\n")

    for idx, config in enumerate(configs):
        name = config.get("name", f"接口_{idx+1}")
        url = config.get("url")
        mode = config.get("mode", "AUTO").upper()

        print(f"▶ [{idx+1}/{len(configs)}] 正在测试: {name}")
        if not url:
            print("    ❌ 缺少 url 字段")
            continue

        modes_to_test = [mode]
        if mode == "AUTO":
            # 自动探测的优先级（最不容易被拦截的放前面）
            modes_to_test = ["POST_JSON", "POST_FORM", "GET_QUERY"]

        success = False
        for m in modes_to_test:
            try:
                # 1. 请求数据
                content = _build_and_send(url, m, target_url)
                
                # 2. 试解密校验
                final_text = process_data_and_check(content)
                
                # 3. 成功，写入本地文件
                out_file = f"test_output_{idx+1}.json"
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(final_text)
                
                print(f"    ✅ 成功！(模式: {m}) 数据已保存至 {out_file}")
                success = True
                break # 成功后跳出模式循环
                
            except Exception as e:
                print(f"    ❌ 失败 (模式: {m}): {str(e)[:80]}")
        
        if not success:
            print(f"    ❌ 接口 {name} 所有模式均失败\n")
        else:
            print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python test_remote_api.py <目标URL> [配置文件.json]")
        print("  如果不传配置文件，将使用脚本内预设的测试数据。")
        sys.exit(1)

    target = sys.argv[1]
    
    # 默认测试配置
    test_configs = [
        # 1. 159 接口 (自动识别模式)
        {"name": "159接口", "url": "http://159.75.152.41:88/api.php", "mode": "GET_QUERY"},
        # 2. y456y 接口 (嵌套 JSON)
        {"name": "y456y接口", "url": "http://www.y456y.com/helper/api.php", "mode": "POST_JSON_NESTED"},
        # 3. 2015888 接口 (表单 POST)
        {"name": "2015888接口", "url": "http://2015888.xyz/jiemi/get_jiemi.php", "mode": "POST_FORM"},
        # 4. 一个未知的新接口（自动探测）
        # {"name": "神秘接口", "url": "http://xxx.xxx/api", "mode": "AUTO"}
    ]

    # 如果命令行传了配置文件，则读取并覆盖
    if len(sys.argv) >= 3 and os.path.exists(sys.argv[2]):
        with open(sys.argv[2], "r", encoding="utf-8") as f:
            test_configs = json.load(f)

    test_remote_configs(target, test_configs)
