import sys
import os
import base64
import binascii
import time
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ========== 工具函数 ==========

def ab2str(data: bytes) -> str:
    """字节转 UTF-8 字符串"""
    return data.decode('utf-8', errors='ignore')

def str2ab(text: str) -> bytes:
    """字符串转 UTF-8 字节"""
    return text.encode('utf-8')

def b64decode_bytes(b64_str: str) -> bytes:
    """Base64 解码"""
    return base64.b64decode(b64_str.strip())

# ========== 图片提取 ==========

def extract_config_from_image_data(data: bytes) -> bytes:
    """
    从图片二进制数据中提取配置（标记 '**' 之后的内容，Base64 解码）
    """
    marker = b'**'
    pos = data.find(marker)
    if pos == -1:
        raise ValueError("未找到标记 '**'，该图片可能不是由本工具生成。")
    encoded = data[pos + len(marker):]
    # 转为 ASCII 字符串（Base64）
    try:
        encoded_str = encoded.decode('ascii').strip()
    except UnicodeDecodeError:
        encoded_str = encoded.decode('utf-8', errors='ignore').strip()
    return base64.b64decode(encoded_str)

# ========== AES 解密 ==========

def decrypt_tvbox_text(content: str) -> str:
    """
    解密 TVBox 加密文本（十六进制格式）
    """
    data = content.strip()
    if not all(c in "0123456789abcdefABCDEF" for c in data):
        raise ValueError("输入不是有效的十六进制字符串")
    marker = "2324"
    idx = data.find(marker)
    if idx == -1:
        raise ValueError("未找到标记 #$，格式不正确")

    prefix_hex = data[:idx + len(marker)]
    cipher_hex = data[idx + len(marker):-26]
    iv_hex = data[-26:]

    if prefix_hex.startswith("2423"):
        key_hex = prefix_hex[4:-4]
    else:
        key_hex = prefix_hex[:-len(marker)]

    key_raw = bytes.fromhex(key_hex).decode('utf-8', errors='ignore')
    iv_raw = bytes.fromhex(iv_hex).decode('utf-8', errors='ignore')

    key_padded = key_raw.ljust(16, '0')
    iv_padded = iv_raw.ljust(16, '0')

    key_bytes = key_padded.encode('utf-8')
    iv_bytes = iv_padded.encode('utf-8')

    if len(key_bytes) < 16:
        key_bytes = key_bytes + b'\x00' * (16 - len(key_bytes))
    if len(iv_bytes) < 16:
        iv_bytes = iv_bytes + b'\x00' * (16 - len(iv_bytes))

    cipher = AES.new(key_bytes[:16], AES.MODE_CBC, iv_bytes[:16])
    ciphertext = binascii.unhexlify(cipher_hex)
    plaintext_padded = cipher.decrypt(ciphertext)

    try:
        plaintext = unpad(plaintext_padded, AES.block_size).decode('utf-8', errors='ignore')
    except ValueError:
        plaintext = plaintext_padded.decode('utf-8', errors='ignore')
    return plaintext

# ========== 自动处理流程 ==========

def process_data(data: bytes) -> str:
    """
    自动识别并处理数据：
      - 如果是图片（含 '**'），提取配置。
      - 如果提取结果或原始数据是加密十六进制（含 '2324'），解密。
      - 否则直接返回文本（假定为 JSON）。
      - 新增：进行明文有效性校验。
    """
    # 1. 检查是否为图片（含有 '**' 标记）
    if b'**' in data:
        try:
            extracted = extract_config_from_image_data(data)
            # 提取结果可能是二进制文本，尝试转为字符串
            text = ab2str(extracted)
            # 检查是否加密格式（十六进制且含 '2324'）
            text_clean = text.strip()
            if all(c in "0123456789abcdefABCDEF" for c in text_clean.replace(' ', '')) and '2324' in text_clean:
                print("🔐 检测到加密配置，正在解密...")
                decrypted = decrypt_tvbox_text(text_clean)
                # ===== 校验 =====
                if "sites" not in decrypted and "spider" not in decrypted:
                    raise ValueError("解密后缺少 sites/spider")
                return decrypted
            else:
                print("✅ 提取到明文配置")
                return text
        except Exception as e:
            print(f"⚠️ 图片提取失败: {e}，尝试按普通文本处理...")
            # 降级处理

    # 2. 不是图片，或提取失败，尝试作为文本处理
    try:
        text = ab2str(data).strip()
        # 检查是否为加密格式
        if all(c in "0123456789abcdefABCDEF" for c in text.replace(' ', '')) and '2324' in text:
            print("🔐 检测到加密文本，正在解密...")
            decrypted = decrypt_tvbox_text(text)
            # ===== 校验 =====
            if "sites" not in decrypted and "spider" not in decrypted:
                raise ValueError("解密后缺少 sites/spider")
            return decrypted
        else:
            print("✅ 输入为明文配置")
            # ===== 校验 =====
            if "sites" not in text and "spider" not in text:
                raise ValueError("明文缺少 sites/spider")
            return text
    except Exception as e:
        raise ValueError(f"无法识别数据格式: {e}")

# ========== 网络下载 ==========

# 原有：UA 轮换配置（每项为 User-Agent, X-Requested-With）
UA_池 = [
    ("okhttp/3.15",     "com.iptvbox"),
    ("okhttp/4.9.3",    "com.iptvbox"),
    ("TVBox/1.0.0",     "com.iptvbox"),
    ("okhttp/3.12.0",   "com.iptvbox"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", ""),
]
UA重试次数 = 2
UA重试间隔 = 0.5

# ===== 新增：E 方案开关与回退配置 =====
ENABLE_FALLBACK = os.environ.get("TVBOX_FALLBACK", "0") == "1"

# 配置两个远程服务地址
REMOTE_FALLBACK_URL_1 = os.environ.get("TVBOX_REMOTE_FALLBACK_URL_1", "").strip()
REMOTE_FALLBACK_URL_2 = os.environ.get("TVBOX_REMOTE_FALLBACK_URL_2", "").strip()


def download_url(url: str) -> bytes:
    """从 URL 下载数据，返回字节"""
    last_err = None
    for ua, xrw in UA_池:
        for attempt in range(UA重试次数):
            try:
                headers = {
                    "User-Agent": ua,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Connection": "keep-alive",
                }
                if xrw:
                    headers["X-Requested-With"] = xrw
                resp = requests.get(url, headers=headers, timeout=30)

                if resp.status_code != 200:
                    print(f"  🔍 [诊断] UA={ua} 尝试{attempt + 1}: "
                          f"状态码={resp.status_code} {resp.reason} | "
                          f"响应体长度={len(resp.content)}")
                    if attempt == 0:
                        print(f"  🔍 [诊断] 请求头: {dict(resp.request.headers)}")
                        print(f"  🔍 [诊断] 响应头: {dict(resp.headers)}")
                        try:
                            snippet = resp.text[:500].replace("\r", "\\r").replace("\n", "\\n")
                            print(f"  🔍 [诊断] 响应体前500字符: {snippet}")
                        except Exception as diag_err:
                            print(f"  🔍 [诊断] 响应体解码失败: {diag_err}")

                resp.raise_for_status()
                print(f"  ✓ 下载成功 (UA={ua}, XRW={xrw or '-'})")
                return resp.content
            except Exception as e:
                last_err = e
                print(f"  ✗ UA={ua} 第{attempt + 1}次失败: {e}")
                if attempt < UA重试次数 - 1:
                    time.sleep(UA重试间隔)
    raise RuntimeError(f"所有 UA 均失败，最后错误: {last_err}")


# ===== 新增：E 方案回退链 =====

def _is_challenge(content: bytes) -> bool:
    """判断返回内容是否为 JS 挑战页"""
    head = content[:600]
    return b"_guard/html.js" in head or b"js=p456" in head


def _download_via_curl_cffi(url: str) -> bytes:
    """回退层 1：curl_cffi 伪装 Chrome TLS 指纹"""
    try:
        from curl_cffi import requests as cffi_requests
    except ImportError:
        raise RuntimeError("curl_cffi 未安装，跳过该回退层")

    last_err = None
    for target in ("chrome124", "chrome131"):
        try:
            resp = cffi_requests.get(url, impersonate=target, timeout=30)
            if resp.status_code == 200 and not _is_challenge(resp.content):
                print(f"  ✓ 回退层 curl_cffi 成功 (impersonate={target})")
                return resp.content
            last_err = RuntimeError(
                f"impersonate={target} 返回 {resp.status_code}，"
                f"内容前 200 字节: {resp.content[:200]!r}"
            )
        except Exception as e:
            last_err = e
    raise RuntimeError(f"curl_cffi 所有 impersonate 目标均未通过，最后错误: {last_err}")


def _download_via_remote_159(url: str) -> bytes:
    """回退层 2：远程服务 1 (159.75.152.41:88)"""
    if not REMOTE_FALLBACK_URL_1:
        raise RuntimeError("未配置 TVBOX_REMOTE_FALLBACK_URL_1，跳过")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Referer": "http://159.75.152.41:88/",
    }
    # GET 请求，参数 ou
    resp = requests.get(REMOTE_FALLBACK_URL_1, params={"ou": url}, headers=headers, timeout=120)
    resp.raise_for_status()
    if _is_challenge(resp.content) or not resp.content.strip():
        raise RuntimeError("服务1返回挑战页或空内容")
    return resp.content


def _download_via_remote_y456y(url: str) -> bytes:
    """回退层 3：远程服务 2 (www.y456y.com/helper/api.php)"""
    if not REMOTE_FALLBACK_URL_2:
        raise RuntimeError("未配置 TVBOX_REMOTE_FALLBACK_URL_2，跳过")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Origin": "http://www.y456y.com",
        "Referer": "http://www.y456y.com/helper/",
        "Content-Type": "application/json"
    }
    payload = {
        "action": "fetch_content",
        "params": {
            "url": url
        },
        "ts": int(time.time())
    }
    # POST 请求，JSON 嵌套结构
    resp = requests.post(REMOTE_FALLBACK_URL_2, json=payload, headers=headers, timeout=120)
    resp.raise_for_status()
    if _is_challenge(resp.content) or not resp.content.strip():
        raise RuntimeError("服务2返回挑战页或空内容")
    return resp.content


def download_url_with_fallback(url: str) -> bytes:
    """先走原有下载，失败后按顺序尝试回退层，并由本地模板试解密验货"""
    # 第 0 层：原有逻辑，一行不改
    try:
        return download_url(url)
    except Exception as e:
        print(f"⚠ 原有下载方案失败: {e}")
        print("→ 进入回退链...")

    last_err = None
    fallbacks = [
        ("curl_cffi", _download_via_curl_cffi),
        ("远程_159",  _download_via_remote_159),
        ("远程_y456y", _download_via_remote_y456y),
    ]
    
    for name, fn in fallbacks:
        try:
            # 1. 接口只负责下载，把内容拿回来
            content = fn(url)
            
            # 2. 试解密校验：调用本地 process_data
            print(f"  🔍 正在校验 {name} 下载的数据...")
            process_data(content)  # 如果解出来的乱码没有 sites/spider，会在这里抛出异常
            
            # 3. 如果校验通过，说明数据有效
            print(f"  ✓ 采用 {name} 的下载数据")
            return content
            
        except Exception as e:
            last_err = e
            print(f"  ✗ {name} 校验未通过或被跳过: {e}")

    raise RuntimeError(f"原有方案与所有回退层均失败，最后错误: {last_err}")


# ========== 主入口 ==========

def main():
    if len(sys.argv) < 2:
        print("用法: python a.py <URL或本地文件路径> [输出文件名]")
        print("  例如: python a.py https://example.com/config.bmp my_config.json")
        sys.exit(1)

    source = sys.argv[1]
    out_name = sys.argv[2] if len(sys.argv) > 2 else "config.json"

    # 1. 获取数据
    if source.startswith(('http://', 'https://')):
        print(f"📥 正在从 URL 下载: {source}")
        try:
            if ENABLE_FALLBACK:
                print("🔁 回退链已启用 (TVBOX_FALLBACK=1)")
                data = download_url_with_fallback(source)
            else:
                data = download_url(source)
            print("✅ 下载成功")
        except Exception as e:
            print(f"❌ 下载失败: {e}")
            sys.exit(1)
    else:
        # 本地文件
        print(f"📂 读取本地文件: {source}")
        try:
            with open(source, 'rb') as f:
                data = f.read()
            print("✅ 读取成功")
        except Exception as e:
            print(f"❌ 读取文件失败: {e}")
            sys.exit(1)

    # 2. 自动处理
    try:
        result_text = process_data(data)
        # 3. 保存结果
        with open(out_name, 'w', encoding='utf-8') as f:
            f.write(result_text)
        print(f"🎉 处理完成，结果已保存至: {out_name}")
    except Exception as e:
        print(f"❌ 处理失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
