#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TVBOX 远程拉取测试单文件版

用法：
    python test.py <URL或本地文件路径> <输出文件名>

环境变量：
    TVBOX_REMOTE_CONFIGS  JSON 数组，每项一个服务：
        {"name": "159",   "url": "http://159.75.152.41:88/api.php",        "mode": "AUTO"}
        {"name": "y456y", "url": "http://www.y456y.com/helper/api.php",    "mode": "POST_JSON_NESTED"}

    mode 取值：
        AUTO              自动探测全部格式（推荐给新地址）
        GET_QUERY_URL     GET  ?url=
        GET_QUERY_OU      GET  ?ou=
        GET_PATH_B64      GET  /<base64url>
        POST_FORM         POST form  url=
        POST_JSON         POST JSON 平铺 {"url": ...}
        POST_JSON_NESTED  POST JSON 嵌套 {"action":"fetch_content","params":{"url":...},"ts":...}
        POST_JSON_ARRAY   POST JSON 数组 ["<url>"]
        （也可以写成列表，如 ["POST_JSON_NESTED","POST_FORM"]，按顺序尝试）

    可选字段：headers（自定义请求头）、enabled（false 可临时停用）、timeout。

其他环境变量（可选）：
    TVBOX_DIRECT_FIRST   1/0，是否先走直连再回退（默认 1）
    TVBOX_DEADLINE       总预算秒数（默认 60）
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass

import requests

try:                                   # 十六进制加密配置需要 AES
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    _HAS_AES = True
except Exception:                      # pragma: no cover
    _HAS_AES = False

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
PROBE_TIMEOUT = 8.0
FETCH_TIMEOUT = 120.0
REFETCH = os.environ.get("TVBOX_REFETCH", "1") != "0"   # 命中后是否长超时重拉


# ============================================================ 请求格式

@dataclass(frozen=True)
class Fmt:
    key: str                       # mode 名
    method: str = "GET"
    where: str = "query"           # query | form | json | json_array | path
    param: str = "url"
    action: str | None = None      # 非空 => JSON 嵌套结构
    encode: str = "none"           # none | quote | b64url

    def encode_target(self, target: str) -> str:
        if self.encode == "quote":
            return urllib.parse.quote(target, safe="")
        if self.encode == "b64url":
            return base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
        return target


FMTS: dict[str, Fmt] = {
    "GET_QUERY_URL":     Fmt("GET_QUERY_URL", "GET", "query", "url"),
    "GET_QUERY_OU":      Fmt("GET_QUERY_OU", "GET", "query", "ou"),
    "GET_PATH_B64":      Fmt("GET_PATH_B64", "GET", "path", "url", None, "b64url"),
    "POST_FORM":         Fmt("POST_FORM", "POST", "form", "url", None, "quote"),
    "POST_JSON":         Fmt("POST_JSON", "POST", "json", "url"),
    "POST_JSON_NESTED":  Fmt("POST_JSON_NESTED", "POST", "json", "url", "fetch_content"),
    "POST_JSON_ARRAY":   Fmt("POST_JSON_ARRAY", "POST", "json_array", "url"),
}

AUTO_ORDER = ["GET_QUERY_URL", "GET_QUERY_OU", "POST_FORM", "POST_JSON",
              "POST_JSON_NESTED", "POST_JSON_ARRAY", "GET_PATH_B64"]


# ============================================================ 环境变量解析

def _normalize_json(text: str) -> str:
    """把常见的"手工录入污染"修正掉，且不破坏字符串内部的内容。

    处理：BOM、全角逗号/分号/冒号、中文引号、单引号、尾逗号。
    只在字符串外部替换标点，因此 URL、header 内部不会被改坏。
    """
    text = text.lstrip("\ufeff").strip()
    out = []
    quote = None      # None / '"' / "'"
    esc = False       # 上一个字符是反斜杠

    for ch in text:
        if esc:
            out.append(ch)
            esc = False
            continue
        if quote is None:
            if ch == '"':
                quote = '"'
                out.append('"')
            elif ch in ("'", "“"):           # 中文/单引号一律归一成双引号
                quote = '"'
                out.append('"')
            elif ch in "，；、":
                out.append(",")
            elif ch == "：":
                out.append(":")
            elif ch == "”":
                out.append('"')
            else:
                out.append(ch)
        else:
            if ch == "\\":
                out.append(ch)
                esc = True
            elif quote == '"' and ch in ('"', "”"):
                quote = None
                out.append('"')
            elif quote == "'" and ch == "'":
                quote = None
                out.append('"')
            else:
                out.append(ch)

    fixed = "".join(out)
    return re.sub(r",\s*([}\]])", r"\1", fixed)   # 去掉尾逗号


def load_configs() -> list[dict]:
    raw = os.environ.get("TVBOX_REMOTE_CONFIGS", "").strip()
    if not raw:
        print("⚠ 未设置 TVBOX_REMOTE_CONFIGS，只尝试直连。示例：")
        print('  export TVBOX_REMOTE_CONFIGS=\'[{"name":"159","url":"http://x/api.php","mode":"AUTO"}]\'')
        return []
    try:
        data = json.loads(raw)
    except Exception:
        try:
            data = json.loads(_normalize_json(raw))
            print("ℹ 已自动修正全角标点/尾逗号后解析成功（建议源配置直接用英文逗号）")
        except Exception as e:
            print(f"❌ TVBOX_REMOTE_CONFIGS 不是合法 JSON: {e}")
            print("原始值前 200 字符:", raw[:200])
            sys.exit(2)
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not data:
        print("❌ TVBOX_REMOTE_CONFIGS 必须是非空数组")
        sys.exit(2)
    return data


def resolve_formats(mode) -> list[Fmt]:
    if isinstance(mode, list):
        names = mode
    elif str(mode).strip().upper() == "AUTO":
        names = AUTO_ORDER
    else:
        names = [str(mode).strip().upper()]
    result = []
    for n in names:
        if n not in FMTS:
            raise ValueError(f"未知 mode: {n}，可选: AUTO / {' / '.join(FMTS)}")
        result.append(FMTS[n])
    return result


@dataclass
class Service:
    name: str
    url: str
    formats: list[Fmt]
    headers: dict
    timeout: float

    @classmethod
    def from_dict(cls, d: dict) -> "Service":
        return cls(
            name=d.get("name") or d["url"],
            url=d["url"],
            formats=resolve_formats(d.get("mode", "AUTO")),
            headers=d.get("headers") or {},
            timeout=float(d.get("timeout") or PROBE_TIMEOUT),
        )


# ============================================================ 请求构造

def build_request(fmt: Fmt, svc: Service, target: str) -> tuple[str, str, dict]:
    encoded = fmt.encode_target(target)
    parsed = urllib.parse.urlsplit(svc.url)
    origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ""
    headers = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}
    if origin:
        headers["Referer"] = origin + "/"
        headers["Origin"] = origin
    headers.update(svc.headers)

    url, kwargs = svc.url, {"headers": headers}

    if fmt.where == "query":
        kwargs["params"] = {fmt.param: encoded}       # 交给 requests 编码，防 & 截断
    elif fmt.where == "path":
        url = url.rstrip("/") + "/" + encoded
    elif fmt.where == "form":
        kwargs["data"] = {fmt.param: encoded}
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif fmt.where == "json":
        kwargs["json"] = ({"action": fmt.action,
                           "params": {fmt.param: encoded},
                           "ts": int(time.time())} if fmt.action
                          else {fmt.param: encoded})
    elif fmt.where == "json_array":
        kwargs["json"] = [encoded]
    else:
        raise ValueError(f"未实现的位置: {fmt.where}")
    return fmt.method, url, kwargs


# ============================================================ 载荷解码

def _decode_hex_config(text: str) -> str:
    """十六进制 + '2324' 标记的 TVBOX 加密配置。"""
    if not _HAS_AES:
        raise ValueError("缺少 pycryptodome，无法解密十六进制配置（pip install pycryptodome）")
    data = text.strip()
    idx = data.find("2324")
    prefix, cipher_hex, iv_hex = data[:idx + 4], data[idx + 4:-26], data[-26:]
    key_hex = prefix[4:-4] if prefix.startswith("2423") else prefix[:-4]
    key = bytes.fromhex(key_hex).decode("utf-8", "ignore").ljust(16, "0").encode()[:16]
    iv = bytes.fromhex(iv_hex).decode("utf-8", "ignore").ljust(16, "0").encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain = cipher.decrypt(binascii.unhexlify(cipher_hex))
    try:
        plain = unpad(plain, AES.block_size)
    except ValueError:
        pass
    return plain.decode("utf-8", "ignore")


def _check_json(text: str) -> str:
    """严格判定：必须是 JSON 对象，且 sites 是数组（或 spider 是字符串）。"""
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("顶层不是 JSON 对象")
    if "sites" in obj and not isinstance(obj["sites"], list):
        raise ValueError("sites 不是数组")
    if "spider" in obj and not isinstance(obj["spider"], str):
        raise ValueError("spider 不是字符串")
    if "sites" not in obj and "spider" not in obj:
        raise ValueError("缺少 sites/spider 字段")
    return text


def decode_config(payload: bytes) -> str:
    """把一份载荷变成配置文本；不可用就抛异常。"""
    # 1) 图片形态：'**' 之后是 base64
    if b"**" in payload[:4096]:
        pos = payload.find(b"**")
        b64 = payload[pos + 2:].decode("ascii", "ignore").strip()
        inner = base64.b64decode(b64)
        return decode_config(inner)

    text = payload.decode("utf-8", "ignore").strip()
    if not text:
        raise ValueError("空内容")

    # 2) 十六进制加密形态
    hexed = text.replace(" ", "")
    if "2324" in hexed and all(c in "0123456789abcdefABCDEF" for c in hexed):
        return _check_json(_decode_hex_config(text))

    # 3) 明文形态
    if not text.startswith("{"):
        raise ValueError(f"非 JSON 文本，开头={text[:60]!r}")
    return _check_json(text)


def candidate_payloads(content: bytes):
    """裸 body + JSON 包装里的字段（含 base64 解码结果）。"""
    yield content
    body = content.strip()
    if not body.startswith((b"{", b"[")):
        return
    try:
        obj = json.loads(body)
    except Exception:
        return
    for s in _iter_strings(obj):
        if len(s) < 64:
            continue
        yield s.encode("utf-8", "ignore")
        try:
            yield base64.b64decode(s, validate=False)
        except Exception:
            pass
        try:
            yield base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        except Exception:
            pass


def _iter_strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for v in o.values():
            yield from _iter_strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _iter_strings(v)


# ============================================================ 探测

@dataclass
class Attempt:
    service: str
    mode: str
    status: str        # OK / HTTP 400 / 请求异常 / 内容不符
    ms: int
    detail: str = ""


def try_once(svc: Service, fmt: Fmt, target: str, timeout: float):
    """返回 (解码文本, Attempt)。失败时文本为 None。"""
    t0 = time.time()
    try:
        method, url, kwargs = build_request(fmt, svc, target)
        resp = requests.request(method, url, timeout=timeout, **kwargs)
    except Exception as e:
        return None, Attempt(svc.name, fmt.key, "请求异常", int((time.time() - t0) * 1000),
                             str(e)[:120])
    if resp.status_code != 200:
        return None, Attempt(svc.name, fmt.key, f"HTTP {resp.status_code}",
                             int((time.time() - t0) * 1000),
                             resp.text[:80].replace("\n", " ") if resp.text else "")
    for payload in candidate_payloads(resp.content):
        try:
            text = decode_config(payload)
        except Exception:
            continue
        return text, Attempt(svc.name, fmt.key, "OK", int((time.time() - t0) * 1000),
                             f"{len(resp.content)}B")
    return None, Attempt(svc.name, fmt.key, "内容不符", int((time.time() - t0) * 1000),
                         f"{len(resp.content)}B {resp.content[:60]!r}")


def probe(target: str, services: list[Service], deadline: float) -> tuple[str, list[Attempt]]:
    log: list[Attempt] = []
    end = time.time() + deadline
    for svc in services:
        for fmt in svc.formats:
            if time.time() > end:
                raise RuntimeError(f"总预算 {deadline}s 已耗尽")
            print(f"  → {svc.name} / {fmt.key} ...", end="", flush=True)
            text, att = try_once(svc, fmt, target, svc.timeout)
            log.append(att)
            print(f" {att.status} ({att.ms}ms)" + (f" | {att.detail}" if att.status != "OK" else ""))
            if text is not None:
                # 探测阶段是短超时，正文可能被截断：按同格式长超时重拉一次
                if not REFETCH:
                    return text, log
                print(f"  ↻ 长超时重拉 {svc.name} / {fmt.key} ({FETCH_TIMEOUT}s)")
                text2, att2 = try_once(svc, fmt, target, FETCH_TIMEOUT)
                log.append(att2)
                if text2 is not None:
                    return text2, log
                print("  ⚠ 重拉失败，使用探测结果")
                return text, log
    raise RuntimeError("所有服务 × 所有格式均未拿到可用配置")


# ============================================================ 主流程

def download(url: str) -> bytes:
    """直连下载（和 tvbox_core.download_url 同样的 UA 轮换思路，简化版）。"""
    last = None
    for ua in ("okhttp/3.15", "okhttp/4.9.3", "TVBox/1.0.0", DEFAULT_UA):
        try:
            r = requests.get(url, headers={"User-Agent": ua}, timeout=8)
            r.raise_for_status()
            return r.content
        except Exception as e:
            last = e
    raise RuntimeError(str(last))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) < 2:
        print("用法: python test.py <URL或本地文件路径> <输出文件名>")
        print("  例: python test.py https://example.com/config.bmp out.json")
        sys.exit(1)
    source, out_name = args[0], args[1]

    deadline = float(os.environ.get("TVBOX_DEADLINE") or 60)
    direct_first = os.environ.get("TVBOX_DIRECT_FIRST", "1") != "0"

    raw_services = [d for d in load_configs() if d.get("enabled", True) is not False]
    services: list[Service] = []
    for d in raw_services:
        if not d.get("url"):
            print(f"⚠ 跳过缺少 url 的配置项: {d}")
            continue
        try:
            services.append(Service.from_dict(d))
        except ValueError as e:
            print(f"❌ 配置项 [{d.get('name', '?')}] 有误: {e}")
            sys.exit(2)
    if services:
        print("📋 服务列表:")
        for s in services:
            print(f"   - {s.name}: {s.url} | mode={[f.key for f in s.formats]} | timeout={s.timeout}s")

    # 1) 取数据
    data = None
    text = None
    attempts: list[Attempt] = []
    if source.startswith(("http://", "https://")) and direct_first:
        print(f"\n📥 直连下载: {source}")
        try:
            data = download(source)
            print("✅ 直连成功")
        except Exception as e:
            print(f"⚠ 直连失败: {str(e)[:160]}")

    if data is not None:
        try:
            text = decode_config(data)
        except Exception as e:
            print(f"⚠ 直连内容不可用（{e}），转入远程服务")
            data, text = None, None

    if data is None:
        print("\n🔁 进入远程服务探测")
        try:
            text, attempts = probe(source, services, deadline)
            print("✅ 远程探测成功，已选中可用服务")
        except RuntimeError as e:
            print(f"❌ {e}")
            print_report(attempts)
            sys.exit(1)

    # 2) 落盘
    with open(out_name, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"\n🎉 已写入 {out_name}（{len(text)} 字符）")
    print(f"   预览: {text[:120].replace(chr(10), ' ')}...")
    if attempts:
        print_report(attempts)


def print_report(attempts: list[Attempt]):
    if not attempts:
        return
    print("\n附：请求明细")
    header = f"{'#':>2}  {'服务':<10} {'格式':<18} {'状态':<10} {'耗时':>6}  说明"
    print(header)
    print("-" * len(header))
    for i, a in enumerate(attempts, 1):
        print(f"{i:>2}  {a.service:<10} {a.mode:<18} {a.status:<10} {a.ms:>5}ms  {a.detail[:40]}")
    ok = [a for a in attempts if a.status == "OK"]
    total_ms = sum(a.ms for a in attempts)
    print(f"\n共 {len(attempts)} 次请求，耗时合计 {total_ms/1000:.2f}s，"
          f"成功 {len(ok)} 次，首选成功项: {ok[0].service + ' / ' + ok[0].mode if ok else '无'}")


if __name__ == "__main__":
    main()
#（注：内容由AI生成）
