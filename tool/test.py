#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TVBOX 远程拉取测试单文件版（v2）

用法：
    python test.py <URL或本地文件路径> <输出文件名>

环境变量：
    TVBOX_REMOTE_CONFIGS   JSON 数组，按顺序尝试，一个地址失败自动换下一个：
        [{"name": "159",   "url": "http://159.75.152.41:88/api.php",     "mode": "AUTO"},
         {"name": "y456y", "url": "http://www.y456y.com/helper/api.php", "mode": "POST_JSON_NESTED"}]

    mode 取值：
        AUTO              自动探测 7 种格式，成功后会打印可回填的 {"名称","url","mode"}
        GET_QUERY_URL     GET  ?url=
        GET_QUERY_OU      GET  ?ou=
        GET_PATH_B64      GET  /<base64url>
        POST_FORM         POST form  url=
        POST_JSON         POST JSON 平铺 {"url": ...}
        POST_JSON_NESTED  POST JSON 嵌套 {"action":"fetch_content","params":{"url":...},"ts":...}
        POST_JSON_ARRAY   POST JSON 数组 ["<url>"]
        也可以是列表，如 ["POST_JSON_NESTED","POST_FORM"]，按顺序尝试

    其余可选字段：headers（追加请求头）、timeout（单次超时秒）、enabled（false 停用）

其他环境变量：
    TVBOX_DIRECT_FIRST  1/0，先直连再回退（默认 1）
    TVBOX_DEADLINE      总预算秒（默认 60）
    TVBOX_REFETCH       1/0，命中后长超时重拉（默认 1）
    TVBOX_TRY_ALL       1/0，成功后是否继续试其余地址做对比（默认 0，命中即停）
    TVBOX_ACTION_LOG    额外把 AUTO 结果追加写到的日志文件路径
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
from dataclasses import dataclass, field

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
REFETCH = os.environ.get("TVBOX_REFETCH", "1") != "0"
TRY_ALL = os.environ.get("TVBOX_TRY_ALL", "0") == "1"

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
    """修正手工录入污染（全角标点/中文引号/单引号/尾逗号），不破坏字符串内部。"""
    text = text.lstrip("\ufeff").strip()
    out, quote, esc = [], None, False
    for ch in text:
        if esc:
            out.append(ch)
            esc = False
            continue
        if quote is None:
            if ch == '"':
                quote = '"'
                out.append('"')
            elif ch in ("'", "“"):
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
    return re.sub(r",\s*([}\]])", r"\1", "".join(out))


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
        names = [str(n).strip().upper() for n in mode]
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
    declared_mode: str            # 配置里写的原始 mode，用于判断是否需要回写
    formats: list[Fmt]
    headers: dict = field(default_factory=dict)
    timeout: float = PROBE_TIMEOUT

    @property
    def is_auto(self) -> bool:
        return self.declared_mode == "AUTO"

    @classmethod
    def from_dict(cls, d: dict) -> "Service":
        raw_mode = d.get("mode", "AUTO")
        if str(raw_mode).strip().upper() == "AUTO":
            declared = "AUTO"
        elif isinstance(raw_mode, list):
            declared = json.dumps(raw_mode, ensure_ascii=False)
        else:
            declared = str(raw_mode).strip().upper()
        return cls(
            name=d.get("name") or d["url"],
            url=d["url"],
            declared_mode=declared,
            formats=resolve_formats(raw_mode),
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
        kwargs["params"] = {fmt.param: encoded}
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
    if not _HAS_AES:
        raise ValueError("缺少 pycryptodome，无法解密十六进制配置")
    data = text.strip()
    idx = data.find("2324")
    prefix, cipher_hex, iv_hex = data[:idx + 4], data[idx + 4:-26], data[-26:]
    key_hex = prefix[4:-4] if prefix.startswith("2423") else prefix[:-4]
    key = bytes.fromhex(key_hex).decode("utf-8", "ignore").ljust(16, "0").encode()[:16]
    iv = bytes.fromhex(iv_hex).decode("utf-8", "ignore").ljust(16, "0").encode()[:16]
    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(binascii.unhexlify(cipher_hex))
    try:
        plain = unpad(plain, AES.block_size)
    except ValueError:
        pass
    return plain.decode("utf-8", "ignore")


def _check_json(text: str) -> str:
    """严格判定：JSON 对象 + sites 是数组（或 spider 是字符串）。"""
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
    """把载荷变成明文配置；不可用抛异常（=> 视为"没解析出明文"，换下一个地址）。"""
    if b"**" in payload[:4096]:                      # 图片隐写
        pos = payload.find(b"**")
        return decode_config(base64.b64decode(payload[pos + 2:].decode("ascii", "ignore").strip()))

    text = payload.decode("utf-8", "ignore").strip()
    if not text:
        raise ValueError("空内容")

    hexed = text.replace(" ", "")
    if "2324" in hexed and all(c in "0123456789abcdefABCDEF" for c in hexed):
        return _check_json(_decode_hex_config(text))

    if not text.startswith("{"):
        raise ValueError(f"非 JSON 文本，开头={text[:60]!r}")
    return _check_json(text)


def candidate_payloads(content: bytes):
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


# ============================================================ 结果预览

def preview_lines(text: str | None, head_bytes: bytes | None, limit: int = 120) -> list[str]:
    """给"每个地址的解析结果"生成可读预览。

    成功：spider / sites 数量与示例 / 开头片段
    失败：响应开头片段，便于判断是地址错还是格式错
    """
    if text is None:
        snippet = (head_bytes or b"")[:limit].decode("utf-8", "ignore").replace("\n", " ")
        return [f"响应开头: {snippet!r}"] if snippet else ["无响应内容"]

    out = []
    try:
        obj = json.loads(text)
    except Exception:
        return [f"开头: {text[:limit].replace(chr(10), ' ')}"]

    spider = obj.get("spider")
    sites = obj.get("sites") if isinstance(obj.get("sites"), list) else []
    lives = obj.get("lives") if isinstance(obj.get("lives"), list) else []
    if spider:
        out.append(f"spider: {str(spider)[:100]}")
    names = [str(s.get("name")) for s in sites[:3] if isinstance(s, dict) and s.get("name")]
    out.append(f"sites: {len(sites)} 个" + (f" | 示例: {'、'.join(names)}" if names else " | 示例: 无"))
    if lives:
        out.append(f"lives: {len(lives)} 个")
    out.append(f"parsed: {len(text)} 字符 | 开头: {text[:limit].replace(chr(10), ' ')}")
    return out


# ============================================================ ACTION 日志

def emit_action_mode(svc: Service, fmt: Fmt):
    """把 AUTO 探测出的可用 mode 回写成可直接粘回配置的 JSON。

    三种落点：
      1) GitHub Actions 注解 ::notice::（显示在 run 日志里，可折叠）
      2) 单行 TVBOX_AUTO_MODE=...（便于 grep / 下游脚本解析）
      3) 可选 TVBOX_ACTION_LOG 文件 + GITHUB_STEP_SUMMARY
    """
    payload = {"名称": svc.name, "url": svc.url, "mode": fmt.key}
    one_line = json.dumps(payload, ensure_ascii=False)

    print("\n📌 AUTO 模式探测结果（可直接粘回 TVBOX_REMOTE_CONFIGS）:")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print(f"::notice title=TVBOX_AUTO_MODE::{one_line}")
    print(f"TVBOX_AUTO_MODE={one_line}")

    log_path = os.environ.get("TVBOX_ACTION_LOG", "").strip()
    if log_path:
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] TVBOX_AUTO_MODE {one_line}\n")
            print(f"   已追加到 {log_path}")
        except Exception as e:
            print(f"   ⚠ 写日志文件失败: {e}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as f:
                f.write(f"\n| 名称 | url | 建议 mode |\n|---|---|---|\n"
                        f"| {svc.name} | {svc.url} | `{fmt.key}` |\n")
        except Exception:
            pass


# ============================================================ 探测

@dataclass
class Attempt:
    svc: Service
    mode: str
    status: str            # OK / HTTP 400 / 请求异常 / 内容不符
    ms: int
    detail: str = ""
    text: str | None = None
    body_head: bytes = b""


def try_once(svc: Service, fmt: Fmt, target: str, timeout: float) -> Attempt:
    t0 = time.time()
    try:
        method, url, kwargs = build_request(fmt, svc, target)
        resp = requests.request(method, url, timeout=timeout, **kwargs)
    except Exception as e:
        return Attempt(svc, fmt.key, "请求异常", int((time.time() - t0) * 1000), str(e)[:120])

    if resp.status_code != 200:
        body = resp.content[:200]
        return Attempt(svc, fmt.key, f"HTTP {resp.status_code}",
                       int((time.time() - t0) * 1000),
                       body.decode("utf-8", "ignore")[:80].replace("\n", " "), body_head=body)

    for payload in candidate_payloads(resp.content):
        try:
            text = decode_config(payload)
        except Exception:
            continue
        return Attempt(svc, fmt.key, "OK", int((time.time() - t0) * 1000),
                       f"{len(resp.content)}B", text, resp.content[:200])

    return Attempt(svc, fmt.key, "内容不符", int((time.time() - t0) * 1000),
                   f"{len(resp.content)}B 无明文", body_head=resp.content[:200])


def probe(target: str, services: list[Service], deadline: float):
    """按数组顺序逐地址尝试；某地址全部格式失败或没解析出明文，自动换下一个。"""
    attempts: list[Attempt] = []
    results: list[tuple[Service, Fmt, str]] = []
    end = time.time() + deadline

    for idx, svc in enumerate(services, 1):
        print(f"\n[{idx}/{len(services)}] 尝试 {svc.name}: {svc.url} (mode={svc.declared_mode})")
        hit: tuple[Fmt, str] | None = None
        for fmt in svc.formats:
            if time.time() > end:
                raise RuntimeError(f"总预算 {deadline}s 已耗尽（未完成全部地址）")
            print(f"  → {fmt.key} ...", end="", flush=True)
            att = try_once(svc, fmt, target, svc.timeout)
            attempts.append(att)
            print(f" {att.status} ({att.ms}ms)" + (f" | {att.detail}" if att.detail else ""))
            if att.text is None:
                continue

            if REFETCH:     # 短超时可能截断正文，按同格式长超时重拉
                print(f"  ↻ 长超时重拉 ({FETCH_TIMEOUT}s)", end="", flush=True)
                att2 = try_once(svc, fmt, target, FETCH_TIMEOUT)
                attempts.append(att2)
                print(f" {att2.status} ({att2.ms}ms)")
                if att2.text is not None:
                    att = att2
            hit = (fmt, att.text)
            break

        if hit:
            results.append((svc, hit[0], hit[1]))
            print(f"  ✓ {svc.name} 解析成功（{hit[0].key}）")
            if not TRY_ALL:
                print("  命中即停（TVBOX_TRY_ALL=0）")
                break
        else:
            print(f"  ✗ {svc.name} 未解析出明文，切换到下一个地址")

    return results, attempts


# ============================================================ 报表

def print_service_previews(services: list[Service], attempts: list[Attempt],
                           results: list[tuple[Service, Fmt, str]]):
    win = {svc.name: (fmt, text) for svc, fmt, text in results}
    by_svc: dict[str, list[Attempt]] = {}
    for a in attempts:
        by_svc.setdefault(a.svc.name, []).append(a)

    print("\n" + "=" * 62)
    print("每个解析地址的结果预览")
    print("=" * 62)
    for svc in services:
        rows = by_svc.get(svc.name, [])
        if svc.name in win:
            fmt, text = win[svc.name]
            print(f"\n● {svc.name}  [成功]  mode={fmt.key}  url={svc.url}")
            for line in preview_lines(text, None):
                print(f"    {line}")
            if svc.is_auto:
                print(f"    ↳ 该地址配置为 AUTO，可回填 mode=\"{fmt.key}\"")
        elif rows:
            # 优先展示"拿到了 200 响应但内容不可用"的那次，比 404 更有诊断价值
            informative = [r for r in rows if r.status == "内容不符"]
            last = informative[-1] if informative else rows[-1]
            print(f"\n● {svc.name}  [失败]  共试 {len(rows)} 种格式，"
                  f"代表结果 {last.mode}: {last.status} {last.detail}")
            for line in preview_lines(None, last.body_head):
                print(f"    {line}")
        else:
            print(f"\n● {svc.name}  [跳过]  未发起请求")


def print_report(attempts: list[Attempt], results: list[tuple[Service, Fmt, str]]):
    if not attempts:
        return
    print("\n附：请求明细")
    header = f"{'#':>2}  {'服务':<10} {'格式':<18} {'状态':<11} {'耗时':>7}  说明"
    print(header)
    print("-" * len(header))
    for i, a in enumerate(attempts, 1):
        print(f"{i:>2}  {a.svc.name:<10} {a.mode:<18} {a.status:<11} {a.ms:>6}ms  {a.detail[:36]}")
    total_ms = sum(a.ms for a in attempts)
    print(f"\n共 {len(attempts)} 次请求，合计 {total_ms/1000:.2f}s，"
          f"成功地址 {len(results)} 个"
          + (f"，首个: {results[0][0].name} / {results[0][1].key}" if results else ""))


# ============================================================ 主流程

def download(url: str) -> bytes:
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

    services: list[Service] = []
    for d in load_configs():
        if d.get("enabled", True) is False:
            print(f"⚠ 已跳过停用项: {d.get('name', d.get('url'))}")
            continue
        if not d.get("url"):
            print(f"⚠ 跳过缺少 url 的配置项: {d}")
            continue
        try:
            services.append(Service.from_dict(d))
        except ValueError as e:
            print(f"❌ 配置项 [{d.get('name', '?')}] 有误: {e}")
            sys.exit(2)

    if services:
        print(f"📋 服务列表（按顺序尝试 {len(services)} 个）:")
        for i, s in enumerate(services, 1):
            print(f"   {i}. {s.name}: {s.url} | mode={s.declared_mode} "
                  f"| 待试格式={[f.key for f in s.formats]} | timeout={s.timeout}s")

    attempts: list[Attempt] = []
    results: list[tuple[Service, Fmt, str]] = []
    text: str | None = None

    # 1) 直连优先
    data = None
    if source.startswith(("http://", "https://")) and direct_first:
        print(f"\n📥 直连下载: {source}")
        try:
            data = download(source)
            print("✅ 直连成功")
        except Exception as e:
            print(f"⚠ 直连失败: {str(e)[:150]}")

    if data is not None:
        try:
            text = decode_config(data)
        except Exception as e:
            print(f"⚠ 直连内容不可用（{e}），转入远程服务")
            data, text = None, None

    # 2) 远程探测
    if text is None:
        print("\n🔁 进入远程服务解析")
        try:
            results, attempts = probe(source, services, deadline)
        except RuntimeError as e:
            print(f"\n❌ {e}")
            print_service_previews(services, attempts, results)
            print_report(attempts, results)
            sys.exit(1)

        if not results:
            print("\n❌ 所有地址均未解析出明文")
            print_service_previews(services, attempts, results)
            print_report(attempts, results)
            sys.exit(1)

        svc, fmt, text = results[0]        # 最终采用第一个成功地址的结果
        print(f"\n✅ 最终采用: {svc.name} / {fmt.key}")

    # 3) 每个地址的结果预览 + AUTO 回写
    if services and attempts:
        print_service_previews(services, attempts, results)

    if results:
        win_svc, win_fmt, _ = results[0]
        if win_svc.is_auto:
            emit_action_mode(win_svc, win_fmt)
        else:
            print(f"\n📌 该地址 mode 已显式指定为 {win_svc.declared_mode}，无需回写")

    # 4) 落盘
    with open(out_name, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"\n🎉 已写入 {out_name}（{len(text)} 字符）")
    if attempts:
        print_report(attempts, results)


if __name__ == "__main__":
    main()
