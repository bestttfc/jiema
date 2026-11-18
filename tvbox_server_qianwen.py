# -*- coding: utf-8 -*-
"""
TvBox 本地解密 HTTP 服务（补丁版：支持按请求传回退链参数）
=========================================================
与原 tvbox_server.py 的差异（其余逻辑一行未动）：
  1. GET  /decode?url=...&fallback=1&remote1=...&remote2=...
  2. POST /decode  {"url": "...", "fallback": "1", "remote1": "...", "remote2": "..."}
     —— 三个新参数均可选；不传时沿用进程启动时的环境变量值（与原版行为一致）。
  3. 收到参数时，在调用下载前动态改写 tvbox_core 的模块级变量：
     ENABLE_FALLBACK / REMOTE_FALLBACK_URL_1 / REMOTE_FALLBACK_URL_2
     （tvbox_core.py 无需任何修改，其函数在调用时才读取这些模块全局量）
  4. 注意：ThreadingHTTPServer 并发下这些全局量存在竞态；本机单人使用无影响，
     如需严格隔离可改为把参数显式传参进 core 函数（需要动 core 签名）。

网页端（加密解码工具箱 v6 及以后）在「本地 TvBoxHelper」通道下会以 POST
方式附带这三个字段；旧版 exe 会忽略多余字段，向后兼容。

替换方法：用本文件覆盖仓库 tool/tvbox_server.py 后重新编译：
  pyinstaller -F --windowed -n TvBoxHelper tvbox_server.py
"""
import json
import logging
import os
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from urllib.parse import urlparse, parse_qs

import tvbox_core  # 附件2 重命名后的模块

# ===================== 配置 =====================
HOST = "127.0.0.1"            # 只绑本机，切勿改 0.0.0.0
PORT = 8765                   # 必须与前端 LOCAL_SERVER 一致
MAX_BYTES = 20 * 1024 * 1024  # 下载上限 20MB
BLOCK_PRIVATE = os.environ.get("TVBOX_BLOCK_PRIVATE", "1") != "0"

BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
LOG_FILE = os.path.join(BASE_DIR, "tvbox_server.log")

# 打包成 --windowed 时没有控制台，stdout 重定向到日志，避免 print 报错
if sys.stdout is None:
    sys.stdout = open(LOG_FILE, "a", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = sys.stdout

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("tvbox")


# ===================== SSRF 防护 =====================
def is_private_target(url: str) -> bool:
    """解析域名后判断是否指向私网/回环/链路本地，防止本地服务变成内网探测跳板"""
    try:
        host = urlparse(url).hostname
        if not host:
            return True
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            addr = ip_address(info[4][0])
            if (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
                return True
        return False
    except Exception as e:
        log.warning("SSRF 检查异常，按不安全处理: %s -> %s", url, e)
        return True


# ===================== 回退链参数（新增） =====================
def _truthy(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "on", "yes")


def apply_fallback_overrides(fb, r1, r2):
    """按请求动态改写 tvbox_core 的模块级配置；None/空串表示不改动"""
    changed = []
    if fb is not None and str(fb).strip() != "":
        tvbox_core.ENABLE_FALLBACK = _truthy(fb)
        changed.append("fallback=%s" % tvbox_core.ENABLE_FALLBACK)
    if r1 is not None and str(r1).strip() != "":
        tvbox_core.REMOTE_FALLBACK_URL_1 = str(r1).strip()
        changed.append("remote1=%s" % tvbox_core.REMOTE_FALLBACK_URL_1)
    if r2 is not None and str(r2).strip() != "":
        tvbox_core.REMOTE_FALLBACK_URL_2 = str(r2).strip()
        changed.append("remote2=%s" % tvbox_core.REMOTE_FALLBACK_URL_2)
    if changed:
        log.info("回退链参数已更新: %s", ", ".join(changed))


# ===================== HTTP 处理 =====================
class Handler(BaseHTTPRequestHandler):
    server_version = "TvBoxPy/1.1"

    def log_message(self, fmt, *args):
        log.info("%s - %s", self.address_string(), fmt % args)

    # ---------- 通用响应 ----------
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---------- 路由 ----------
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/ping":
            self._json(200, {
                "ok": True, "name": "tvbox-py", "version": "1.1",
                "fallback": bool(tvbox_core.ENABLE_FALLBACK),
                "remote1": tvbox_core.REMOTE_FALLBACK_URL_1,
                "remote2": tvbox_core.REMOTE_FALLBACK_URL_2,
            })
            return
        if parsed.path == "/decode":
            qs = parse_qs(parsed.query)
            url = (qs.get("url") or [""])[0].strip()
            fb = (qs.get("fallback") or [None])[0]
            r1 = (qs.get("remote1") or [None])[0]
            r2 = (qs.get("remote2") or [None])[0]
            self._handle_decode(url, fb, r1, r2)
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/decode":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode("utf-8") if length else "{}"
                data = json.loads(raw) if raw.strip() else {}
                url = str(data.get("url", "")).strip()
                fb = data.get("fallback")
                r1 = data.get("remote1")
                r2 = data.get("remote2")
            except Exception as e:
                self._json(400, {"ok": False, "error": "bad json: %s" % e})
                return
            self._handle_decode(url, fb, r1, r2)
            return
        self._json(404, {"ok": False, "error": "not found"})

    # ---------- 核心逻辑 ----------
    def _handle_decode(self, url: str, fb=None, r1=None, r2=None):
        if not url:
            self._json(400, {"ok": False, "error": "missing url"})
            return
        if not url.startswith(("http://", "https://")):
            self._json(400, {"ok": False, "error": "only http(s) allowed"})
            return
        if BLOCK_PRIVATE and is_private_target(url):
            log.warning("拦截私网目标: %s", url)
            self._json(400, {"ok": False, "error": "private/loopback host blocked"})
            return

        # 新增：按请求应用回退链参数（不传则沿用启动时环境变量）
        apply_fallback_overrides(fb, r1, r2)

        t0 = time.time()
        try:
            if tvbox_core.ENABLE_FALLBACK:
                raw = tvbox_core.download_url_with_fallback(url)
            else:
                raw = tvbox_core.download_url(url)

            if not raw:
                raise ValueError("empty response")
            if len(raw) > MAX_BYTES:
                raise ValueError("response too large: %d > %d" % (len(raw), MAX_BYTES))

            plain = tvbox_core.process_data(raw)
            dt = int((time.time() - t0) * 1000)
            log.info("OK %s -> %dB, %d chars, %dms, fallback=%s",
                     url, len(raw), len(plain), dt, tvbox_core.ENABLE_FALLBACK)
            self._json(200, {
                "ok": True,
                "content": plain,
                "bytes": len(raw),
                "elapsed_ms": dt,
                "fallback_used": bool(tvbox_core.ENABLE_FALLBACK),
            })
        except Exception as e:
            dt = int((time.time() - t0) * 1000)
            log.error("ERR %s -> %s (%dms)", url, e, dt)
            self._json(200, {"ok": False, "error": str(e), "elapsed_ms": dt})


# ===================== 启动 =====================
def main():
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as e:
        log.error("端口 %d 无法绑定: %s", PORT, e)
        log.error("请检查是否已有实例在运行：netstat -ano | findstr :%d", PORT)
        log.error("或修改 PORT（同时改前端 LOCAL_SERVER 常量）后重试")
        sys.exit(1)

    log.info("=" * 56)
    log.info("TvBox Python 服务已启动: http://%s:%d", HOST, PORT)
    log.info("  GET  /ping")
    log.info("  GET  /decode?url=...[&fallback=1&remote1=...&remote2=...]")
    log.info("  POST /decode  {\"url\": \"...\", \"fallback\": \"1\", \"remote1\": \"...\", \"remote2\": \"...\"}")
    log.info("  回退链(启动默认): %s", "已启用" if tvbox_core.ENABLE_FALLBACK else "未启用")
    log.info("  SSRF 防护: %s", "开启" if BLOCK_PRIVATE else "关闭")
    log.info("日志文件: %s", LOG_FILE)
    log.info("=" * 56)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("收到 Ctrl+C，正在退出...")
        server.shutdown()


if __name__ == "__main__":
    main()
