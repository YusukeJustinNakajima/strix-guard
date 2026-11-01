"""Docker API Proxy: exec create を実行前にゲートする（allow/hold/deny）

- 上流: unix socket (既定 /var/run/docker.sock) または TCP
- ゲート対象: POST /vX.Y/containers/{id}/exec （body の Cmd）
- それ以外は透過（M1ではContent-Length前提の簡易リレー。hijack/streamは後続で対応）
"""
import http.client
import json
import re
import select
import shlex
import socket
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional

EXEC_CREATE_RE = re.compile(r"^/v[\d.]+/containers/[^/]+/exec$")
CONTAINER_CREATE_RE = re.compile(r"^/v[\d.]+/containers/create(?:\?.*)?$")
CONTAINER_START_RE = re.compile(r"^/v[\d.]+/containers/([^/]+)/start(?:\?.*)?$")
STREAM_HINTS = re.compile(r"/(exec/[^/]+/start|attach|logs)$")
_PTY_WRAPPER = re.compile(r"^(.*?_pty\.pid\s+(?:bash|sh)\s+-lc\s+)(.*)$", re.S)


def _notice_command(msg: str) -> str:
    return "printf '%s\\n' " + shlex.quote(msg) + "; exit 1"


def _rewrite_notice(spec: dict, msg: str) -> dict:
    """deny/revise用の通知execを作る。strixのPTYラッパーは維持して出力を届ける。"""
    new_spec = dict(spec)
    cmd = spec.get("Cmd") or []
    inner = _notice_command(msg)
    if isinstance(cmd, list) and cmd and isinstance(cmd[-1], str):
        m = _PTY_WRAPPER.match(cmd[-1])
        if m:
            new_spec["Cmd"] = list(cmd[:-1]) + [m.group(1) + inner]
            new_spec["AttachStdout"] = True
            new_spec["AttachStderr"] = True
            return new_spec
    new_spec["Cmd"] = ["sh", "-c", inner]
    new_spec["AttachStdout"] = True
    new_spec["AttachStderr"] = True
    new_spec["Tty"] = False
    return new_spec


def _set_proxy_env(spec: dict, proxy_url: str) -> dict:
    new = dict(spec)
    env = [e for e in (spec.get("Env") or [])
           if not e.lower().startswith(("http_proxy=", "https_proxy=", "all_proxy=", "no_proxy="))]
    env += [f"http_proxy={proxy_url}", f"https_proxy={proxy_url}",
            f"HTTP_PROXY={proxy_url}", f"HTTPS_PROXY={proxy_url}",
            f"ALL_PROXY={proxy_url}", "NO_PROXY=localhost,127.0.0.1,api.caido.io"]
    new["Env"] = env
    return new


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, unix_path: str, timeout: float = 30.0):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = unix_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.unix_path)
        self.sock = sock


def _open_upstream(upstream: tuple, timeout: float = 30.0) -> http.client.HTTPConnection:
    kind = upstream[0]
    if kind == "unix":
        return _UnixHTTPConnection(upstream[1], timeout=timeout)
    if kind == "tcp":
        return http.client.HTTPConnection(upstream[1], upstream[2], timeout=timeout)
    raise ValueError(f"unknown upstream: {upstream}")


# on_exec(container_id, cmd_argv, raw_body: dict) -> (action, message)
#   action: "allow" | "deny" | "revise"
#   message: deny/revise の場合に返す本文（エージェントへの修正指示を含められる）
OnExec = Callable[[str, list, dict], tuple]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "strix-guard/0.1"

    def log_message(self, fmt, *args):  # 静かに
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    # --- ユーティリティ ---
    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _respond_json(self, status: int, obj: dict):
        payload = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _forward(self, method: str, path: str, body: bytes):
        upstream = self.server.upstream
        conn = _open_upstream(upstream)
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "connection", "transfer-encoding", "content-length")}
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() in ("transfer-encoding", "connection", "content-length"):
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # --- HTTP ---
    def _handle(self, method: str):
        body = self._read_body()
        path = self.path
        if method == "POST" and EXEC_CREATE_RE.match(path):
            return self._handle_exec_create(path, body)
        if method == "POST" and CONTAINER_CREATE_RE.match(path):
            return self._handle_container_create(path, body)
        ms = CONTAINER_START_RE.match(path) if method == "POST" else None
        if ms:
            return self._handle_container_start(path, body, ms.group(1))
        if self._should_tunnel(path):
            return self._tunnel(method, path, body)
        self._forward(method, path, body)

    def _handle_container_create(self, path: str, body: bytes):
        if not self.server.on_container_create:
            return self._forward("POST", path, body)
        try:
            spec = json.loads(body or b"{}")
        except Exception:
            return self._forward("POST", path, body)
        try:
            spec = self.server.on_container_create(spec) or spec
        except Exception as e:
            self.server.audit({"kind": "sidecar_error", "error": str(e)[:200]})
            return self._forward("POST", path, body)
        return self._forward("POST", path, json.dumps(spec).encode())

    def _handle_container_start(self, path: str, body: bytes, container_id: str):
        upstream = self.server.upstream
        conn = _open_upstream(upstream)
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "connection", "transfer-encoding", "content-length")}
        try:
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
        finally:
            try:
                conn.close()
            except Exception:
                pass
        if self.server.on_container_start:
            try:
                self.server.on_container_start(container_id)
            except Exception as e:
                self.server.audit({"kind": "sidecar_error", "container_id": container_id,
                                   "error": str(e)[:200]})
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() in ("content-length", "transfer-encoding", "connection"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _should_tunnel(self, path: str) -> bool:
        if (self.headers.get("Upgrade") or "").strip():
            return True
        return bool(STREAM_HINTS.search(path))

    def _tunnel(self, method: str, path: str, body: bytes):
        """hijack/ストリーミング用の生スプライス（exec start, attach, logs follow）"""
        upstream = self.server.upstream
        try:
            if upstream[0] == "unix":
                up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                up.settimeout(60)
                up.connect(upstream[1])
            else:
                up = socket.create_connection((upstream[1], upstream[2]), timeout=60)
        except Exception:
            self._respond_json(502, {"message": "strix-guard: upstream connect failed"})
            return
        lines = [f"{method} {path} HTTP/1.1"]
        for k, v in self.headers.items():
            if k.lower() == "host":
                v = "localhost"
            lines.append(f"{k}: {v}")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode()
        try:
            up.sendall(head)
            if body:
                up.sendall(body)
        except Exception:
            up.close()
            return
        client = self.connection
        self.close_connection = True
        socks = [client, up]
        try:
            while True:
                r, _, x = select.select(socks, [], socks, 300)
                if x or not r:
                    break
                for s in r:
                    try:
                        data = s.recv(65536)
                    except Exception:
                        data = b""
                    if not data:
                        return
                    other = up if s is client else client
                    try:
                        other.sendall(data)
                    except Exception:
                        return
        finally:
            try:
                up.close()
            except Exception:
                pass

    def _handle_exec_create(self, path: str, body: bytes):
        container_id = path.split("/")[3]
        try:
            spec = json.loads(body or b"{}")
        except Exception:
            spec = {}
        cmd_argv = spec.get("Cmd") or []
        cmd_str = " ".join(cmd_argv) if isinstance(cmd_argv, list) else str(cmd_argv)
        action, message = self.server.on_exec(container_id, cmd_argv, spec)
        rec = {"container_id": container_id, "cmd": cmd_str, "action": action,
               "message": message}
        self.server.audit(rec)
        if action == "allow":
            proxy_url = getattr(self.server, "exec_env_proxy", None)
            if proxy_url:
                return self._forward("POST", path,
                                     json.dumps(_set_proxy_env(spec, proxy_url)).encode())
            return self._forward("POST", path, body)
        # deny / revise: サンドボックス層は APIError 本文を捨てるため、指示文を出力する
        # 安全な exec に差し替えて、通常のツール出力としてエージェントへ確実に届ける
        msg = message or f"strix-guard: {action}"
        new_spec = _rewrite_notice(spec, msg)
        new_body = json.dumps(new_spec).encode()
        return self._forward("POST", path, new_body)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_PUT(self):
        self._handle("PUT")

    def do_HEAD(self):
        self._handle("HEAD")


class DockerProxy:
    def __init__(self, upstream: tuple = ("unix", "/var/run/docker.sock"),
                 on_exec: Optional[OnExec] = None,
                 audit: Optional[Callable[[dict], None]] = None,
                 on_container_create: Optional[Callable[[dict], dict]] = None,
                 on_container_start: Optional[Callable[[str], None]] = None,
                 exec_env_proxy: Optional[str] = None,
                 host: str = "127.0.0.1", port: int = 0,
                 verbose: bool = False):
        self.upstream = upstream
        self.on_exec = on_exec or (lambda cid, argv, spec: ("allow", None))
        self.audit = audit or (lambda rec: None)
        self.verbose = verbose
        self.httpd = ThreadingHTTPServer((host, port), _Handler)
        self.httpd.upstream = upstream
        self.httpd.on_exec = self.on_exec
        self.httpd.audit = self.audit
        self.httpd.on_container_create = on_container_create
        self.httpd.on_container_start = on_container_start
        self.httpd.exec_env_proxy = exec_env_proxy
        self.httpd.verbose = verbose
        self._thread: Optional[threading.Thread] = None
        self.token = uuid.uuid4().hex

    @property
    def address(self) -> tuple:
        return self.httpd.server_address

    def start(self):
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
