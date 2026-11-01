"""In-container HTTP egress proxy for strix-guard.

Runs inside the strix sandbox, listens on 127.0.0.1:48081, and chains to the
existing in-container proxy (Caido, 127.0.0.1:48080). It enforces the run's
allowed HTTP methods, host allowlist, request/rate/parallel caps, and writes a
JSONL access log that the host mounts from the container.
"""
import argparse
import http.client
import json
import os
import select
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HOP = {"connection", "proxy-connection", "keep-alive", "transfer-encoding",
       "te", "trailer", "upgrade", "content-length", "proxy-authorization"}
IN_SCOPE = {"host.docker.internal", "127.0.0.1", "localhost", "0.0.0.0", "::1"}


class Guard:
    def __init__(self, policy: dict, log_path: str):
        self.policy = policy
        self.log_path = log_path
        self.log_lock = threading.Lock()
        self.lock = threading.Lock()
        self.total = 0
        self.window = 0.0
        self.window_count = 0
        self.sem = threading.BoundedSemaphore(int(policy.get("max_parallel") or 10))

    def log(self, rec: dict):
        rec = dict(rec)
        rec.setdefault("ts", time.time())
        try:
            with self.log_lock, open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def check(self, method: str, hostport: str, host: str, enforce_method: bool = True) -> tuple[bool, str]:
        infra = {str(x).lower() for x in (self.policy.get("infra_hosts") or [])}
        if hostport.lower() in infra or host.lower() in infra:
            return True, "infra"
        allowed_methods = {m.upper() for m in (self.policy.get("allowed_methods") or ["GET"])}
        if enforce_method and method.upper() not in allowed_methods:
            return False, "method_not_allowed"
        allowed_hosts = {str(x).lower() for x in (self.policy.get("allowed_hosts") or [])}
        if allowed_hosts:
            if hostport.lower() not in allowed_hosts and host.lower() not in allowed_hosts:
                # allow a configured bare host against host:port requests
                if not any(":" not in a and a == host.lower() for a in allowed_hosts):
                    return False, "host_not_allowed"
        elif host.lower() not in IN_SCOPE:
            return False, "host_not_allowed"
        now = time.time()
        with self.lock:
            self.total += 1
            if self.total > int(self.policy.get("max_requests") or 500):
                return False, "request_cap"
            if now - self.window >= 1.0:
                self.window = now
                self.window_count = 0
            self.window_count += 1
            if self.window_count > int(self.policy.get("max_rps") or 10):
                return False, "rate_limit"
        return True, "allow"

    @staticmethod
    def split_url(path: str):
        u = urlsplit(path)
        if not u.scheme or not u.hostname:
            return None
        host = u.hostname.lower()
        hostport = host + ((":" + str(u.port)) if u.port else "")
        return u, host, hostport


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "strix-guard-sidecar/0.1"

    def log_message(self, *a):
        pass

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _respond(self, status: int, text: str):
        body = (text + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _relay(self, method: str, body: bytes):
        g: Guard = self.server.guard
        if self.path.startswith("/__guard/health"):
            return self._respond(200, "ok")
        parsed = g.split_url(self.path)
        if not parsed:
            g.log({"method": method, "path": self.path, "verdict": "bad_request"})
            return self._respond(400, "strix-guard: proxy requires an absolute URL")
        u, host, hostport = parsed
        ok, reason = g.check(method, hostport, host)
        if not ok:
            g.log({"method": method, "host": hostport, "path": u.path,
                   "verdict": reason})
            return self._respond(403, "strix-guard: blocked by HTTP policy (" + reason + ")")
        if not g.sem.acquire(blocking=False):
            g.log({"method": method, "host": hostport, "path": u.path,
                   "verdict": "parallel_cap"})
            return self._respond(429, "strix-guard: too many parallel requests")
        status = 0
        try:
            up_host = g.policy.get("upstream_host")
            up_port = int(g.policy.get("upstream_port") or 0)
            if up_host and up_port:
                conn = http.client.HTTPConnection(up_host, up_port, timeout=60)
                target = self.path
            else:
                conn = http.client.HTTPConnection(host, u.port or (443 if u.scheme == "https" else 80), timeout=60)
                target = (u.path or "/") + (("?" + u.query) if u.query else "")
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
            conn.request(method, target, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            status = resp.status
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() in HOP:
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            conn.close()
        except Exception as e:
            g.log({"method": method, "host": hostport, "path": u.path,
                   "verdict": "upstream_error", "error": str(e)[:160]})
            return self._respond(502, "strix-guard: upstream request failed")
        finally:
            g.sem.release()
        g.log({"method": method, "host": hostport, "path": u.path,
               "verdict": "allow", "status": status})

    def do_GET(self):
        self._relay("GET", self._body())

    def do_HEAD(self):
        self._relay("HEAD", self._body())

    def do_OPTIONS(self):
        self._relay("OPTIONS", self._body())

    def do_POST(self):
        self._relay("POST", self._body())

    def do_PUT(self):
        self._relay("PUT", self._body())

    def do_PATCH(self):
        self._relay("PATCH", self._body())

    def do_DELETE(self):
        self._relay("DELETE", self._body())

    def do_CONNECT(self):
        g: Guard = self.server.guard
        host, _, port = self.path.partition(":")
        hostport = host.lower() + ((":" + port) if port else "")
        allowed, reason = g.check("CONNECT", hostport, host.lower(), enforce_method=False)
        if not allowed:
            g.log({"method": "CONNECT", "host": hostport, "verdict": reason})
            return self._respond(403, "strix-guard: blocked by HTTP policy (" + reason + ")")
        if not g.policy.get("allow_connect") and reason != "infra":
            g.log({"method": "CONNECT", "host": hostport, "verdict": "connect_not_allowed"})
            return self._respond(403, "strix-guard: CONNECT is not allowed by policy")
        up_host = g.policy.get("upstream_host")
        up_port = int(g.policy.get("upstream_port") or 0)
        try:
            if up_host and up_port:
                up = socket.create_connection((up_host, up_port), timeout=30)
                up.sendall(("CONNECT " + hostport + " HTTP/1.1\r\nHost: " + hostport +
                            "\r\n\r\n").encode())
                if not _read_headers(up):
                    up.close()
                    return self._respond(502, "strix-guard: upstream CONNECT failed")
            else:
                up = socket.create_connection((host, int(port or 443)), timeout=30)
            self.send_response(200, "Connection Established")
            self.end_headers()
            _relay_sockets(self.connection, up)
        except Exception as e:
            g.log({"method": "CONNECT", "host": hostport, "verdict": "upstream_error",
                   "error": str(e)[:160]})
            return self._respond(502, "strix-guard: CONNECT failed")
        g.log({"method": "CONNECT", "host": hostport, "verdict": "allow_tunnel"})


def _read_headers(sock) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            return b""
        data += chunk
    return data


def _relay_sockets(a, b):
    socks = [a, b]
    try:
        while True:
            r, _, x = select.select(socks, [], socks, 300)
            if x or not r:
                return
            for s in r:
                try:
                    data = s.recv(65536)
                except Exception:
                    data = b""
                if not data:
                    return
                (b if s is a else a).sendall(data)
    finally:
        try:
            b.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:48081")
    ap.add_argument("--upstream", default="127.0.0.1:48080")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--ready", required=True)
    args = ap.parse_args()
    with open(args.policy, encoding="utf-8") as f:
        policy = json.load(f)
    if args.upstream:
        uh, _, up = args.upstream.rpartition(":")
        policy["upstream_host"] = uh or "127.0.0.1"
        policy["upstream_port"] = int(up or 0)
    host, _, port = args.listen.rpartition(":")
    guard = Guard(policy, args.log)
    httpd = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
    httpd.guard = guard
    try:
        open(args.ready, "w").write("ready\n")
    except Exception:
        pass
    httpd.serve_forever()


if __name__ == "__main__":
    main()
