import http.client
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from strix_guard.docker_proxy import DockerProxy, _rewrite_notice, _set_proxy_env


class MockDocker(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    hits = {"ping": 0, "exec": 0}
    last_exec_body = None

    def log_message(self, *a):
        pass

    def _send(self, status, body: bytes, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.endswith("/_ping"):
            MockDocker.hits["ping"] += 1
            return self._send(200, b"OK", "text/plain")
        if self.path.endswith("/containers/json"):
            return self._send(200, b"[]")
        return self._send(404, b'{"message":"not found"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        if "/exec" in self.path:
            MockDocker.hits["exec"] += 1
            MockDocker.last_exec_body = json.loads(body or b"{}")
            return self._send(201, b'{"Id":"exec-123"}')
        return self._send(404, b'{"message":"not found"}')


def rule_judge(container_id, cmd_argv, spec):
    cmd = " ".join(cmd_argv)
    if "rm -rf" in cmd:
        return ("deny", "[strix-guard instruction] destructive command denied")
    if "range(10000)" in cmd:
        return ("revise", "[strix-guard instruction] reduce to <=500 requests")
    return ("allow", None)


class TestDockerProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.up = ThreadingHTTPServer(("127.0.0.1", 0), MockDocker)
        cls.up_thread = threading.Thread(target=cls.up.serve_forever, daemon=True)
        cls.up_thread.start()
        cls.up_addr = cls.up.server_address
        cls.proxy = DockerProxy(upstream=("tcp", cls.up_addr[0], cls.up_addr[1]),
                                on_exec=rule_judge).start()
        cls.proxy_addr = cls.proxy.address

    @classmethod
    def tearDownClass(cls):
        cls.proxy.stop()
        cls.up.shutdown()
        cls.up.server_close()

    def _req(self, method, path, body=None):
        conn = http.client.HTTPConnection(self.proxy_addr[0], self.proxy_addr[1], timeout=10)
        conn.request(method, path, body=body)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def test_passthrough_ping(self):
        status, data = self._req("GET", "/v1.45/_ping")
        self.assertEqual(status, 200)
        self.assertEqual(data, b"OK")
        self.assertGreaterEqual(MockDocker.hits["ping"], 1)

    def test_exec_allow_forwarded(self):
        body = json.dumps({"Cmd": ["echo", "hi"], "AttachStdout": True}).encode()
        status, data = self._req("POST", "/v1.45/containers/abc/exec", body)
        self.assertEqual(status, 201)
        self.assertIn("exec-123", data.decode())
        self.assertEqual(MockDocker.last_exec_body["Cmd"], ["echo", "hi"])

    def test_exec_deny_rewritten_to_notice(self):
        body = json.dumps({"Cmd": ["rm", "-rf", "/"]}).encode()
        status, data = self._req("POST", "/v1.45/containers/abc/exec", body)
        self.assertEqual(status, 201)
        cmd = " ".join(MockDocker.last_exec_body["Cmd"])
        self.assertIn("destructive command denied", cmd)
        self.assertNotIn("rm -rf", cmd)
        self.assertIn("exit 1", cmd)

    def test_exec_revise_delivers_instruction(self):
        body = json.dumps({"Cmd": ["python3", "-c", "for i in range(10000): pass"]}).encode()
        status, data = self._req("POST", "/v1.45/containers/abc/exec", body)
        self.assertEqual(status, 201)
        cmd = " ".join(MockDocker.last_exec_body["Cmd"])
        self.assertIn("reduce to <=500", cmd)
        self.assertNotIn("range(10000)", cmd)

    def test_allow_rewrites_exec_env(self):
        p = DockerProxy(upstream=("tcp", self.up_addr[0], self.up_addr[1]),
                        on_exec=rule_judge, exec_env_proxy="http://127.0.0.1:48081").start()
        try:
            addr = p.address
            conn = http.client.HTTPConnection(addr[0], addr[1], timeout=10)
            body = json.dumps({"Cmd": ["echo", "hi"],
                               "Env": ["http_proxy=http://127.0.0.1:48080", "A=1"]}).encode()
            conn.request("POST", "/v1.45/containers/abc/exec", body=body)
            conn.getresponse().read()
            conn.close()
            env = MockDocker.last_exec_body["Env"]
            self.assertIn("A=1", env)
            self.assertIn("http_proxy=http://127.0.0.1:48081", env)
            self.assertFalse(any(e == "http_proxy=http://127.0.0.1:48080" for e in env))
        finally:
            p.stop()


class TestProxyEnv(unittest.TestCase):
    def test_replaces_proxy_env(self):
        spec = {"Env": ["http_proxy=http://127.0.0.1:48080", "FOO=bar"]}
        out = _set_proxy_env(spec, "http://127.0.0.1:48081")
        env = out["Env"]
        self.assertIn("FOO=bar", env)
        self.assertIn("http_proxy=http://127.0.0.1:48081", env)
        self.assertIn("NO_PROXY=localhost,127.0.0.1,api.caido.io", env)
        self.assertFalse(any(e.startswith("http_proxy=http://127.0.0.1:48080") for e in env))


class TestNoticeRewrite(unittest.TestCase):
    def test_preserves_pty_wrapper(self):
        wrapper = ('sh -lc mkdir -p "$1" && printf "%s" "$$" > "$2" && shift 2 && exec "$@" '
                   'sh /tmp/sandbox-docker-archive /tmp/x_pty.pid bash -lc rm -rf /')
        spec = {"Cmd": ["bash", "-lc", wrapper], "Tty": True}
        out = _rewrite_notice(spec, "denied")
        text = out["Cmd"][-1]
        self.assertIn("sandbox-docker-archive", text)
        self.assertIn("_pty.pid bash -lc printf", text)
        self.assertNotIn("rm -rf", text)
        self.assertTrue(out["AttachStdout"])
        self.assertTrue(out["AttachStderr"])
        self.assertTrue(out["Tty"])

    def test_plain_command_rewritten(self):
        out = _rewrite_notice({"Cmd": ["bash", "-lc", "curl -X POST http://h/x"]}, "no")
        self.assertEqual(out["Cmd"][:2], ["sh", "-c"])
        self.assertIn("printf", out["Cmd"][2])
        self.assertNotIn("curl", out["Cmd"][2])
        self.assertFalse(out["Tty"])

    def test_quotes_are_safe(self):
        out = _rewrite_notice({"Cmd": ["rm", "-rf", "/"]}, "it's blocked")
        text = out["Cmd"][2]
        self.assertIn("blocked", text)
        self.assertIn("it", text)


if __name__ == "__main__":
    unittest.main()
