import json
import os
import shutil
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from strix_guard.policy_config import resolve_policy
from strix_guard.sidecar_manager import make_hooks, prepare, target_hosts_from_args


class FakeDocker(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    calls = []

    def log_message(self, *a):
        pass

    def _send(self, status, obj=None):
        data = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.endswith("/version"):
            return self._send(200, {"ApiVersion": "1.56"})
        return self._send(404, {"message": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        FakeDocker.calls.append((self.path, body))
        if "/containers/cid/exec" in self.path:
            return self._send(201, {"Id": "e1"})
        if "/exec/e1/start" in self.path:
            return self._send(204)
        return self._send(404, {"message": "not found"})


class TestSidecarManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.up = ThreadingHTTPServer(("127.0.0.1", 0), FakeDocker)
        threading.Thread(target=cls.up.serve_forever, daemon=True).start()
        cls.up_addr = cls.up.server_address

    @classmethod
    def tearDownClass(cls):
        cls.up.shutdown()
        cls.up.server_close()

    def setUp(self):
        FakeDocker.calls = []
        self.policy = resolve_policy("reference_only")
        self.sidecar = prepare(self.policy, ["http://host.docker.internal:5000"])

    def tearDown(self):
        if self.sidecar:
            shutil.rmtree(self.sidecar["base"], ignore_errors=True)

    def test_target_hosts(self):
        hosts = target_hosts_from_args(["http://host.docker.internal:5000", "x"])
        self.assertIn("host.docker.internal", hosts)
        self.assertIn("host.docker.internal:5000", hosts)

    def test_prepare_writes_script_and_policy(self):
        self.assertIsNotNone(self.sidecar)
        app = self.sidecar["app_dir"]
        self.assertTrue(os.path.exists(os.path.join(app, "http_sidecar.py")))
        with open(os.path.join(app, "policy.json")) as f:
            policy = json.load(f)
        self.assertEqual(policy["allowed_methods"], ["GET", "HEAD", "OPTIONS"])
        self.assertIn("host.docker.internal:5000", policy["allowed_hosts"])

    def test_full_preset_has_no_sidecar(self):
        self.assertIsNone(prepare(resolve_policy("full"), ["http://host.docker.internal:5000"]))

    def test_on_container_create_sets_env_and_binds(self):
        on_create, _ = make_hooks(self.sidecar, ("tcp", self.up_addr[0], self.up_addr[1]), lambda r: None)
        spec = {"Env": ["http_proxy=http://127.0.0.1:48080", "FOO=bar"],
                "HostConfig": {"Binds": ["/a:/b"]}}
        out = on_create(spec)
        self.assertIn("FOO=bar", out["Env"])
        self.assertIn("http_proxy=http://127.0.0.1:48081", out["Env"])
        self.assertIn("NO_PROXY=localhost,127.0.0.1,api.caido.io", out["Env"])
        self.assertTrue(any(":/opt/strix-guard:ro" in b for b in out["HostConfig"]["Binds"]))
        self.assertTrue(any(":/var/log/strix-guard:rw" in b for b in out["HostConfig"]["Binds"]))

    def test_on_container_start_launches_sidecar(self):
        on_create, on_start = make_hooks(
            self.sidecar, ("tcp", self.up_addr[0], self.up_addr[1]), lambda r: None)
        ready = os.path.join(self.sidecar["log_dir"], "ready-cid")
        open(ready, "w").close()
        on_start("cid")
        paths = [p for p, _ in FakeDocker.calls]
        self.assertTrue(any("/containers/cid/exec" in p for p in paths))
        self.assertTrue(any("/exec/e1/start" in p for p in paths))
        exec_body = [b for p, b in FakeDocker.calls if "/containers/cid/exec" in p][0]
        self.assertIn("http_sidecar.py", " ".join(exec_body["Cmd"]))


if __name__ == "__main__":
    unittest.main()
