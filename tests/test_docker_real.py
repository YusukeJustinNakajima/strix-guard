"""実Docker(/var/run/docker.sock)に対する統合テスト。

- /var/run/docker.sock が無い環境では skip
- 小さなコンテナを作成し、exec create がガードでブロックできることを実証する
"""
import http.client
import json
import os
import unittest

from strix_guard.docker_proxy import DockerProxy

SOCK = "/var/run/docker.sock"


def rule_judge(container_id, cmd_argv, spec):
    cmd = " ".join(cmd_argv)
    if "rm -rf /" in cmd:
        return ("deny", "[strix-guard instruction] destructive command denied")
    return ("allow", None)


@unittest.skipUnless(os.path.exists(SOCK), "docker.sock not available")
class TestRealDocker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy = DockerProxy(upstream=("unix", SOCK), on_exec=rule_judge).start()
        cls.addr = cls.proxy.address
        status, ver = cls._raw(cls.addr, "GET", "/version")
        if status != 200:
            raise unittest.SkipTest(f"cannot talk to docker: {status}")
        cls.api = "/v" + json.loads(ver)["ApiVersion"]
        cls.container_id = None

    @classmethod
    def tearDownClass(cls):
        if cls.container_id:
            cls._raw(cls.addr, "DELETE", f"{cls.api}/containers/{cls.container_id}?force=1")
        cls.proxy.stop()

    @staticmethod
    def _raw(addr, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection(addr[0], addr[1], timeout=30)
        hdrs = dict(headers or {})
        if body is not None:
            hdrs.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def _req(self, method, path, body=None):
        return self._raw(self.addr, method, path, body)

    def test_01_ping_via_proxy(self):
        status, _ = self._req("GET", f"{self.api}/_ping")
        self.assertEqual(status, 200)

    def test_02_create_container(self):
        status, data = self._req("GET", f"{self.api}/images/json")
        self.assertEqual(status, 200)
        images = json.loads(data)
        if not images:
            self.skipTest("no local images")
        tag = images[0].get("RepoTags", [None])[0] or images[0]["Id"]
        body = json.dumps({"Image": tag, "Cmd": ["sleep", "120"]}).encode()
        status, data = self._req("POST", f"{self.api}/containers/create", body)
        self.assertEqual(status, 201, data[:200])
        TestRealDocker.container_id = json.loads(data)["Id"]
        status, _ = self._req("POST", f"{self.api}/containers/{self.container_id}/start")
        self.assertIn(status, (204, 304))

    def test_03_exec_denied_rewritten_to_notice(self):
        self.assertIsNotNone(self.container_id, "container not created")
        body = json.dumps({"Cmd": ["rm", "-rf", "/"], "AttachStdout": True}).encode()
        status, data = self._req("POST", f"{self.api}/containers/{self.container_id}/exec", body)
        self.assertEqual(status, 201, data[:200])
        eid = json.loads(data)["Id"]
        st, d = self._req("GET", f"{self.api}/exec/{eid}/json")
        self.assertEqual(st, 200)
        spec = json.loads(d)
        pc = spec.get("ProcessConfig") or {}
        cmd = " ".join([pc.get("entrypoint") or ""] + list(pc.get("arguments") or []))
        self.assertIn("destructive command denied", cmd)
        self.assertNotIn("rm -rf", cmd)

    def test_04_exec_allowed_created(self):
        self.assertIsNotNone(self.container_id, "container not created")
        body = json.dumps({"Cmd": ["echo", "hello"], "AttachStdout": True,
                           "AttachStderr": True}).encode()
        status, data = self._req("POST", f"{self.api}/containers/{self.container_id}/exec", body)
        self.assertEqual(status, 201, data[:200])
        self.assertIn("Id", json.loads(data))

    def test_05_denied_exec_output_carries_notice(self):
        self.assertIsNotNone(self.container_id, "container not created")
        body = json.dumps({"Cmd": ["rm", "-rf", "/"], "AttachStdout": True,
                           "AttachStderr": True}).encode()
        status, data = self._req("POST", f"{self.api}/containers/{self.container_id}/exec", body)
        self.assertEqual(status, 201, data[:200])
        eid = json.loads(data)["Id"]
        conn = http.client.HTTPConnection(self.addr[0], self.addr[1], timeout=30)
        conn.request("POST", f"{self.api}/exec/{eid}/start",
                     body=json.dumps({"Detach": False, "Tty": False}).encode(),
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        text = b""
        i = 0
        while i + 8 <= len(raw):
            size = int.from_bytes(raw[i + 4:i + 8], "big")
            text += raw[i + 8:i + 8 + size]
            i += 8 + size
        if not text:
            text = raw
        decoded = text.decode("utf-8", "replace")
        self.assertIn("denied", decoded.lower())
        status, data = self._req("GET", f"{self.api}/exec/{eid}/json")
        self.assertEqual(status, 200)
        self.assertNotEqual(json.loads(data).get("ExitCode"), 0)


if __name__ == "__main__":
    unittest.main()
