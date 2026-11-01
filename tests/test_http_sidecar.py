import http.client
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from strix_guard.http_sidecar import Guard, Handler


class FakeUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen = []

    def log_message(self, *a):
        pass

    def _respond(self, status=200, body=b"ok"):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        FakeUpstream.seen.append(("GET", self.path))
        self._respond(200, b"upstream-get")

    def do_POST(self):
        FakeUpstream.seen.append(("POST", self.path))
        self._respond(200, b"upstream-post")


class TestHttpSidecar(unittest.TestCase):
    def setUp(self):
        FakeUpstream.seen = []
        self.up = ThreadingHTTPServer(("127.0.0.1", 0), FakeUpstream)
        threading.Thread(target=self.up.serve_forever, daemon=True).start()
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "http.jsonl")
        policy = {
            "allowed_methods": ["GET", "HEAD", "OPTIONS"],
            "allowed_hosts": ["example.test"],
            "infra_hosts": ["127.0.0.1:48080"],
            "max_requests": 10,
            "max_parallel": 5,
            "max_rps": 100,
            "allow_connect": False,
            "upstream_host": "127.0.0.1",
            "upstream_port": self.up.server_address[1],
        }
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.guard = Guard(policy, self.log)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addr = self.httpd.server_address

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.up.shutdown()
        self.up.server_close()
        self.tmp.cleanup()

    def _req(self, method, path):
        conn = http.client.HTTPConnection(self.addr[0], self.addr[1], timeout=10)
        conn.request(method, path)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def test_get_forwarded_to_upstream(self):
        status, data = self._req("GET", "http://example.test/x")
        self.assertEqual(status, 200)
        self.assertEqual(data, b"upstream-get")
        self.assertIn(("GET", "http://example.test/x"), FakeUpstream.seen)

    def test_post_blocked(self):
        status, data = self._req("POST", "http://example.test/login")
        self.assertEqual(status, 403)
        self.assertIn(b"method_not_allowed", data)
        self.assertNotIn(("POST", "http://example.test/login"), FakeUpstream.seen)

    def test_host_not_allowed(self):
        status, data = self._req("GET", "http://evil.test/x")
        self.assertEqual(status, 403)
        self.assertIn(b"host_not_allowed", data)

    def test_infra_host_bypasses_method_check(self):
        status, data = self._req("POST", "http://127.0.0.1:48080/graphql")
        self.assertEqual(status, 200)
        self.assertIn(("POST", "http://127.0.0.1:48080/graphql"), FakeUpstream.seen)

    def test_log_records_verdicts(self):
        self._req("GET", "http://example.test/x")
        self._req("POST", "http://example.test/login")
        lines = [json.loads(l) for l in open(self.log)]
        verdicts = {d["verdict"] for d in lines}
        self.assertIn("allow", verdicts)
        self.assertIn("method_not_allowed", verdicts)

    def test_request_cap(self):
        self.httpd.guard.policy["max_requests"] = 1
        self.assertEqual(self._req("GET", "http://example.test/1")[0], 200)
        status, data = self._req("GET", "http://example.test/2")
        self.assertEqual(status, 403)
        self.assertIn(b"request_cap", data)

    def test_connect_blocked_when_disallowed(self):
        conn = http.client.HTTPConnection(self.addr[0], self.addr[1], timeout=10)
        conn.request("CONNECT", "example.test:443")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 403)
        conn.close()

    def test_connect_host_check_when_allowed(self):
        policy = dict(self.httpd.guard.policy)
        policy["allow_connect"] = True
        g = Guard(policy, self.log)
        ok, reason = g.check("CONNECT", "example.test:443", "example.test",
                             enforce_method=False)
        self.assertTrue(ok)
        self.assertEqual(reason, "allow")
        ok, reason = g.check("CONNECT", "evil.test:443", "evil.test",
                             enforce_method=False)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
