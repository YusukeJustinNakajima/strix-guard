import json
import threading
import time
import unittest
import urllib.error
import urllib.request

from strix_guard.webui import ApprovalBroker, WebApprovalServer


class TestBroker(unittest.TestCase):
    def test_decision_roundtrip(self):
        b = ApprovalBroker(timeout_s=5)
        result = {}

        def worker():
            result["d"] = b.request({"card": "c", "cmd": "x", "summary": {}})

        t = threading.Thread(target=worker)
        t.start()
        time.sleep(0.2)
        snap = b.snapshot()
        self.assertEqual(len(snap), 1)
        pid = snap[0]["id"]
        self.assertTrue(b.decide(pid, {"action": "allow", "cache_pattern": True}))
        t.join(timeout=5)
        self.assertEqual(result["d"]["action"], "allow")
        self.assertTrue(result["d"]["cache_pattern"])

    def test_timeout_denies(self):
        b = ApprovalBroker(timeout_s=0.5)
        d = b.request({"card": "", "cmd": "x", "summary": {}})
        self.assertEqual(d["action"], "deny")
        self.assertIn("timed out", d["message"])


class TestWebServer(unittest.TestCase):
    def setUp(self):
        self.broker = ApprovalBroker(timeout_s=5)
        self.srv = WebApprovalServer(self.broker).start()
        self.base = self.srv.url().split("/?")[0]
        self.token = self.srv.token

    def tearDown(self):
        self.srv.stop()

    def test_forbidden_without_token(self):
        try:
            with urllib.request.urlopen(self.base + "/api/pending") as r:
                r.read()
            self.fail("expected 403")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)

    def test_page_contains_buttons_and_safe_layout(self):
        with urllib.request.urlopen(f"{self.base}/?t={self.token}") as r:
            page = r.read().decode()
        self.assertEqual(page.count("<button"), 4)
        self.assertIn("repeat(auto-fit", page)
        self.assertIn("white-space:pre-wrap", page)
        self.assertIn("grid-column:1/-1", page)
        # 入力中に再描画でフォーカス/内容を壊さない仕組み
        self.assertIn("lastSig", page)
        self.assertIn("sigOf", page)
        self.assertIn("Allow once", page)

    def test_page_language_ja(self):
        srv = WebApprovalServer(ApprovalBroker(timeout_s=5), lang="ja").start()
        try:
            base = srv.url().split("/?")[0]
            with urllib.request.urlopen(f"{base}/?t={srv.token}") as r:
                page = r.read().decode()
            self.assertIn("1回だけ許可", page)
        finally:
            srv.stop()

    def test_pending_and_decide(self):
        result = {}
        t = threading.Thread(target=lambda: result.update(
            d=self.broker.request({"card": "c", "cmd": "x", "summary": {}})))
        t.start()
        time.sleep(0.2)
        with urllib.request.urlopen(self.base + f"/api/pending?t={self.token}") as r:
            data = json.loads(r.read())
        self.assertEqual(len(data["pending"]), 1)
        pid = data["pending"][0]["id"]
        req = urllib.request.Request(
            self.base + f"/api/decide?t={self.token}",
            data=json.dumps({"id": pid, "action": "allow"}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.status, 200)
        t.join(timeout=5)
        self.assertEqual(result["d"]["action"], "allow")


if __name__ == "__main__":
    unittest.main()
