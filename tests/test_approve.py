import json
import os
import subprocess
import sys
import tempfile
import unittest


class TestApproveHelper(unittest.TestCase):
    def _run(self, keys: str, timeout_s: float = 5, env_extra: dict | None = None):
        d = tempfile.mkdtemp()
        payload = os.path.join(d, "p.json")
        decision = os.path.join(d, "d.json")
        json.dump({"card": "テストカード", "cmd": "ffuf -t 50 ...",
                   "summary": {"verdict": "REVISE"}}, open(payload, "w", encoding="utf-8"))
        env = dict(os.environ)
        env.pop("STRIX_GUARD_LANG", None)
        if env_extra:
            env.update(env_extra)
        proc = subprocess.run(
            [sys.executable, "-m", "strix_guard.approve", payload, decision, str(timeout_s)],
            input=keys, capture_output=True, text=True, timeout=30, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
        return json.load(open(decision, encoding="utf-8")), proc.stdout

    def test_allow(self):
        d, out = self._run("a\n")
        self.assertEqual(d["action"], "allow")
        self.assertIn("テストカード", out)

    def test_pattern(self):
        d, _ = self._run("p\n")
        self.assertEqual(d["action"], "allow")
        self.assertTrue(d["cache_pattern"])

    def test_deny(self):
        d, _ = self._run("d\n")
        self.assertEqual(d["action"], "deny")

    def test_revise(self):
        d, _ = self._run("e\n並列10\n")
        self.assertEqual(d["action"], "revise")
        self.assertIn("並列10", d["message"])

    def test_timeout_denies(self):
        d = tempfile.mkdtemp()
        payload = os.path.join(d, "p.json")
        decision = os.path.join(d, "d.json")
        json.dump({"card": "c", "cmd": "x", "summary": {}}, open(payload, "w", encoding="utf-8"))
        p = subprocess.Popen(
            [sys.executable, "-m", "strix_guard.approve", payload, decision, "1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        p.wait(timeout=15)
        res = json.load(open(decision, encoding="utf-8"))
        self.assertEqual(res["action"], "deny")
        self.assertIn("timed out", res["message"])

    def test_eof_denies(self):
        d, _ = self._run("")
        self.assertEqual(d["action"], "deny")
        self.assertIn("input closed", d["message"])

    def test_japanese_labels(self):
        d, out = self._run("a\n", env_extra={"STRIX_GUARD_LANG": "ja"})
        self.assertEqual(d["action"], "allow")
        self.assertIn("1回だけ許可", out)


if __name__ == "__main__":
    unittest.main()
