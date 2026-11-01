import json
import os
import tempfile
import unittest

from strix_guard.policy import RiskVector
from strix_guard.policy_config import (
    PRESETS,
    policy_summary,
    resolve_policy,
    review_band_hits,
    validate_policy,
    write_snapshot,
)


class TestPolicyConfig(unittest.TestCase):
    def test_reference_only_preset(self):
        p = resolve_policy("reference_only")
        self.assertEqual(p["http"]["allowed_methods"], ["GET", "HEAD", "OPTIONS"])
        self.assertFalse(p["http"]["allow_uploads"])
        self.assertFalse(p["data"]["allow_writes"])
        self.assertFalse(p["egress"]["allow_external"])

    def test_file_overrides_preset(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "policy.json")
            with open(path, "w") as f:
                json.dump({"preset": "reference_only",
                           "review_band": {"load": 0.5},
                           "http": {"max_requests": 123}}, f)
            p = resolve_policy("full", path)
        self.assertEqual(p["preset"], "reference_only")
        self.assertEqual(p["http"]["max_requests"], 123)
        self.assertEqual(p["review_band"]["load"], 0.5)
        self.assertEqual(p["http"]["allowed_methods"], ["GET", "HEAD", "OPTIONS"])

    def test_unknown_key_rejected(self):
        with self.assertRaises(ValueError):
            validate_policy({"nope": 1})

    def test_invalid_method_rejected(self):
        with self.assertRaises(ValueError):
            validate_policy({"http": {"allowed_methods": ["FETCH"]}})

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            resolve_policy("full", "/nonexistent/policy.json")

    def test_review_band_hits(self):
        p = resolve_policy("full")
        risk = RiskVector(destructiveness=0.4, load=0.1, data_exposure=0.3)
        dims = {h["dimension"] for h in review_band_hits(risk, p)}
        self.assertIn("destructiveness", dims)
        self.assertIn("data_exposure", dims)
        self.assertNotIn("load", dims)

    def test_review_band_can_be_disabled(self):
        p = resolve_policy("full")
        p["review_band"] = {}
        self.assertEqual(review_band_hits(RiskVector(destructiveness=1.0), p), [])

    def test_summary_omits_accounts(self):
        p = resolve_policy("full")
        p["data"]["allowed_test_accounts"] = ["secret-user"]
        s = json.dumps(policy_summary(p))
        self.assertNotIn("secret-user", s)
        self.assertIn("allowed_methods", s)

    def test_snapshot(self):
        p = resolve_policy("reference_only")
        with tempfile.TemporaryDirectory() as td:
            sha = write_snapshot(p, td)
            with open(os.path.join(td, "policy.json")) as f:
                self.assertEqual(json.load(f)["preset"], "reference_only")
        self.assertEqual(len(sha), 64)

    def test_preset_custom_falls_back_to_base(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "policy.json")
            with open(path, "w") as f:
                json.dump({"preset": "custom",
                           "http": {"max_requests": 77}}, f)
            p = resolve_policy("reference_only", path)
        self.assertEqual(p["preset"], "reference_only")
        self.assertEqual(p["http"]["max_requests"], 77)


if __name__ == "__main__":
    unittest.main()
