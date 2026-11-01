import json
import os
import tempfile
import unittest

from strix_guard.setup import run_setup


def _driver(answers):
    it = iter(answers)

    def input_fn(_prompt):
        return next(it)

    return input_fn, (lambda *a, **k: None)


class TestSetup(unittest.TestCase):
    def test_benchmark_defaults_full_policy(self):
        input_fn, out = _driver(["benchmark", "", "", "", "", "", "", "alice,bob", "y"])
        res = run_setup(input_fn=input_fn, output_fn=out)
        self.assertEqual(res.environment, "benchmark")
        self.assertEqual(res.policy_preset, "full")
        self.assertEqual(res.policy_file, "")
        self.assertEqual(res.test_accounts, ["alice", "bob"])

    def test_production_defaults_reference_only(self):
        input_fn, out = _driver(["production", "", "", "", "", "", "", "", "y"])
        res = run_setup(input_fn=input_fn, output_fn=out)
        self.assertEqual(res.policy_preset, "reference_only")

    def test_custom_policy_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "policy.json")
            with open(path, "w") as f:
                json.dump({"preset": "reference_only"}, f)
            input_fn, out = _driver(["benchmark", "custom", path, "", "", "", "", "", "", "y"])
            res = run_setup(input_fn=input_fn, output_fn=out)
        self.assertEqual(res.policy_preset, "custom")
        self.assertEqual(res.policy_file, path)


if __name__ == "__main__":
    unittest.main()
