import unittest

from strix_guard.adjudicator import Adjudicator, _parse_json
from strix_guard.policy import PolicyDecision, RiskVector, Verdict


class StubAdjudicator(Adjudicator):
    def __init__(self, response: str):
        super().__init__("test-key", model="stub", max_calls=10)
        self.response = response

    def _call(self, body):
        return {"model": "stub",
                "usage": {"cost": 0.001},
                "choices": [{"message": {"content": self.response}}]}


class TestAdjudicator(unittest.TestCase):
    def _risk(self):
        return RiskVector(load=0.6)

    def _decision(self):
        return PolicyDecision(Verdict.REVISE, ["high_load"], {"max_parallel": 10})

    def test_parses_fenced_json(self):
        a = StubAdjudicator(
            '```json\n{"action":"revise","constraints":{"max_parallel":10},'
            '"instruction_for_agent":"reduce parallelism","needs_more_info":[],'
            '"rationale":"high load","confidence":0.9}\n```')
        out = a.adjudicate(cmd="ffuf -t 50", script_content=None,
                           risk=self._risk(), decision=self._decision())
        self.assertEqual(out["action"], "revise")
        self.assertEqual(out["constraints"]["max_parallel"], 10)
        self.assertEqual(a.calls, 1)
        self.assertAlmostEqual(a.cost, 0.001)

    def test_budget_cap_denies(self):
        a = StubAdjudicator('{"action":"allow","confidence":0.9}')
        a.max_calls = 0
        out = a.adjudicate(cmd="x", script_content=None,
                           risk=self._risk(), decision=self._decision())
        self.assertEqual(out["action"], "deny")
        self.assertIn("budget", out["rationale"])

    def test_unparseable_returns_none(self):
        a = StubAdjudicator("not json at all")
        self.assertIsNone(a.adjudicate(cmd="x", script_content=None,
                                       risk=self._risk(), decision=self._decision()))

    def test_parse_json_plain(self):
        self.assertEqual(_parse_json('{"a":1}')["a"], 1)


class SequenceAdjudicator(Adjudicator):
    def __init__(self, responses):
        super().__init__("test-key", model="primary",
                         fallback_models=["fallback1", "fallback2"], max_calls=10)
        self.responses = list(responses)

    def _call(self, body):
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok(action="revise", cost=0.002):
    return {"model": "fallback1", "usage": {"cost": cost},
            "choices": [{"message": {"content": (
                '{"action":"%s","constraints":{},"instruction_for_agent":"x",'
                '"needs_more_info":[],"rationale":"ok","confidence":0.8}' % action)}}]}


def _refusal():
    return {"error": {"code": 403, "message": "cyber policy",
                      "metadata": {"error_type": "refusal", "provider_code": "cyber_policy"}}}


class TestAdjudicatorFallback(unittest.TestCase):
    def _risk(self):
        return RiskVector(load=0.6)

    def _decision(self):
        return PolicyDecision(Verdict.REVISE, ["high_load"], {"max_parallel": 10})

    def _run(self, responses):
        a = SequenceAdjudicator(responses)
        return a, a.adjudicate(cmd="x", script_content="print(1)",
                               risk=self._risk(), decision=self._decision())

    def test_provider_refusal_uses_fallback(self):
        a, out = self._run([_refusal(), _ok()])
        self.assertEqual(out["action"], "revise")
        self.assertTrue(out["fallback"])
        self.assertEqual(out["model"], "fallback1")
        self.assertEqual(a.calls, 2)
        self.assertIsNone(a.last_error)

    def test_request_error_uses_fallback(self):
        a, out = self._run([RuntimeError("boom"), _ok()])
        self.assertEqual(out["action"], "revise")
        self.assertTrue(out["fallback"])

    def test_unparseable_retries_then_falls_back(self):
        bad = {"choices": [{"message": {"content": "not json"}}]}
        a, out = self._run([bad, bad, _ok()])
        self.assertEqual(out["action"], "revise")
        self.assertTrue(out["fallback"])
        self.assertEqual(a.calls, 3)

    def test_all_models_fail_records_reason(self):
        a, out = self._run([_refusal(), _refusal(), _refusal()])
        self.assertIsNone(out)
        self.assertIn("cyber_policy", a.last_error)
        self.assertEqual(a.calls, 3)


if __name__ == "__main__":
    unittest.main()
