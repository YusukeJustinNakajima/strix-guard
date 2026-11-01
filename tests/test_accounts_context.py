import unittest

from strix_guard.adjudicator import SYSTEM as ADJ_SYSTEM
from strix_guard.decision import DecisionService


class CapturingService(DecisionService):
    def __init__(self, **kw):
        super().__init__(api_key="k", use_jev=True, **kw)
        self.bodies = []

    def _call_decisions(self, body):
        self.bodies.append(body)
        return {"answers": {
            "destructiveness": {"type": "score", "probabilities": {"0": 1.0, "1": 0.0}},
            "load": {"type": "score", "probabilities": {"0": 1.0, "1": 0.0}},
            "data_exposure": {"type": "score", "probabilities": {"0": 1.0, "1": 0.0}},
            "scope_violation": {"type": "score", "probabilities": {"0": 1.0, "1": 0.0}},
            "third_party": {"type": "score", "probabilities": {"0": 1.0, "1": 0.0}},
            "sufficiency": {"type": "choice", "choice": "sufficient"},
        }}


class TestAccountsContext(unittest.TestCase):
    def test_jev_state_contains_accounts(self):
        svc = CapturingService(test_accounts=["alice", "bob"])
        svc.assess("python3 script.py")
        st = svc.bodies[0]["state"]
        self.assertEqual(st["allowed_test_accounts"], ["alice", "bob"])
        self.assertIn("account_policy", st)

    def test_jev_state_omits_when_empty(self):
        svc = CapturingService(test_accounts=[])
        svc.assess("python3 script.py")
        self.assertNotIn("allowed_test_accounts", svc.bodies[0]["state"])

    def test_adjudicator_prompt_mentions_accounts(self):
        self.assertIn("allowed_test_accounts", ADJ_SYSTEM)


if __name__ == "__main__":
    unittest.main()
