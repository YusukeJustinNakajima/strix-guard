import unittest

from strix_guard.policy import RiskVector, Verdict, decide, ui_label, sandbox_internal


class TestSandboxInternal(unittest.TestCase):
    def test_bootstrap_helper_allowed(self):
        self.assertTrue(sandbox_internal("sh -c # INSTALL_RUNTIME_HELPER_V1\nset -eu\n..."))

    def test_local_checks_allowed(self):
        self.assertTrue(sandbox_internal("test -x /tmp/openai-agents/bin/resolve-workspace-path-f8e24896b498"))
        self.assertTrue(sandbox_internal("mkdir -p /workspace/recon && cd /workspace/recon"))
        self.assertTrue(sandbox_internal("rm -f /tmp/a.txt"))

    def test_sandbox_archive_cleanup_allowed(self):
        self.assertTrue(sandbox_internal(
            "rm -rf -- /tmp/sandbox-docker-archive/1bcc9890377d4d698e85661df997e2e8_probe_auth.py"))

    def test_sdk_helper_execution_allowed(self):
        self.assertTrue(sandbox_internal(
            "/tmp/openai-agents/bin/resolve-workspace-path-f8e24896b498 /workspace /workspace 1"))

    def test_sdk_file_write_helper_allowed(self):
        cmd = ('sh -c n=$1; shift; [ "$(printf ab | head -c 1 2>/dev/null)" = a ] || exit 98; '
               'head -c "$n" | "$@" sh 2807 sh -lc cat > "$1" sh /tmp/x')
        self.assertTrue(sandbox_internal(cmd))

    def test_network_not_internal(self):
        self.assertFalse(sandbox_internal("curl -s http://host.docker.internal:5000/"))
        self.assertFalse(sandbox_internal("test -x /tmp/x && curl http://host.docker.internal:5000/"))

    def test_destructive_outside_local_denied(self):
        self.assertFalse(sandbox_internal("rm -rf /etc"))
        self.assertFalse(sandbox_internal("rm -rf /workspace/../etc"))  # チェーンは許可しない

    def test_heredoc_not_auto_allowed(self):
        self.assertFalse(sandbox_internal("cat > /tmp/x.sh <<'EOF'\nrm -rf /\nEOF"))


class TestNormalizeRisk(unittest.TestCase):
    def test_in_scope_urls_cap_third_party(self):
        from strix_guard.decision import normalize_risk
        r = RiskVector(third_party=0.9, scope_violation=0.9)
        normalize_risk(r, "ffuf -u http://host.docker.internal:5000/FUZZ -w x")
        self.assertLessEqual(r.third_party, 0.2)
        self.assertLessEqual(r.scope_violation, 0.2)

    def test_external_url_not_capped(self):
        from strix_guard.decision import normalize_risk
        r = RiskVector(third_party=0.9, scope_violation=0.9)
        normalize_risk(r, "curl https://example.com/x")
        self.assertEqual(r.third_party, 0.9)

    def test_oast_marker_keeps_high(self):
        from strix_guard.decision import normalize_risk
        r = RiskVector(third_party=0.9)
        normalize_risk(r, "curl http://host.docker.internal:5000/x?u=http://abc.oast.pro/")
        self.assertEqual(r.third_party, 0.9)

    def test_local_no_url_cap(self):
        from strix_guard.decision import normalize_risk
        r = RiskVector(third_party=0.9, scope_violation=0.9)
        normalize_risk(r, "rm -rf /tmp/x")
        self.assertLessEqual(r.third_party, 0.2)


class TestDataPolicy(unittest.TestCase):
    def test_benchmark_test_data_capped(self):
        from strix_guard.decision import apply_data_policy
        r = RiskVector(data_exposure=0.9)
        apply_data_policy(r, "benchmark/sandbox", "test_data_ok")
        self.assertLessEqual(r.data_exposure, 0.4)

    def test_strict_keeps_high_exposure(self):
        from strix_guard.decision import apply_data_policy
        r = RiskVector(data_exposure=0.9)
        apply_data_policy(r, "benchmark/sandbox", "strict")
        self.assertEqual(r.data_exposure, 0.9)

    def test_production_keeps_high_exposure(self):
        from strix_guard.decision import apply_data_policy
        r = RiskVector(data_exposure=0.9)
        apply_data_policy(r, "production", "test_data_ok")
        self.assertEqual(r.data_exposure, 0.9)


class TestPolicy(unittest.TestCase):
    def test_benign_allow(self):
        d = decide(RiskVector(destructiveness=0.0, load=0.05))
        self.assertEqual(d.verdict, Verdict.ALLOW)
        self.assertEqual(ui_label(d), "allow")

    def test_high_load_revise_with_constraints(self):
        d = decide(RiskVector(load=0.6))
        self.assertEqual(d.verdict, Verdict.REVISE)
        self.assertIn("max_requests", d.constraints)
        self.assertIn("high_load", d.reasons)

    def test_destructive_block(self):
        d = decide(RiskVector(destructiveness=0.9))
        self.assertEqual(d.verdict, Verdict.BLOCK)

    def test_third_party_block(self):
        d = decide(RiskVector(third_party=0.9))
        self.assertEqual(d.verdict, Verdict.BLOCK)

    def test_insufficient_info_needs_info(self):
        d = decide(RiskVector(sufficiency="insufficient_content"))
        self.assertEqual(d.verdict, Verdict.NEED_INFO)
        self.assertEqual(ui_label(d), "unknown")

    def test_cross_user_revise(self):
        d = decide(RiskVector(data_exposure=0.7))
        self.assertEqual(d.verdict, Verdict.REVISE)
        self.assertEqual(d.constraints.get("scope"), "own_test_account")


if __name__ == "__main__":
    unittest.main()
