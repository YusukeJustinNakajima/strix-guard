import unittest

from strix_guard.policy_config import resolve_policy
from strix_guard.policy_guard import check_exec_policy, detect_methods, infra_only


class TestPolicyGuard(unittest.TestCase):
    def setUp(self):
        self.ref = resolve_policy("reference_only")
        self.full = resolve_policy("full")

    def _kinds(self, cmd, script=None, policy=None):
        return [v.kind for v in check_exec_policy(cmd, script, policy or self.ref)]

    def test_get_is_allowed(self):
        self.assertEqual(self._kinds("curl -s http://host.docker.internal:5000/x"), [])

    def test_put_is_blocked(self):
        self.assertIn("policy_http_method", self._kinds(
            "curl -X PUT http://host.docker.internal:5000/x"))

    def test_curl_data_is_blocked(self):
        self.assertIn("policy_http_method", self._kinds(
            "curl -d 'a=b' http://host.docker.internal:5000/login"))

    def test_script_post_is_blocked(self):
        self.assertIn("policy_http_method", self._kinds(
            "python3 exploit.py", "import requests\nrequests.post(u, json={})"))

    def test_upload_is_blocked(self):
        self.assertIn("policy_upload", self._kinds(
            "curl -F file=@a.png http://host.docker.internal:5000/upload"))

    def test_sql_write_is_blocked(self):
        self.assertIn("policy_data_write", self._kinds(
            "python3 q.py", "cur.execute('UPDATE users SET admin=true')"))

    def test_external_egress_is_blocked(self):
        self.assertIn("policy_egress", self._kinds(
            "curl http://evil.example/x"))

    def test_allowed_hosts_override(self):
        p = resolve_policy("reference_only")
        p["egress"]["allowed_hosts"] = ["api.example.com"]
        self.assertEqual(self._kinds("curl http://api.example.com/x", policy=p), [])
        self.assertIn("policy_egress", self._kinds("curl http://other.example.com/x", policy=p))

    def test_full_preset_has_no_exec_restrictions(self):
        self.assertEqual(self._kinds(
            "curl -X PUT http://host.docker.internal:5000/x", policy=self.full), [])

    def test_denied_paths_block_in_full_preset(self):
        p = resolve_policy("full")
        p["http"]["denied_paths"] = ["/admin/delete_account", "/admin/delete_account/*"]
        self.assertIn("policy_denied_path", self._kinds(
            "curl -X POST http://host.docker.internal:5000/admin/delete_account/31", policy=p))
        self.assertIn("policy_denied_path", self._kinds(
            "curl 'http://host.docker.internal:5000/admin/delete_account?x=1'", policy=p))
        self.assertEqual(self._kinds(
            "curl -X POST http://host.docker.internal:5000/admin/delete_accounts", policy=p), [])

    def test_denied_paths_match_script_literals(self):
        p = resolve_policy("full")
        p["http"]["denied_paths"] = ["/admin/delete_account/*"]
        self.assertIn("policy_denied_path", self._kinds(
            "python3 exploit.py",
            "import requests\nrequests.post('/admin/delete_account/31')", policy=p))

    def test_denied_paths_match_percent_encoded_path(self):
        p = resolve_policy("full")
        p["http"]["denied_paths"] = ["/admin/*"]
        self.assertIn("policy_denied_path", self._kinds(
            "curl http://host.docker.internal:5000/%61dmin/delete_account/31", policy=p))
        self.assertIn("policy_denied_path", self._kinds(
            "curl http://host.docker.internal:5000/%2Fadmin%2Fdelete_account", policy=p))

    def test_denied_paths_do_not_apply_to_infra_hosts(self):
        p = resolve_policy("full")
        p["http"]["denied_paths"] = ["/graphql"]
        self.assertEqual(self._kinds(
            "curl -X POST http://127.0.0.1:48080/graphql", policy=p), [])

    def test_recon_blocks_exploit_tools(self):
        p = resolve_policy("recon")
        self.assertIn("policy_tool", self._kinds("sqlmap -u http://host.docker.internal:5000", policy=p))

    def test_sandbox_internal_skips_policy(self):
        self.assertEqual(self._kinds("echo 'PUT /x'"), [])

    def test_infra_proxy_is_allowed(self):
        self.assertEqual(self._kinds(
            "sh -lc curl -X POST http://127.0.0.1:48080/graphql -d '{}'"), [])

    def test_target_post_still_blocked(self):
        self.assertIn("policy_http_method", self._kinds(
            "curl -X POST http://host.docker.internal:5000/login -d x=y"))

    def test_infra_only_detection(self):
        self.assertTrue(infra_only("curl -X POST http://127.0.0.1:48080/graphql", None, self.ref))
        self.assertFalse(infra_only("curl -X POST http://host.docker.internal:5000/login", None, self.ref))
        self.assertFalse(infra_only(
            "curl http://127.0.0.1:48080/graphql; curl http://host.docker.internal:5000/", None, self.ref))

    def test_detect_methods(self):
        for cmd, method in [
            ("curl -X PATCH http://h/x", "PATCH"),
            ("wget --post-data=x http://h/x", "POST"),
            ("python3 -c \"import requests; requests.delete(u)\"", "DELETE"),
            ("node app.js", None),
        ]:
            methods = detect_methods(cmd)
            if method:
                self.assertIn(method, methods)
            else:
                self.assertEqual(methods, set())


if __name__ == "__main__":
    unittest.main()
