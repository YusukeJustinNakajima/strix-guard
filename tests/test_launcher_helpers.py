import os
import tempfile
import unittest

from strix_guard.launcher import (_family, _inner_command, _load_denied_paths,
                                  _merge_denied_paths, _parallel_of)


class TestFamily(unittest.TestCase):
    def test_wrapper_matches_direct(self):
        direct = "bash -lc ffuf -u http://host.docker.internal:5000/FUZZ -w x -t 50"
        wrapped = ('sh -lc mkdir -p "$1" && printf "%s" "$$" > "$2" && shift 2 && exec "$@" '
                   'sh /tmp/sandbox-docker-archive /tmp/sandbox-docker-archive/p.pid ' + direct)
        self.assertEqual(_family(direct), _family(wrapped))

    def test_different_targets_differ(self):
        a = _family("ffuf -u http://host.docker.internal:5000/FUZZ -w x")
        b = _family("ffuf -u http://host.docker.internal:5003/FUZZ -w x")
        self.assertNotEqual(a, b)

    def test_different_tools_differ(self):
        a = _family("ffuf -u http://host.docker.internal:5000/FUZZ -w x")
        b = _family("curl -s http://host.docker.internal:5000/")
        self.assertNotEqual(a, b)

    def test_script_family(self):
        self.assertIn("brute.py", _family("python3 /workspace/brute.py"))

    def test_parallel_of(self):
        self.assertEqual(_parallel_of("ffuf -u http://x/FUZZ -t 50"), 50)
        self.assertEqual(_parallel_of("ffuf --threads=20 -u http://x/FUZZ"), 20)
        self.assertIsNone(_parallel_of("curl http://x"))

    def test_inner_command_strips_wrapper(self):
        direct = "bash -lc ffuf -u http://x/FUZZ -t 50"
        wrapped = ('sh -lc mkdir -p "$1" && printf x > "$2" && shift 2 && exec "$@" '
                   'sh /tmp/sandbox-docker-archive /tmp/a.pid ' + direct)
        self.assertEqual(_inner_command(wrapped), "ffuf -u http://x/FUZZ -t 50")

    def test_load_denied_paths_from_args(self):
        self.assertEqual(
            _load_denied_paths([" /admin/* ", "/admin/*", "/internal"], None),
            ["/admin/*", "/internal"])

    def test_load_denied_paths_from_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "deny.txt")
            with open(path, "w", encoding="utf-8-sig") as f:
                f.write("# comment\n\n/admin/*\n  /internal  \n")
            self.assertEqual(
                _load_denied_paths(["/admin/*"], path),
                ["/admin/*", "/internal"])

    def test_load_denied_paths_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            _load_denied_paths([], "/nonexistent/deny.txt")

    def test_merge_denied_paths(self):
        policy = {"http": {"denied_paths": ["/admin/*"]}}
        self.assertEqual(
            _merge_denied_paths(policy, ["/admin/*", "/internal"]),
            ["/admin/*", "/internal"])


if __name__ == "__main__":
    unittest.main()
