import unittest

from strix_guard.diff import command_diff


class TestDiff(unittest.TestCase):
    def test_replace_token(self):
        old = "ffuf -u http://host.docker.internal:5000/FUZZ -w a -t 50"
        new = "ffuf -u http://host.docker.internal:5000/FUZZ -w a -t 10"
        self.assertEqual(command_diff(old, new), "50 → 10")

    def test_identical(self):
        self.assertEqual(command_diff("a b c", "a b c"), "変更なし")

    def test_added_and_removed(self):
        d = command_diff("ffuf -u http://x/FUZZ -t 50",
                         "ffuf -u http://x/FUZZ -w small.txt -t 10")
        self.assertIn("追加", d)


if __name__ == "__main__":
    unittest.main()
