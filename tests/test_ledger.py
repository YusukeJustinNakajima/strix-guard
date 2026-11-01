import json
import os
import sqlite3
import tempfile
import unittest

from strix_guard.ledger import build_ledger_from_db, resolve_script


LEDGER = {
    "uploadval/val.py": "print('hello')",
    "app.js": "console.log('hi')",
    "/workspace/tools/probe.sh": "echo probe",
}


class TestResolveScript(unittest.TestCase):
    def test_direct_path(self):
        self.assertEqual(resolve_script(LEDGER, "python3 /workspace/tools/probe.sh"), "echo probe")

    def test_basename_match(self):
        self.assertEqual(resolve_script(LEDGER, "python3 -u val.py"), "print('hello')")

    def test_interpreter_flags(self):
        self.assertEqual(resolve_script(LEDGER, "cd /workspace/uploadval && python3 -u val.py 2>&1"), "print('hello')")
        self.assertEqual(resolve_script(LEDGER, "node --inspect app.js"), "console.log('hi')")

    def test_wrapped_sandbox_command(self):
        cmd = ('sh -lc mkdir -p "$1" && shift 2 && exec "$@" sh /tmp/sandbox-docker-archive '
               '/tmp/x_pty.pid bash -lc cd /workspace/uploadval && python3 -u val.py')
        self.assertEqual(resolve_script(LEDGER, cmd), "print('hello')")

    def test_no_script(self):
        self.assertIsNone(resolve_script(LEDGER, "curl http://localhost/"))


class TestBuildLedger(unittest.TestCase):
    def _ledger_from_cmds(self, cmds):
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, "agents.db")
            con = sqlite3.connect(db)
            con.execute("CREATE TABLE agent_messages (id INTEGER PRIMARY KEY, message_data TEXT)")
            for cmd in cmds:
                con.execute("INSERT INTO agent_messages (message_data) VALUES (?)",
                            (json.dumps({"type": "function_call", "name": "exec_command",
                                         "arguments": json.dumps({"cmd": cmd})}),))
            con.commit()
            con.close()
            return build_ledger_from_db(db)

    def test_cp_copies_tracked_content(self):
        ledger = self._ledger_from_cmds([
            "cat > poc.py <<'EOF'\nprint(1)\nEOF",
            "cp poc.py zz.py",
        ])
        self.assertEqual(ledger["zz.py"], "print(1)")
        self.assertEqual(resolve_script(ledger, "cd /workspace/bfla && python3 zz.py"), "print(1)")

    def test_cp_between_absolute_paths(self):
        ledger = self._ledger_from_cmds([
            "cat > bfla/poc.py <<'EOF'\nprint(2)\nEOF",
            "cp /workspace/bfla/poc.py /workspace/bfla/zz.py",
        ])
        self.assertEqual(resolve_script(ledger, "python3 /workspace/bfla/zz.py"), "print(2)")

    def test_mv_moves_content(self):
        ledger = self._ledger_from_cmds([
            "cat > poc.py <<'EOF'\nprint(3)\nEOF",
            "mv poc.py zz.py",
        ])
        self.assertNotIn("poc.py", ledger)
        self.assertEqual(ledger["zz.py"], "print(3)")

    def test_scp_is_not_tracked(self):
        ledger = self._ledger_from_cmds([
            "cat > poc.py <<'EOF'\nprint(4)\nEOF",
            "scp poc.py host:/tmp/x",
        ])
        self.assertEqual(list(ledger), ["poc.py"])

    def test_apply_patch_add_strips_plus(self):
        patch = ("*** Begin Patch\n"
                 "*** Add File: /workspace/uploadval/val.py\n"
                 "+import random\n"
                 "+\n"
                 "+print('ok')\n"
                 "*** End Patch\n")
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, "agents.db")
            con = sqlite3.connect(db)
            con.execute("CREATE TABLE agent_messages (id INTEGER PRIMARY KEY, message_data TEXT)")
            con.execute("INSERT INTO agent_messages (message_data) VALUES (?)",
                        (json.dumps({"type": "function_call", "name": "apply_patch",
                                     "arguments": json.dumps({"patch": patch})}),))
            con.commit()
            con.close()
            ledger = build_ledger_from_db(db)
        self.assertEqual(ledger["/workspace/uploadval/val.py"], "import random\n\nprint('ok')")

    def test_heredoc(self):
        cmd = "cat > uploadval/val.py <<'EOF'\nprint('hi')\nEOF"
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, "agents.db")
            con = sqlite3.connect(db)
            con.execute("CREATE TABLE agent_messages (id INTEGER PRIMARY KEY, message_data TEXT)")
            con.execute("INSERT INTO agent_messages (message_data) VALUES (?)",
                        (json.dumps({"type": "function_call", "name": "exec_command",
                                     "arguments": json.dumps({"cmd": cmd})}),))
            con.commit()
            con.close()
            ledger = build_ledger_from_db(db)
        self.assertEqual(ledger["uploadval/val.py"], "print('hi')")


if __name__ == "__main__":
    unittest.main()
