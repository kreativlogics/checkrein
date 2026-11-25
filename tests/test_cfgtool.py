import json
import os
import subprocess
import sys
import unittest

from helpers import SCRIPTS, HookCase, fake

CFGTOOL = os.path.join(SCRIPTS, "cfgtool.py")


class CfgTool(HookCase):
    def cfg(self, *args, expect=0):
        res = subprocess.run([sys.executable, CFGTOOL, "--data", self.data] + list(args), env=self.env,
                             cwd=self.project, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=60)
        self.assertEqual(res.returncode, expect, res.stdout + res.stderr)
        return res.stdout + res.stderr

    def user_config(self):
        with open(os.path.join(self.data, "config.json")) as fh:
            return json.load(fh)

    def test_show_and_explain(self):
        out = self.cfg("show")
        self.assertIn("Preset: standard (default)", out)
        self.assertRegex(out, r"GIT01\s+deny")
        out = self.cfg("explain", "GIT01")
        self.assertIn("docs/rules.md#git01", out)
        self.assertIn("relaxed=ask", out)
        self.assertIn("Lists from every layer add up", self.cfg("explain", "protected_branches"))
        self.cfg("explain", "NOPE", expect=1)

    def test_set_and_unset_take_effect(self):
        self.cfg("set", "rules.GIT06", "ask")
        self.assertEqual(self.user_config()["rules"]["GIT06"], "ask")
        self.assertDecision("ask", self.bash("git stash"), "GIT06")
        self.cfg("unset", "rules.GIT06")
        self.assertDecision("allow", self.bash("git stash"))

    def test_list_add_and_remove(self):
        self.cfg("set", "protected_branches", "--add", "qa")
        self.assertIn("qa", self.user_config()["protected_branches"])
        self.assertDecision("deny", self.bash("git push --force origin qa"), "GIT01")
        self.cfg("set", "protected_branches", "--remove", "qa")
        self.assertNotIn("qa", self.user_config().get("protected_branches", []))

    def test_set_rejects_bad_values(self):
        self.cfg("set", "rules.GIT01", "maybe", expect=1)
        self.cfg("set", "rules.NOPE1", "deny", expect=1)
        out = self.cfg("set", "protected_branches", "--add", fake("github"), expect=1)
        self.assertNotIn(fake("github"), out)
        self.assertFalse(os.path.exists(os.path.join(self.data, "config.json")))

    def test_project_set(self):
        self.cfg("--project-dir", self.project, "set", "rules.GIT06", "deny", "--project")
        with open(os.path.join(self.project, ".checkrein", "config.json")) as fh:
            self.assertEqual(json.load(fh)["rules"]["GIT06"], "deny")
        self.assertDecision("deny", self.bash("git stash"), "GIT06")

    def test_init_previews_then_writes(self):
        out = self.cfg("init", "--preset", "strict")
        self.assertFalse(os.path.exists(os.path.join(self.data, "config.json")), out)
        self.cfg("init", "--preset", "strict", "--yes")
        self.assertEqual(self.user_config()["preset"], "strict")
        self.cfg("init", "--yes", expect=1)
        self.cfg("init", "--preset", "relaxed", "--yes", "--force")
        self.assertEqual(self.user_config()["preset"], "relaxed")

    def test_detect_and_doctor(self):
        out = self.cfg("detect")
        self.assertIn("Found:", out)
        self.assertIn("ledger: missing", out)
        out = self.cfg("doctor")
        self.assertIn("0 problem(s).", out)
        self.assertIn("hook runs", out)

    def test_doctor_reports_broken_config(self):
        with open(os.path.join(self.data, "config.json"), "w") as fh:
            fh.write("{broken")
        out = self.cfg("doctor", expect=1)
        self.assertNotIn("0 problem(s).", out)


class KnownMisses(HookCase):
    """Things a pattern-based hook cannot see. Listed in docs/limits.md; if one starts passing, update both."""

    @unittest.expectedFailure
    def test_alias_hides_force_push(self):
        self.assertDecision("deny", self.bash("git pf origin master"), "GIT01")

    @unittest.expectedFailure
    def test_encoded_command(self):
        self.assertDecision("deny", self.bash("echo Z2l0IHB1c2ggLWYgb3JpZ2luIG1hc3Rlcg== | base64 -d | sh"), "GIT01")

    @unittest.expectedFailure
    def test_script_written_then_run(self):
        script = os.path.join(self.project, "go.sh")
        with open(script, "w") as fh:
            fh.write("git push --force origin master\n")
        self.assertDecision("deny", self.bash("sh go.sh"), "GIT01")

    @unittest.expectedFailure
    def test_secret_split_across_writes(self):
        value = fake("github")
        path = os.path.join(self.project, "a.py")
        with open(path, "w") as fh:
            fh.write("A = '%s'\n" % value[:10])
        self.assertDecision("deny", self.pre("Write", {"file_path": path, "content": "A = '%s'\nB = A + '%s'\n"
                                                       % (value[:10], value[10:])}), "SEC01")


if __name__ == "__main__":
    unittest.main()
