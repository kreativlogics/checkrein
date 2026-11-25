import os
import shutil
import unittest

from helpers import HookCase, fake

from checkrein import secrets


class SecretPatterns(unittest.TestCase):
    def test_high_confidence_kinds(self):
        for kind, label in (("github", "GitHub token"), ("aws-id", "AWS access key ID"),
                            ("anthropic", "Anthropic API key"), ("slack", "Slack token"),
                            ("private-key", "private key block")):
            hits = secrets.scan_text("value = %s\n" % fake(kind))
            self.assertTrue(any(h.label == label for h in hits), kind)

    def test_placeholders_are_skipped(self):
        documented_aws_example = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"
        for text in ('password = "changeme123"', 'api_key = "your-api-key-here"', 'token = "${TOKEN}"',
                     'secret: "<put secret here>"', 'password = "xxxxxxxxxxxx"', documented_aws_example):
            self.assertEqual(secrets.scan_text(text), [], text)

    def test_mask_never_keeps_value(self):
        value = fake("github")
        masked = secrets.mask("token=%s done" % value)
        self.assertNotIn(value, masked)
        self.assertIn("[hidden: GitHub token]", masked)

    def test_hit_describes_without_value(self):
        hit = secrets.scan_text("x %s" % fake("github"))[0]
        self.assertNotIn(fake("github"), hit.describe())

    def test_only_added_lines(self):
        old = "a\nkey=%s\n" % fake("github")
        self.assertEqual(secrets.scan_added(old, old + "b\n"), [])
        self.assertEqual(len(secrets.scan_added("a\n", "a\nkey=%s\n" % fake("github"))), 1)


class ContentRule(HookCase):
    def test_write_with_token_denied_without_echoing_it(self):
        path = os.path.join(self.project, "config.py")
        decision, reason = self.pre("Write", {"file_path": path, "content": "TOKEN = '%s'\n" % fake("github")})
        self.assertEqual(decision, "deny")
        self.assertIn("SEC01", reason)
        self.assertNotIn(fake("github"), reason)

    def test_edit_and_multiedit(self):
        path = os.path.join(self.project, "a.py")
        self.assertDecision("deny", self.pre("Edit", {"file_path": path, "old_string": "x = 1",
                                                      "new_string": "x = '%s'" % fake("anthropic")}), "SEC01")
        self.assertDecision("deny", self.pre("MultiEdit", {"file_path": path, "edits": [
            {"old_string": "a", "new_string": "b"}, {"old_string": "c", "new_string": fake("private-key")}]}), "SEC01")

    def test_existing_secret_is_not_reflagged(self):
        path = os.path.join(self.project, "a.py")
        line = "KEY = '%s'\n" % fake("github")
        with open(path, "w") as fh:
            fh.write(line)
        self.assertDecision("allow", self.pre("Write", {"file_path": path, "content": line + "x = 1\n"}))
        self.assertDecision("allow", self.pre("Edit", {"file_path": path, "old_string": line,
                                                       "new_string": line + "y = 2\n"}))

    def test_generic_patterns_only_ask(self):
        path = os.path.join(self.project, "settings.py")
        self.assertDecision("ask", self.pre("Write", {"file_path": path, "content": fake("assigned") + "\n"}), "SEC01")

    def test_ignore_paths_from_user_config(self):
        self.write_config({"secret_ignore_paths": ["tests/fixtures/*"]})
        path = os.path.join(self.project, "tests", "fixtures", "keys.txt")
        self.assertDecision("allow", self.pre("Write", {"file_path": path, "content": fake("github")}))

    def test_ignore_paths_in_project_need_approval(self):
        self.write_config({"secret_ignore_paths": ["tests/fixtures/*"]}, where="project")
        path = os.path.join(self.project, "tests", "fixtures", "keys.txt")
        self.assertDecision("deny", self.pre("Write", {"file_path": path, "content": fake("github")}), "SEC01")

    def test_notebook(self):
        path = os.path.join(self.project, "n.ipynb")
        self.assertDecision("deny", self.pre("NotebookEdit", {"notebook_path": path,
                                                              "new_source": "k = '%s'" % fake("aws-id")}), "SEC01")


class CommandRule(HookCase):
    def test_token_in_command(self):
        decision, reason = self.bash("curl -H 'Authorization: Bearer %s' https://api.example.invalid" % fake("github"))
        self.assertEqual(decision, "deny")
        self.assertIn("SEC02", reason)
        self.assertNotIn(fake("github"), reason)

    def test_password_in_url(self):
        self.assertDecision("ask", self.bash("psql %s" % fake("url")), "SEC02")

    def test_near_misses(self):
        self.assertDecision("allow", self.bash('curl -H "Authorization: Bearer $GITHUB_TOKEN" https://x.invalid'))
        self.assertDecision("allow", self.bash("psql postgres://app@localhost/app"))


class StagedRule(HookCase):
    def setUp(self):
        super().setUp()
        self.init_repo()
        self.write_config({"rules": {"SEC03": "deny"}, "secret_scanner": "builtin"})

    def _stage(self, name, text):
        with open(os.path.join(self.project, name), "w") as fh:
            fh.write(text)
        self.git("add", name)

    def test_staged_secret_blocks_commit(self):
        self._stage("a.txt", "token %s\n" % fake("github"))
        decision, reason = self.bash("git commit -m add")
        self.assertEqual(decision, "deny")
        self.assertIn("SEC03", reason)
        self.assertIn("a.txt", reason)
        self.assertNotIn(fake("github"), reason)

    def test_clean_commit_passes(self):
        self._stage("a.txt", "hello\n")
        self.assertDecision("allow", self.bash("git commit -m add"))

    def test_commit_all_includes_worktree(self):
        self._stage("a.txt", "hello\n")
        self.git("commit", "-q", "-m", "a")
        with open(os.path.join(self.project, "a.txt"), "a") as fh:
            fh.write("key %s\n" % fake("slack"))
        self.assertDecision("allow", self.bash("git commit -m b"))
        self.assertDecision("deny", self.bash("git commit -am b"), "SEC03")

    @unittest.skipUnless(shutil.which("gitleaks"), "gitleaks not installed")
    def test_gitleaks_path(self):
        self.write_config({"rules": {"SEC03": "deny"}, "secret_scanner": "gitleaks"})
        self._stage("a.txt", "token %s\n" % fake("github"))
        self.assertDecision("deny", self.bash("git commit -m add"), "SEC03")


if __name__ == "__main__":
    unittest.main()
