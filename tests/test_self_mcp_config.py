import json
import os
import time
import unittest

from helpers import PLUGIN, ROOT, SCRIPTS, HookCase, fake
from checkrein import globs

CFGTOOL = os.path.join(SCRIPTS, "cfgtool.py")
SKILLGATE = os.path.join(SCRIPTS, "skillgate.py")


class SelfProtection(HookCase):
    def test_data_dir_edits_denied(self):
        ledger = os.path.join(self.data, "ledger.json")
        self.assertDecision("deny", self.pre("Write", {"file_path": ledger, "content": "{}"}), "SLF01")
        self.assertDecision("deny", self.bash("rm %s" % ledger), "SLF01")
        self.assertDecision("deny", self.bash("echo '{}' > $CLAUDE_PLUGIN_DATA/config.json"), "SLF01")
        self.assertDecision("deny", self.bash("python3 -c \"open('%s','w')\"" % ledger), "SLF01")
        self.assertDecision("deny", self.bash("sed -i '' s/deny/off/ %s/config.json" % self.data), "SLF01")

    def test_project_config_edits_denied(self):
        path = os.path.join(self.project, ".checkrein", "config.json")
        self.assertDecision("deny", self.pre("Write", {"file_path": path, "content": "{}"}), "SLF01")

    def test_plugin_files_denied(self):
        target = os.path.join(PLUGIN, "scripts", "checkrein", "rules.json")
        self.assertDecision("deny", self.pre("Edit", {"file_path": target, "old_string": "deny",
                                                      "new_string": "off"}), "SLF01")

    def test_reading_is_fine(self):
        self.assertDecision("allow", self.bash("cat %s/ledger.json" % self.data))
        self.assertDecision("allow", self.bash("jq . %s/config.json" % self.data))
        self.assertDecision("allow", self.bash("ls -la %s" % self.data))
        self.assertDecision("allow", self.bash("grep -r GIT01 %s" % os.path.join(PLUGIN, "scripts")))

    def test_own_config_commands_ask(self):
        base = "python3 %s --data %s " % (CFGTOOL, self.data)
        self.assertDecision("ask", self.bash(base + "set rules.GIT06 ask"), "SLF01")
        self.assertDecision("ask", self.bash(base + "approve scanner"), "SLF01")
        self.assertDecision("ask", self.bash(base + "init --yes"), "SLF01")
        self.assertDecision("allow", self.bash(base + "show"))
        self.assertDecision("allow", self.bash(base + "doctor"))
        self.assertDecision("allow", self.bash(base + "explain GIT01"))

    def test_settings_changes_about_checkrein(self):
        settings = os.path.join(self.home, ".claude", "settings.json")
        os.makedirs(os.path.dirname(settings))
        with open(settings, "w") as fh:
            json.dump({"enabledPlugins": {"checkrein@kreativlogics": True}}, fh)
        self.assertDecision("deny", self.pre("Write", {"file_path": settings, "content": "{}"}), "SLF01")
        self.assertDecision("deny", self.pre("Edit", {"file_path": settings, "old_string": "{",
                                                      "new_string": "{\"disableAllHooks\": true,"}), "SLF01")
        self.assertDecision("allow", self.pre("Edit", {"file_path": settings, "old_string": "{",
                                                       "new_string": "{\"theme\": \"dark\","}))
        self.assertDecision("deny", self.bash("claude plugin disable checkrein@kreativlogics"), "SLF01")


class Mcp(HookCase):
    def test_secret_in_outbound_call(self):
        decision, reason = self.pre("mcp__tracker__create_issue",
                                    {"title": "bug", "body": "use %s" % fake("github")})
        self.assertEqual(decision, "deny")
        self.assertIn("MCP02", reason)
        self.assertNotIn(fake("github"), reason)

    def test_write_gate_off_by_default(self):
        self.assertDecision("allow", self.pre("mcp__tracker__create_issue", {"title": "bug"}))

    def test_strict_asks_with_payload(self):
        self.write_config({"preset": "strict"})
        decision, reason = self.pre("mcp__tracker__create_issue", {"title": "Login button broken"})
        self.assertEqual(decision, "ask")
        self.assertIn("MCP01", reason)
        self.assertIn("Login button broken", reason)
        self.assertDecision("allow", self.pre("mcp__tracker__list_issues", {"q": "x"}))
        self.assertDecision("allow", self.pre("mcp__tracker__getIssue", {"id": 1}))

    def test_routine_tools_pass_user_config_only(self):
        self.write_config({"preset": "strict", "mcp_routine": ["*__set_session_title"]})
        self.assertDecision("allow", self.pre("mcp__session__set_session_title", {"t": "x"}))
        self.write_config({"preset": "strict"})
        self.write_config({"mcp_routine": ["*"]}, where="project")
        self.assertDecision("ask", self.pre("mcp__tracker__create_issue", {"title": "x"}), "MCP01")


class ConfigLayers(HookCase):
    def test_project_cannot_loosen(self):
        self.write_config({"rules": {"GIT01": "off", "SEC01": "off"}, "preset": "relaxed", "fail_mode": "allow"},
                          where="project")
        self.assertDecision("deny", self.bash("git push --force origin feature/x"), "GIT01")
        out = self.hook("session", {"cwd": self.project})
        self.assertIn("Ignored", out["systemMessage"])

    def test_project_can_tighten(self):
        self.write_config({"rules": {"GIT06": "deny"}}, where="project")
        self.assertDecision("deny", self.bash("git stash"), "GIT06")

    def test_user_can_loosen(self):
        self.write_config({"rules": {"GIT02": "off"}})
        self.assertDecision("allow", self.bash("git reset --hard"))

    def test_plugin_option_preset(self):
        decision, _ = self.pre("Bash", {"command": "git push -f origin feature/x"},
                               extra_env={"CLAUDE_PLUGIN_OPTION_PRESET": "relaxed"})
        self.assertEqual(decision, "ask")

    def test_unknown_key_reports_hint(self):
        self.write_config({"protected_branch": ["x"]})
        decision, reason = self.bash("ls")
        self.assertEqual(decision, "ask")
        self.assertIn("Did you mean 'protected_branches'", reason)

    def test_secret_in_config_rejected(self):
        self.write_config({"protected_branches": [fake("github")]})
        decision, reason = self.bash("ls")
        self.assertEqual(decision, "ask")
        self.assertIn("looks like a real secret", reason)
        self.assertNotIn(fake("github"), reason)

    def test_newer_version_says_update(self):
        self.write_config({"version": 99})
        _decision, reason = self.bash("ls")
        self.assertIn("Update the plugin", reason)


class Failures(HookCase):
    def test_broken_config_uses_fail_mode(self):
        path = os.path.join(self.data, "config.json")
        with open(path, "w") as fh:
            fh.write("{broken")
        self.assertDecision("ask", self.bash("ls"))
        self.assertDecision("deny", self.bash("ls", mode="dontAsk"))
        self.assertDecision("allow", self.bash("ls", extra_env={"CLAUDE_PLUGIN_OPTION_FAIL_MODE": "allow"}))
        self.assertDecision("deny", self.bash("ls", extra_env={"CLAUDE_PLUGIN_OPTION_FAIL_MODE": "deny"}))

    def test_project_can_make_fail_mode_stricter(self):
        with open(os.path.join(self.data, "config.json"), "w") as fh:
            fh.write("{broken")
        self.write_config({"fail_mode": "deny"}, where="project")
        self.assertDecision("deny", self.bash("ls", extra_env={"CLAUDE_PLUGIN_OPTION_FAIL_MODE": "allow"}))

    def test_bad_input(self):
        out = self.hook("pre", None, raw="not json")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")
        out = self.hook("pre", {"tool_input": {}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_unknown_tool_passes(self):
        self.assertDecision("allow", self.pre("Read", {"file_path": "/etc/hosts"}))

    def test_session_with_nothing_to_say_is_silent(self):
        self.assertIsNone(self.hook("session", {"cwd": self.project}))

    def test_timing(self):
        start = time.time()
        for _ in range(5):
            self.bash("git status && ls -la | head")
        per_call = (time.time() - start) / 5
        self.assertLess(per_call, 0.5, "hook too slow: %.0f ms" % (per_call * 1000))


class Registry(unittest.TestCase):
    def test_every_rule_has_tests_and_docs(self):
        with open(os.path.join(SCRIPTS, "checkrein", "rules.json")) as fh:
            rules = json.load(fh)["rules"]
        tests = ""
        here = os.path.dirname(os.path.abspath(__file__))
        for name in os.listdir(here):
            if name.startswith("test_") and name.endswith(".py"):
                with open(os.path.join(here, name)) as fh:
                    tests += fh.read()
        with open(os.path.join(ROOT, "docs", "rules.md")) as fh:
            docs = fh.read()
        for rid, spec in rules.items():
            self.assertIn('"%s"' % rid, tests, "%s has no test" % rid)
            self.assertRegex(docs, r"(?m)^## %s\b" % rid, "%s has no docs entry" % rid)
            self.assertEqual(set(spec["presets"]), {"relaxed", "standard", "strict"})
            for level in spec["presets"].values():
                self.assertIn(level, spec["levels"])

    def test_presets_only_tighten_upwards(self):
        with open(os.path.join(SCRIPTS, "checkrein", "rules.json")) as fh:
            rules = json.load(fh)["rules"]
        for rid, spec in rules.items():
            order = spec["levels"]
            r, s, t = (order.index(spec["presets"][p]) for p in ("relaxed", "standard", "strict"))
            self.assertTrue(r <= s <= t, rid)

    def test_mcp_write_pattern(self):
        with open(os.path.join(SCRIPTS, "checkrein", "rules.json")) as fh:
            pat = json.load(fh)["defaults"]["mcp_write_tools"][0]
        for name in ("mcp__gl__accept_merge_request", "mcp__j__addOrEditComment", "mcp__a__executeWrite",
                     "mcp__s__set_session_title", "mcp__g__create_issue"):
            self.assertTrue(globs.match(pat, name), name)
        for name in ("mcp__gl__list_merge_requests", "mcp__j__getJiraIssue", "mcp__a__executeRead",
                     "mcp__x__search"):
            self.assertFalse(globs.match(pat, name), name)


if __name__ == "__main__":
    unittest.main()
