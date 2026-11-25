"""Review fixes: config layering, fail_mode, plugin approvals, SEC03 diff parsing, regex limits, file safety."""

import json
import os
import subprocess
import sys
import time
import unittest
from unittest import mock

from helpers import SCRIPTS, HookCase, fake

SKILLGATE = os.path.join(SCRIPTS, "skillgate.py")
INSTALL = "claude plugin " + "install"


class ToolCase(HookCase):
    def tool(self, script, *args, expect=0):
        res = subprocess.run([sys.executable, script, "--data", self.data] + list(args), env=self.env,
                             cwd=self.project, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=60)
        if expect is not None:
            self.assertEqual(res.returncode, expect, res.stdout + res.stderr)
        return res.stdout + res.stderr

    def session(self):
        return self.hook("session", {"source": "startup", "cwd": self.project})


class SkillgateArgs(ToolCase):
    def test_abbreviated_options_are_refused(self):
        res = subprocess.run([sys.executable, SKILLGATE, "--data", self.data, "--proj", "x", "list"], env=self.env,
                             cwd=self.project, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=60)
        self.assertNotEqual(res.returncode, 0)
        res = subprocess.run([sys.executable, SKILLGATE, "--da", self.data, "list"], env=self.env,
                             cwd=self.project, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=60)
        self.assertNotEqual(res.returncode, 0)
        self.tool(SKILLGATE, "--project", self.project, "list")


class InvalidProjectConfig(ToolCase):
    def test_invalid_project_layer_cannot_loosen(self):
        self.write_config({"rules": {"GIT01": "maybe"}}, where="project")
        decision, reason = self.bash("git push --force origin master")
        self.assertEqual(decision, "deny", reason)
        self.assertIn("checkrein GIT01", reason)
        self.assertIn("project config", reason)
        self.assertNotIn("maybe", reason)
        decision, reason = self.bash("git push --force origin master",
                                     extra_env={"CLAUDE_PLUGIN_OPTION_FAIL_MODE": "allow"})
        self.assertEqual(decision, "deny", reason)

    def test_invalid_project_json_is_ignored(self):
        path = os.path.join(self.project, ".checkrein", "config.json")
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as fh:
            fh.write("{not json")
        self.assertDecision("allow", self.bash("git status"))
        self.assertDecision("deny", self.bash("git push --force origin master"), "GIT01")

    def test_user_layer_still_applies(self):
        self.write_config({"rules": {"GIT06": "deny"}})
        self.write_config({"rules": {"GIT01": "maybe"}}, where="project")
        from checkrein import cfg
        eff = cfg.resolve(self.data, self.project)
        self.assertEqual(eff.level("GIT06"), "deny")
        self.assertTrue(eff.project_error)

    def test_session_note_reports_it(self):
        self.write_config({"rules": {"GIT01": "maybe"}}, where="project")
        out = self.session()
        self.assertIn("project config", out["systemMessage"])
        self.assertIn("ignored", out["systemMessage"])
        self.assertNotIn("maybe", out["systemMessage"])

    def test_project_secret_value_is_not_echoed(self):
        self.write_config({"protected_branches": [fake("github")]}, where="project")
        decision, reason = self.bash("git push --force origin master")
        self.assertEqual(decision, "deny", reason)
        self.assertNotIn(fake("github"), reason)

    def test_broken_user_config_keeps_fail_mode(self):
        self.write_config({"rules": {"GIT01": "bogus"}})
        decision, reason = self.bash("git status")
        self.assertEqual(decision, "ask", reason)
        self.assertIn("could not check", reason)


class FailMode(ToolCase):
    def test_user_fail_mode_applies_to_internal_errors(self):
        self.write_config({"fail_mode": "deny"})
        out = self.hook("pre", None, raw="{not json")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_user_fail_mode_applies_to_broken_user_rules(self):
        self.write_config({"fail_mode": "deny", "rules": {"GIT01": "bogus"}})
        self.assertDecision("deny", self.bash("git status"))

    def test_strictest_wins(self):
        self.write_config({"fail_mode": "allow"})
        out = self.hook("pre", None, raw="{not json", extra_env={"CLAUDE_PLUGIN_OPTION_FAIL_MODE": "deny"})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_project_cannot_loosen_fail_mode(self):
        self.write_config({"fail_mode": "deny"})
        self.write_config({"fail_mode": "allow"}, where="project")
        out = self.hook("pre", None, raw="{not json")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_default_is_ask(self):
        out = self.hook("pre", None, raw="{not json")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")


def make_plugin(root, name="foo", text="print('hi')\n"):
    os.makedirs(os.path.join(root, ".claude-plugin"))
    with open(os.path.join(root, ".claude-plugin", "plugin.json"), "w") as fh:
        json.dump({"name": name, "version": "1.0.0"}, fh)
    with open(os.path.join(root, "run.py"), "w") as fh:
        fh.write(text)
    return root


class PluginMarketplaceBinding(ToolCase):
    def _approve_plugin(self, *extra, expect=0):
        repo = make_plugin(os.path.join(self.tmp, "foo-repo"))
        report = json.loads(self.tool(SKILLGATE, "vet", repo, "--json"))
        self.assertEqual(report["kind"], "plugin")
        return repo, self.tool(SKILLGATE, "approve", report["id"], "--override", *extra, expect=expect)

    def test_legacy_unbound_approval_does_not_cover_any_marketplace(self):
        with open(os.path.join(self.data, "ledger.json"), "w") as fh:
            json.dump({"version": 1, "entries": {"plugin:foo": {
                "kind": "plugin", "name": "foo", "marketplace": None,
                "sources": ["https://github.com/a/foo"]}}}, fh)
        self.assertDecision("deny", self.bash(INSTALL + " foo@evil-market"), "SKL02")

    def test_plugin_approval_needs_marketplace(self):
        _repo, out = self._approve_plugin(expect=1)
        self.assertIn("--marketplace", out)

    def test_plugin_approval_is_bound_to_its_marketplace(self):
        self._approve_plugin("--marketplace", "good-market")
        led = json.loads(self.tool(SKILLGATE, "list", "--json"))
        self.assertIn("plugin:foo@good-market", led["entries"])
        self.assertDecision("allow", self.bash(INSTALL + " foo@good-market"))
        self.assertDecision("deny", self.bash(INSTALL + " foo@evil-market"), "SKL02")

    def test_bad_marketplace_name_is_refused(self):
        _repo, out = self._approve_plugin("--marketplace", "../x", expect=1)
        self.assertIn("marketplace", out)

    def _cache(self, market, text):
        path = os.path.join(self.home, ".claude", "plugins", "cache", market, "foo", "1.0.0")
        make_plugin(path, text=text)
        return path

    def test_mismatched_cache_is_reported_every_session(self):
        self._approve_plugin("--marketplace", "good-market")
        self._cache("good-market", "print('something else')\n")
        for _ in range(2):
            out = self.session()
            self.assertIn("changed since approval: plugin:foo@good-market#1.0.0", out["systemMessage"])
        audit = json.loads(self.tool(SKILLGATE, "audit", "--json"))
        self.assertEqual(audit["changed"], ["plugin:foo@good-market#1.0.0"])

    def test_matching_cache_is_first_look_then_ok(self):
        self._approve_plugin("--marketplace", "good-market")
        self._cache("good-market", "print('hi')\n")
        out = self.session()
        self.assertIn("first look", out["systemMessage"])
        self.assertNotIn("changed since approval", out["systemMessage"])
        self.assertIsNone(self.session())

    def test_revet_clears_mismatch(self):
        self._approve_plugin("--marketplace", "good-market")
        self._cache("good-market", "print('other')\n")
        self.assertIn("changed since approval", self.session()["systemMessage"])
        repo = make_plugin(os.path.join(self.tmp, "foo-v2"), text="print('other')\n")
        report = json.loads(self.tool(SKILLGATE, "vet", repo, "--json"))
        self.tool(SKILLGATE, "approve", report["id"], "--override", "--marketplace", "good-market")
        self.assertIsNone(self.session())


class Sec03DiffConfig(HookCase):
    def setUp(self):
        super().setUp()
        self.init_repo()
        self.write_config({"rules": {"SEC03": "deny"}, "secret_scanner": "builtin"})

    def _stage(self, name):
        with open(os.path.join(self.project, name), "w") as fh:
            fh.write("token %s\n" % fake("github"))
        self.git("add", name)

    def test_noprefix(self):
        self._stage("a.txt")
        self.git("config", "diff.noprefix", "true")
        self.assertDecision("deny", self.bash("git commit -m add"), "SEC03")

    def test_mnemonic_prefix(self):
        self._stage("a.txt")
        self.git("config", "diff.mnemonicPrefix", "true")
        self.assertDecision("deny", self.bash("git commit -m add"), "SEC03")

    def test_quoted_path(self):
        name = "tëst \"q\".txt"
        self._stage(name)
        decision, reason = self.bash("git commit -m add")
        self.assertEqual(decision, "deny", reason)
        self.assertIn("SEC03", reason)
        self.assertIn(name, reason)

    def test_quoted_path_honours_ignore(self):
        self.write_config({"rules": {"SEC03": "deny"}, "secret_scanner": "builtin",
                           "secret_ignore_paths": ["fixtures/*"]})
        os.makedirs(os.path.join(self.project, "fixtures"))
        self._stage(os.path.join("fixtures", "é.txt"))
        self.assertDecision("allow", self.bash("git commit -m add"))


class McpPatternLimits(ToolCase):
    def test_catastrophic_project_pattern_is_ignored_fast(self):
        self.write_config({"rules": {"MCP01": "ask"}, "mcp_write_tools": ["^mcp__(a+)+$"]}, where="project")
        start = time.time()
        self.pre("mcp__" + "a" * 32 + "!", {})
        self.assertLess(time.time() - start, 5)
        self.assertIn("project config", self.session()["systemMessage"])

    def test_validate_rejects_risky_patterns(self):
        from checkrein import cfg
        reg = cfg.load_registry()
        for pat in ("^mcp__(a+)+$", "(a*)*", "(?:x|xy)+", "(a{1,9})*", r"(a)\1", "x" * 700, "(unclosed",
                    "{a,b}" * 9):
            for key in ("mcp_write_tools", "mcp_routine"):
                with self.assertRaises(cfg.ConfigError, msg=pat):
                    cfg.validate({key: [pat]}, "test", reg)
        for pat in reg["defaults"]["mcp_write_tools"] + ["*__set_session_title", "*", "mcp__x__[ab]",
                                                         "mcp__jira__{create,edit}_issue"]:
            cfg.validate({"mcp_write_tools": [pat]}, "test", reg)

    def test_user_risky_pattern_goes_through_fail_mode(self):
        self.write_config({"mcp_write_tools": ["^mcp__(a+)+$"]})
        start = time.time()
        decision, reason = self.pre("mcp__" + "a" * 32 + "!", {})
        self.assertLess(time.time() - start, 5)
        self.assertEqual(decision, "ask", reason)


_WORKER = r"""
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
from checkrein import approve, ledger
mode, data, tag = sys.argv[2], sys.argv[3], sys.argv[4]
for i in range(25):
    if mode == "grant":
        approve.grant(data, "/p", "k-%s-%d" % (tag, i), [tag, i])
    else:
        with ledger.locked(data):
            led = ledger.load(data) or ledger.empty()
            led["entries"]["skill:user:%s-%d" % (tag, i)] = {"kind": "skill"}
            ledger.save(data, led)
"""


class ConcurrentWrites(HookCase):
    def _run(self, mode):
        script = os.path.join(self.tmp, "worker.py")
        with open(script, "w") as fh:
            fh.write(_WORKER)
        procs = [subprocess.Popen([sys.executable, script, SCRIPTS, mode, self.data, str(n)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                 for n in range(4)]
        for p in procs:
            _out, err = p.communicate(timeout=60)
            self.assertEqual(p.returncode, 0, err)

    def test_concurrent_grants_keep_every_approval(self):
        self._run("grant")
        from checkrein import approve
        self.assertEqual(len(approve.load(self.data)), 100)
        self.assertEqual([n for n in os.listdir(self.data) if "tmp" in n], [])

    def test_concurrent_ledger_updates_keep_every_entry(self):
        self._run("ledger")
        from checkrein import ledger
        self.assertEqual(len(ledger.load(self.data)["entries"]), 100)


class InstallSafety(ToolCase):
    def test_vet_name_cannot_escape(self):
        repo = os.path.join(self.tmp, "coll")
        os.makedirs(os.path.join(repo, "skills", "one"))
        with open(os.path.join(repo, "skills", "one", "SKILL.md"), "w") as fh:
            fh.write("---\nname: one\ndescription: x\n---\nHi\n")
        for bad in ("../..", "..", "a/b", ".hidden", ""):
            out = self.tool(SKILLGATE, "vet", repo, "--name", bad, "--json", expect=1)
            self.assertIn("name", out)
        report = json.loads(self.tool(SKILLGATE, "vet", repo, "--name", "one", "--json"))
        self.assertEqual(report["subject"], os.path.join("tree", "skills", "one"))

    def test_post_copy_mismatch_leaves_nothing_installed(self):
        src = os.path.join(self.tmp, "greeter")
        os.makedirs(src)
        with open(os.path.join(src, "SKILL.md"), "w") as fh:
            fh.write("---\nname: greeter\ndescription: x\n---\nHi\n")
        report = json.loads(self.tool(SKILLGATE, "vet", src, "--json"))
        import shutil
        import skillgate
        real_copytree = shutil.copytree

        def tampering_copytree(s, d, *a, **k):
            result = real_copytree(s, d, *a, **k)
            with open(os.path.join(d, "extra.sh"), "w") as fh:
                fh.write("echo sneaky\n")
            return result

        skills = os.path.join(self.home, ".claude", "skills")
        with mock.patch.dict(os.environ, {"HOME": self.home}), \
                mock.patch.object(skillgate.shutil, "copytree", tampering_copytree):
            with self.assertRaises(SystemExit) as exc:
                skillgate.main(["--data", self.data, "--project", self.project, "approve", report["id"], "--override"])
        self.assertIn("does not match", str(exc.exception.code))
        self.assertEqual(os.listdir(skills) if os.path.isdir(skills) else [], [])
        self.assertNotIn("skill:user:greeter", json.loads(self.tool(SKILLGATE, "list", "--json"))["entries"]
                         if os.path.exists(os.path.join(self.data, "ledger.json")) else {})


if __name__ == "__main__":
    unittest.main()
