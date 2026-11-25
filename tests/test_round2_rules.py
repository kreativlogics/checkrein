"""Round 2 review findings: the plugin CLI, globs and braces, config file safety, MCP globs, write-target gaps,
writing "read-only" commands, split secrets in commands and interpreter heredocs."""

import json
import os
import subprocess
import sys
import time
import unittest

from helpers import GUARD, HookCase, fake

PLUGIN_CLI = "claude " + "plugin"
PLUGINS_CLI = "claude " + "plugins"


class Base(HookCase):
    def assertHit(self, result, rule):
        decision, reason = result
        self.assertIn(decision, ("ask", "deny"), reason)
        self.assertIn("checkrein %s" % rule, reason)

    def allow(self, command, **kw):
        self.assertDecision("allow", self.bash(command, **kw))

    def hook_timed(self, payload, timeout=10, extra_env=None):
        """Run the hook with a short timeout; returns (decision, reason, seconds)."""
        env = dict(self.env)
        env.update(extra_env or {})
        start = time.time()
        res = subprocess.run([sys.executable, GUARD, "pre"], input=json.dumps(payload), env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
        took = time.time() - start
        self.assertEqual(res.returncode, 0, res.stderr)
        if not res.stdout.strip():
            return "allow", "", took
        spec = json.loads(res.stdout)["hookSpecificOutput"]
        return spec["permissionDecision"], spec["permissionDecisionReason"], took

    def bash_timed(self, command, timeout=10):
        return self.hook_timed({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": self.project,
                                "permission_mode": "default"}, timeout)

    @property
    def skills(self):
        return os.path.join(self.home, ".claude", "skills")


class InstalledDataDir(Base):
    """The data dir where Claude Code puts it: ~/.claude/plugins/data/checkrein-<marketplace>."""

    def setUp(self):
        super(InstalledDataDir, self).setUp()
        self.data = os.path.join(self.home, ".claude", "plugins", "data", "checkrein-checkrein")
        os.makedirs(self.data)
        self.env["CLAUDE_PLUGIN_DATA"] = self.data


class PluginCli(InstalledDataDir):
    """N5: plugin|plugins, option values, --all, configure, update, marketplace update."""

    def _ledger(self):
        with open(os.path.join(self.data, "ledger.json"), "w") as fh:
            json.dump({"version": 1, "entries": {"plugin:foo@good": {
                "kind": "plugin", "name": "foo", "marketplace": "good", "sources": ["github.com/a/foo"],
                "tree_hash": "x"}}}, fh)

    def test_turning_checkrein_off(self):
        for cmd in ("%s disable checkrein@checkrein" % PLUGINS_CLI,
                    "%s disable -s user checkrein@checkrein" % PLUGIN_CLI,
                    "%s disable --scope=user checkrein@checkrein" % PLUGIN_CLI,
                    "%s disable --all" % PLUGIN_CLI,
                    "%s disable -a" % PLUGIN_CLI,
                    "%s uninstall -s project checkrein@checkrein" % PLUGIN_CLI,
                    "%s remove checkrein" % PLUGINS_CLI,
                    "echo '{\"preset\":\"relaxed\",\"fail_mode\":\"allow\"}' | %s configure checkrein@checkrein "
                    "--values-stdin" % PLUGIN_CLI,
                    "%s marketplace remove --scope user checkrein" % PLUGINS_CLI):
            self.assertDecision("deny", self.bash(cmd), "SLF01")

    def test_installs_and_updates_need_the_gate(self):
        self._ledger()
        for cmd in ("%s install evil@mkt" % PLUGINS_CLI,
                    "%s i -s project evil@mkt" % PLUGIN_CLI,
                    "%s update evil@mkt" % PLUGIN_CLI,
                    "%s update foo@good" % PLUGIN_CLI,
                    "%s marketplace update" % PLUGIN_CLI,
                    "%s marketplace update good" % PLUGINS_CLI,
                    "%s install foo --marketplace evil/repo" % PLUGIN_CLI,
                    "%s install foo@good --marketplace=evil/repo" % PLUGIN_CLI):
            self.assertDecision("deny", self.bash(cmd), "SKL02")

    def test_scope_value_is_not_the_plugin(self):
        """N13b: -s project must not be read as the plugin name."""
        self._ledger()
        self.allow("%s install -s project foo@good" % PLUGIN_CLI)
        self.allow("%s install --scope project foo@good" % PLUGIN_CLI)
        self.allow("%s i foo@good -s local" % PLUGINS_CLI)

    def test_everyday_plugin_commands(self):
        self._ledger()  # Round 7: enable needs the plugin approved, as an enabledPlugins entry does.
        for cmd in ("list", "list --json", "marketplace list", "details foo", "enable foo@good",
                    "disable -s user other@good", "configure checkrein@checkrein", "validate .",
                    "configure other@good --values-stdin"):
            self.allow("%s %s" % (PLUGIN_CLI, cmd))


class GlobsAndBraces(InstalledDataDir):
    """N6: a glob or brace word that can reach a protected path counts as that path."""

    def test_globs_reach_protected_paths(self):
        self.assertDecision("deny", self.bash("rm -f ~/.claude/plugins/data/checkrein-*/config.json"), "SLF01")
        self.assertDecision("deny", self.bash("rm -f ~/.claude/plugins/data/checkrein-checkrei?/ledger.json"),
                            "SLF01")
        self.assertDecision("deny", self.bash("rm -rf ~/.claude/plugins/dat[a]"), "SLF01")
        self.assertDecision("deny", self.bash("cp -r /tmp/x ~/.claude/skill?/evil"), "SKL01")
        self.assertDecision("deny", self.bash("cp -r /tmp/x ~/.claude/*/evil"), "SKL01")
        self.assertDecision("deny", self.bash("sed -i 's/checkrein/x/' ~/.claude/settings.js?n"), "SLF01")

    def test_braces_reach_protected_paths(self):
        self.assertDecision("deny", self.bash("rm -f ~/.claude/plugins/data/{checkrein-checkrein,x}/config.json"),
                            "SLF01")
        # cp's destination is its last word, so {y,skills} puts the copy in skills (bash runs
        # cp -r /tmp/x ~/.claude/y/evil ~/.claude/skills/evil); {skills,y} would copy into y.
        self.assertDecision("deny", self.bash("cp -r /tmp/x ~/.claude/{y,skills}/evil"), "SKL01")
        script = "python3 -c 'import json,sys; d={\"enabledPlugins\": {}}' "
        self.assertDecision("deny", self.bash(script + "~/.claude/settings.json"), "SLF01")
        self.assertDecision("deny", self.bash(script + "~/.claude/{settings.json,x}"), "SLF01")

    def test_globs_that_cannot_reach_stay_allowed(self):
        os.makedirs(os.path.join(self.project, ".checkrein"))
        for cmd in ("rm -f build/*.o", "cp src/*.py /tmp/", "cp -r dist/* /tmp/out/", "rm -rf *",
                    "rm -f ~/.cache/*.tmp", "mv build/* /tmp/old/", "rm -f ~/*.log", "ls ~/.claude/*",
                    "cat ~/.claude/plugins/data/checkrein-*/config.json"):
            self.allow(cmd)


class ConfigFiles(Base):
    """N7: an odd project config file is ignored, never handed to fail_mode; nothing can hang the hook."""

    push = "git push --force origin master"

    def setUp(self):
        super(ConfigFiles, self).setUp()
        self.write_config({"fail_mode": "allow"})
        self.proj_cfg = os.path.join(self.project, ".checkrein", "config.json")
        os.makedirs(os.path.dirname(self.proj_cfg))

    def _check_ignored(self):
        decision, reason, took = self.bash_timed(self.push)
        self.assertEqual(decision, "deny", reason)
        self.assertIn("GIT01", reason)
        self.assertLess(took, 8)
        self.assertIn("project config", self.hook("session", {"cwd": self.project})["systemMessage"])

    def test_directory(self):
        os.makedirs(self.proj_cfg)
        self._check_ignored()

    def test_symlink_to_directory(self):
        os.symlink(self.tmp, self.proj_cfg)
        self._check_ignored()

    def test_symlink_to_device(self):
        os.symlink("/dev/zero", self.proj_cfg)
        self._check_ignored()

    def test_fifo(self):
        os.mkfifo(self.proj_cfg)
        self._check_ignored()

    def test_too_large(self):
        with open(self.proj_cfg, "w") as fh:
            fh.write("{" + " " * (300 * 1024) + "}")
        self._check_ignored()

    def test_deeply_nested(self):
        with open(self.proj_cfg, "w") as fh:
            fh.write("[" * 100000 + "]" * 100000)
        self._check_ignored()

    def test_user_config_fifo_does_not_hang(self):
        os.remove(os.path.join(self.data, "config.json"))
        os.mkfifo(os.path.join(self.data, "config.json"))
        decision, reason, took = self.bash_timed("git status")
        self.assertEqual(decision, "ask", reason)  # A broken user config still goes to fail_mode.
        self.assertLess(took, 8)

    def test_user_config_directory_goes_to_fail_mode(self):
        os.remove(os.path.join(self.data, "config.json"))
        os.makedirs(os.path.join(self.data, "config.json"))
        decision, reason, _took = self.bash_timed("git status")
        self.assertEqual(decision, "ask", reason)

    def test_ledger_fifo_does_not_hang(self):
        os.mkfifo(os.path.join(self.data, "ledger.json"))
        decision, reason, took = self.bash_timed("%s install foo@good" % PLUGIN_CLI)
        self.assertEqual(decision, "deny", reason)
        self.assertLess(took, 8)


class McpGlobs(Base):
    """N8: MCP tool lists are globs matched in linear time; regexes are refused."""

    def _mcp(self, name, timeout=10):
        return self.hook_timed({"tool_name": name, "tool_input": {"a": 1}, "cwd": self.project,
                                "permission_mode": "default"}, timeout)

    def test_project_patterns_cannot_stall(self):
        for pat, name in (("(.*.*){12}Z", "mcp__srv__" + "x" * 40),
                          (".*.*.*.*.*.*.*.*.*.*.*.*Z", "mcp__" + "a" * 60),
                          ("*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b", "mcp__" + "a" * 200)):
            self.write_config({"preset": "strict", "mcp_write_tools": [pat]}, where="project")
            _decision, _reason, took = self._mcp(name)
            self.assertLess(took, 5, pat)

    def test_globs_match_case_insensitively(self):
        self.write_config({"preset": "strict", "mcp_write_tools": ["mcp__tracker__frob*"],
                           "mcp_routine": ["*__set_session_title"]})
        self.assertDecision("ask", self.pre("mcp__tracker__FrobIssue", {"t": 1}), "MCP01")
        self.assertDecision("ask", self.pre("mcp__tracker__create_issue", {"t": 1}), "MCP01")
        self.assertDecision("allow", self.pre("mcp__session__set_session_title", {"t": "x"}))
        self.assertDecision("allow", self.pre("mcp__tracker__list_issues", {"t": 1}))

    def test_regex_values_are_refused(self):
        from checkrein import cfg
        reg = cfg.load_registry()
        for pat in ("^mcp__(a+)+$", "__set_session_title$", ".*", "mcp__x__(a|b)", r"\w+", "a" * 700, 5):
            for key in ("mcp_write_tools", "mcp_routine"):
                with self.assertRaises(cfg.ConfigError, msg=pat):
                    cfg.validate({key: [pat]}, "test", reg)
        for pat in reg["defaults"]["mcp_write_tools"] + ["mcp__*__create*", "*__set_session_title",
                                                         "mcp__jira__{create,edit}_issue", "mcp__x__[ab]?",
                                                         "mcp__x__[!c]*"]:
            cfg.validate({"mcp_write_tools": [pat]}, "test", reg)

    def test_glob_matcher_is_linear(self):
        from checkrein import globs
        start = time.time()
        self.assertFalse(globs.match("*a" * 100 + "*b", "a" * 5000))
        self.assertLess(time.time() - start, 2)
        self.assertTrue(globs.match("mcp__*__{create,update}*", "MCP__x__UpdateThing"))
        self.assertFalse(globs.match("mcp__*__{create,update}*", "mcp__x__list_updates"))


class WriteTargetGaps(Base):
    """N9: clustered download flags, copies into a parent of a skill root, git work trees."""

    def test_clustered_download_flags(self):
        self.assertDecision("deny", self.bash("curl -sSLo %s/x/SKILL.md https://example.invalid/x" % self.skills),
                            "SKL01")
        self.assertDecision("deny", self.bash("wget -qO %s/x/SKILL.md https://example.invalid/x" % self.skills),
                            "SKL01")
        self.assertDecision("deny", self.bash("curl -fsSLo%s/x/SKILL.md https://example.invalid/x" % self.skills),
                            "SKL01")

    def test_copy_into_skill_parent(self):
        claude = os.path.join(self.home, ".claude")
        self.assertDecision("deny", self.bash("cp -r /tmp/stage/skills %s/" % claude), "SKL01")
        self.assertDecision("deny", self.bash("rsync -a /tmp/stage/ %s/" % claude), "SKL01")
        self.assertDecision("deny", self.bash("ditto /tmp/stage %s" % claude), "SKL01")
        self.assertDecision("deny", self.bash("mv /tmp/stage/skills %s" % claude), "SKL01")
        self.assertDecision("deny", self.bash("cp -r /tmp/stage/.claude %s" % self.home), "SKL01")
        self.assertDecision("deny", self.bash("cp -r /tmp/stage/* %s/" % claude), "SKL01")

    def test_git_work_tree(self):
        self.assertDecision("deny", self.bash("git --git-dir=/tmp/e.git --work-tree=%s/x checkout HEAD -- ."
                                              % self.skills), "SKL01")
        self.assertDecision("deny", self.bash("git --work-tree %s/x checkout HEAD -- ." % self.skills), "SKL01")
        self.assertDecision("deny", self.bash("GIT_WORK_TREE=%s/x git checkout HEAD -- ." % self.skills), "SKL01")

    def test_everyday_copies(self):
        claude = os.path.join(self.home, ".claude")
        for cmd in ("cp notes.txt %s/" % claude, "cp -r dist /tmp/out/", "rsync -a dist/ /tmp/out/",
                    "curl -sSLo /tmp/x https://example.invalid/x", "wget -qO /tmp/x https://example.invalid/x",
                    "cp -r myproject %s/" % self.home, "git --work-tree=/tmp/w checkout HEAD -- ."):
            self.allow(cmd)


class WritingReaders(Base):
    """N10: commands treated as read-only that write or run something."""

    def test_writes_and_runs(self):
        d = self.data
        for cmd in ("rg --pre rm x %s" % d,
                    "rg --pre=rm x %s" % d,
                    "sed --in-place=.bak s/a/b/ %s/config.json" % d,
                    "sed --in-pl s/a/b/ %s/config.json" % d,
                    "sed -ni s/a/b/p %s/config.json" % d,
                    "sed -Ei.bak s/a/b/ %s/config.json" % d,
                    "find /tmp -fprint0 %s/config.json" % d,
                    "fd -x rm . %s" % d,
                    "git grep -O'rm -f' x -- %s" % d,
                    "git grep --open-files-in-pager=rm x -- %s" % d,
                    "LESSOPEN='|rm %%s' less %s/config.json" % d,
                    "git -c core.pager=rm log -- %s" % d,
                    "sort --compress-program=rm %s/config.json" % d):
            self.assertDecision("deny", self.bash(cmd), "SLF01")

    def test_reads_stay_allowed(self):
        d = self.data
        for cmd in ("rg --hidden foo %s" % d, "rg --pretty foo %s" % d, "grep -i foo %s/config.json" % d,
                    "sed -n 1p %s/config.json" % d, "find %s -name '*.json' -print0" % d,
                    "git grep foo -- %s" % d, "less %s/config.json" % d, "sed -i.bak s/a/b/ src/x.py",
                    "rg --hidden foo", "find . -name '*.py' -print0"):
            self.allow(cmd)


class SplitSecrets(Base):
    """N13a: a token split by quotes is joined the way the shell joins it."""

    def test_quoted_pieces(self):
        tok = fake("github")
        self.assertDecision("deny", self.bash("echo %s''%s > .env" % (tok[:10], tok[10:])), "SEC02")
        self.assertDecision("deny", self.bash("echo %s\"\"%s" % (tok[:8], tok[8:])), "SEC02")
        self.assertDecision("deny", self.bash("export T='%s'%s" % (tok[:12], tok[12:])), "SEC02")

    def test_plain_words_allowed(self):
        self.allow("echo 'ghp_' is the prefix")


class InterpreterHeredocs(InstalledDataDir):
    """N4: an interpreter reading its script from a heredoc is judged like its -c form."""

    def setUp(self):
        super(InterpreterHeredocs, self).setUp()
        from checkrein import shell
        cmds = shell.parse("python3 - <<'EOF'\nx\nEOF").cmds
        if not cmds or not hasattr(cmds[0], "stdin_text"):
            self.skipTest("Needs shell.Cmd.stdin_text (heredoc parsing change, landing separately).")

    def test_heredoc_scripts(self):
        d = self.data
        self.assertDecision("deny", self.bash("python3 -c \"import os; os.remove('%s/config.json')\"" % d), "SLF01")
        self.assertDecision("deny", self.bash("python3 - <<'EOF'\nimport os; os.remove('%s/config.json')\nEOF" % d),
                            "SLF01")
        self.assertDecision("deny", self.bash("node <<<\"require('fs').unlinkSync('%s/config.json')\"" % d),
                            "SLF01")
        settings = os.path.join(self.home, ".claude", "settings.json")
        self.assertDecision("deny", self.bash(
            "python3 - <<'EOF'\nimport json\np='%s'\nd=json.load(open(p)); d['enabledPlugins']={}\n"
            "json.dump(d, open(p,'w'))\nEOF" % settings), "SLF01")

    def test_heredoc_text_for_other_commands(self):
        self.allow("git commit -q --allow-empty -F - <<'EOF'\nMention %s/config.json in a message.\nEOF" % self.data)
        self.allow("cat <<'EOF'\n%s/config.json\nEOF" % self.data)


class EverydayCommands(Base):
    def test_allowed(self):
        for cmd in ("rm -f build/*.o", "cp -r dist/* /tmp/out/", "curl -sSLo /tmp/x https://example.invalid/x",
                    "sed -i.bak s/a/b/ src/x.py", "rg --hidden foo", "find . -name '*.py' -print0",
                    "%s list" % PLUGIN_CLI, "%s marketplace list" % PLUGIN_CLI, "ls -la ~/.claude/",
                    "cp README.md /tmp/", "rsync -av src/ build/", "tar -czf /tmp/a.tgz src"):
            self.allow(cmd)


def _fs_ignores_case(path):
    probe = os.path.join(path, "CaseProbe")
    os.makedirs(probe, exist_ok=True)
    try:
        return os.path.exists(os.path.join(path, "caseprobe"))
    finally:
        os.rmdir(probe)


class CaseInsensitivePaths(InstalledDataDir):
    """A case-insensitive file system (macOS, Windows) reaches protected paths under any case."""

    def setUp(self):
        super(CaseInsensitivePaths, self).setUp()
        if not _fs_ignores_case(self.tmp):
            self.skipTest("The temp folder's file system is case-sensitive.")
        os.makedirs(self.skills)

    def test_other_case_reaches(self):
        self.assertDecision("deny", self.bash("cp -r /tmp/x ~/.claude/SKILLS/x"), "SKL01")
        self.assertDecision("deny", self.bash("cp -r /tmp/x ~/.Claude/Skill?/x"), "SKL01")
        self.assertDecision("deny", self.bash("rm -f ~/.claude/plugins/data/CHECKREIN-checkrein/config.json"),
                            "SLF01")
        self.assertDecision("deny", self.bash("python3 -c 'd={\"enabledPlugins\": {}}' ~/.Claude/Settings.json"),
                            "SLF01")
        self.assertDecision("deny", self.pre("Write", {"file_path": os.path.join(self.home, ".claude", "Plugins", "x"),
                                                       "content": "x"}), "SKL01")
        with open(os.path.join(self.home, ".claude", "settings.json"), "w") as fh:
            json.dump({"enabledPlugins": {"checkrein@checkrein": True}}, fh)
        self.assertDecision("deny", self.pre("Edit", {"file_path": os.path.join(self.home, ".CLAUDE", "settings.json"),
                                                      "old_string": "true", "new_string": "false"}), "SLF01")
        self.assertDecision("deny", self.pre("Write", {"file_path": os.path.join(self.data.upper(), "config.json"),
                                                       "content": "{}"}), "SLF01")


class CaseSensitivePaths(unittest.TestCase):
    """On a case-sensitive file system other cases are other paths."""

    def test_no_match(self):
        from checkrein import context
        saved = context.case_insensitive
        context.case_insensitive = lambda path: False
        try:
            self.assertFalse(context.inside("/h/.claude/SKILLS/x", "/h/.claude/skills"))
            self.assertFalse(context.inside("/h/.claude/SKILL?/x", "/h/.claude/skills"))
            self.assertFalse(context.same_path("/h/.Claude/settings.json", "/h/.claude/settings.json"))
            self.assertTrue(context.inside("/h/.claude/skills/x", "/h/.claude/skills"))
            self.assertTrue(context.inside("/h/.claude/skill?/x", "/h/.claude/skills"))
        finally:
            context.case_insensitive = saved


class MarketplaceSources(Base):
    """A marketplace source matches its ledger record in any of the usual spellings, and only its own repo."""

    def _ledger(self, source):
        with open(os.path.join(self.data, "ledger.json"), "w") as fh:
            json.dump({"version": 1, "entries": {"marketplace:mk": {
                "kind": "marketplace", "name": "mk", "plugins": ["bar"], "sources": [source]}}}, fh)

    def test_spellings_match(self):
        host = "git" + "hub.com"
        for recorded in ("a/mk", host + "/a/mk", "https://%s/a/mk.git" % host, "https://%s/A/MK/" % host):
            self._ledger(recorded)
            for typed in ("a/mk", "A/mk", host + "/a/mk", "https://%s/a/mk" % host, "https://%s/a/mk.git" % host,
                          "https://%s/a/mk/" % host, "https://www.%s/a/mk" % host,
                          "ssh://git" + "@%s/a/mk.git" % host):
                self.assertDecision("allow", self.bash("%s marketplace add %s" % (PLUGIN_CLI, typed)))
                self.allow("%s install bar --marketplace %s" % (PLUGIN_CLI, typed))

    def test_other_repos_do_not_match(self):
        host = "git" + "hub.com"
        self._ledger(host + "/a/mk")
        for typed in ("a/mk2", "b/mk", "a/mk/sub", "gitlab.com/a/mk", "https://evil.example/a/mk",
                      "https://%s.evil.example/a/mk" % host, "a/mk#other-branch", "https://evil.example/%s/a/mk"
                      % host, "http://%s/a/mk" % host):
            self.assertDecision("deny", self.bash("%s marketplace add %s" % (PLUGIN_CLI, typed)), "SKL02")

    def test_normalize(self):
        from checkrein import ledger
        host = "git" + "hub.com"
        self.assertEqual(ledger.normalize_source("a/mk"), ledger.normalize_source("git" + "@%s:a/mk.git" % host))
        self.assertNotEqual(ledger.normalize_source("gitlab.com/a/mk"), ledger.normalize_source("gitlab.com/a/MK"))


if __name__ == "__main__":
    unittest.main()
