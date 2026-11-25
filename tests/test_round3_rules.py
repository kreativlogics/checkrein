"""Round 3 review findings: the own-tool exemption, paths relative to a changed folder, settings edits that turn
checkrein off, git config-driven force pushes and cleans, MCP secrets after a newline, character ranges in braces,
control characters in config and relative marketplace sources."""

import json
import os
import subprocess
import sys
import time
import unittest

from helpers import PLUGIN, SCRIPTS, fake
from test_round2_rules import Base

PLUGIN_CLI = "claude " + "plugin"
CFGTOOL = os.path.join(SCRIPTS, "cfgtool.py")
BRANCH = "mas" + "ter"


class OwnTool(Base):
    """F1: only a plain `python3 <plugin>/scripts/<tool>.py ...` is checkrein's own tool."""

    def test_interpreter_options_or_env_are_not_own_tool(self):
        cfg = os.path.join(self.data, "config.json")
        for command in ("python3 -c \"-1;import json;open('%s','w').write('{}')\" %s show" % (cfg, CFGTOOL),
                        "python3 -c \"-1;import os\" %s show" % CFGTOOL,
                        "PYTHONPATH=/tmp/evil python3 %s show" % CFGTOOL,
                        "PYTHONSTARTUP=/tmp/evil.py python3 %s show" % CFGTOOL,
                        "python3 -W ignore::DeprecationWarning %s show" % CFGTOOL,
                        "python3 -i %s show" % CFGTOOL):
            self.assertDecision("deny", self.bash(command), "SLF01")

    def test_plain_own_tool(self):
        self.allow("python3 %s show" % CFGTOOL)
        self.allow("python3 %s --data %s show" % (CFGTOOL, self.data))
        self.assertDecision("allow", self.bash(
            'python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cfgtool.py" --data "${CLAUDE_PLUGIN_DATA}" show',
            extra_env={"CLAUDE_PLUGIN_ROOT": PLUGIN}))
        self.assertDecision("ask", self.bash("python3 %s set rules.SLF01 off" % CFGTOOL), "SLF01")
        self.assertDecision("ask", self.bash("python3 %s --data /tmp/x set rules.SLF01 off" % CFGTOOL), "SLF01")

    def test_own_tool_redirect_still_counts(self):
        self.assertDecision("deny", self.bash("python3 %s show > %s/config.json" % (CFGTOOL, self.data)), "SLF01")


class RelativeToChangedFolder(Base):
    """F2: a command run after cd into a protected folder, or naming it by a relative path."""

    def test_cd_into_data_dir(self):
        self.assertDecision("deny", self.bash("cd %s && python3 -c \"open('config.json','w')\"" % self.data),
                            "SLF01")
        self.assertDecision("deny", self.bash("cd %s && ed -s config.json <<< ',d'" % self.data), "SLF01")
        self.assertDecision("deny", self.bash("cd %s && node -e \"require('fs').rmSync('x')\"" % self.data),
                            "SLF01")

    def test_relative_word_in_code(self):
        parent, name = os.path.split(self.data)
        self.assertDecision("deny", self.bash("cd %s && python3 -c \"open('%s/config.json','w')\"" % (parent, name)),
                            "SLF01")

    def test_reads_and_other_folders_stay_allowed(self):
        self.allow("cd %s && cat config.json" % self.data)
        self.allow("cd %s && ls -la && grep -n rules config.json" % self.data)
        self.allow("cd %s && python3 -c \"open('config.json','w')\"" % self.project)


class SettingsSwitchOff(Base):
    """F6: any change to a settings file that holds checkrein's switch or hooks must keep them on."""

    def setUp(self):
        super(SettingsSwitchOff, self).setUp()
        os.makedirs(os.path.join(self.home, ".claude"))
        self.sp = os.path.join(self.home, ".claude", "settings.json")
        self._write({"enabledPlugins": {"checkrein@checkrein": True}, "theme": "dark"})

    def _write(self, data):
        with open(self.sp, "w") as fh:
            json.dump(data, fh, indent=2)

    def edit(self, old, new):
        return self.pre("Edit", {"file_path": self.sp, "old_string": old, "new_string": new})

    def test_edits_that_switch_off(self):
        self.assertDecision("deny", self.edit("true", "false"), "SLF01")
        self.assertDecision("deny", self.edit('"enabledPlugins"', '"enabledPluginsOld"'), "SLF01")
        self.assertDecision("deny", self.edit('"theme": "dark"', '"theme": "dark", "disableAllHooks": true'),
                            "SLF01")
        self.assertDecision("deny", self.pre("Write", {"file_path": self.sp, "content": "{}"}), "SLF01")
        self.assertDecision("deny", self.pre("MultiEdit", {"file_path": self.sp, "edits": [
            {"old_string": "dark", "new_string": "light"}, {"old_string": "true", "new_string": "false"}]}),
            "SLF01")

    def test_hooks_changes(self):
        self._write({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command",
                                                                              "command": "x"}]}]}})
        self.assertDecision("deny", self.edit('"command": "x"', '"command": "true"'), "SLF01")

    def test_bash_changes(self):
        for command in ("rm ~/.claude/settings.json", "echo '{}' > ~/.claude/settings.json",
                        "sed -i '' s/true/false/ ~/.claude/settings.json", "cp /dev/null ~/.claude/settings.json",
                        "mv /tmp/x ~/.claude/settings.json", "truncate -s0 ~/.claude/settings.json",
                        "tee ~/.claude/settings.json < /tmp/x"):
            self.assertDecision("deny", self.bash(command), "SLF01")

    def test_unrelated_changes_stay_allowed(self):
        self.assertDecision("allow", self.edit('"theme": "dark"', '"theme": "light"'))
        self.assertDecision("allow", self.edit('"theme": "dark"', '"theme": "dark",\n  "model": "opus"'))
        keep = json.dumps({"enabledPlugins": {"checkrein@checkrein": True}, "theme": "light"})
        self.assertDecision("allow", self.pre("Write", {"file_path": self.sp, "content": keep}))
        self.allow("cat ~/.claude/settings.json")
        self.allow("jq . ~/.claude/settings.json > /tmp/settings-copy.json")

    def test_plain_settings_file_stays_editable(self):
        self._write({"theme": "dark"})
        self.assertDecision("allow", self.edit("dark", "light"))
        # Round 4 (R9): what a shell command writes can't be checked, so a person confirms it.
        self.assertDecision("ask", self.bash("sed -i '' s/dark/light/ ~/.claude/settings.json"), "SLF01")


class GitConfigForms(Base):
    """F7: force pushes and cleans driven by git config, send-pack, and --signed not taking the next word."""

    def setUp(self):
        super(GitConfigForms, self).setUp()
        self.remote = os.path.join(self.tmp, "remote.git")
        subprocess.run(["git", "init", "-q", "--bare", self.remote], env=self.env, check=True)
        self.init_repo(BRANCH)
        self.git("remote", "add", "origin", self.remote)

    def test_command_line_config(self):
        for command in ("git -c remote.origin.push=+refs/heads/*:refs/heads/* push origin",
                        "git -c remote.origin.push=+refs/heads/%s:refs/heads/%s push origin" % (BRANCH, BRANCH),
                        "git -c remote.origin.mirror=true push origin",
                        "git push origin '+refs/heads/*:refs/heads/*'",
                        "git send-pack --force origin " + BRANCH,
                        "git send-pack origin +" + BRANCH,
                        "git push --signed --force origin " + BRANCH):
            self.assertDecision("deny", self.bash(command), "GIT01")
        self.assertHit(self.bash("git -c clean.requireForce=false clean -dx"), "GIT03")

    def test_repo_config(self):
        self.git("config", "remote.origin.push", "+refs/heads/*:refs/heads/*")
        self.assertDecision("deny", self.bash("git push origin"), "GIT01")
        self.assertDecision("deny", self.bash("git push"), "GIT01")
        self.git("config", "--unset", "remote.origin.push")
        self.git("config", "remote.origin.mirror", "true")
        self.assertDecision("deny", self.bash("git push origin"), "GIT01")
        self.git("config", "clean.requireForce", "false")
        self.assertHit(self.bash("git clean -dx"), "GIT03")

    def test_ordinary_forms_stay_allowed(self):
        self.allow("git push origin " + BRANCH)
        self.allow("git push --signed=if-asked origin " + BRANCH)
        self.allow("git push origin")
        self.allow("git clean -dx")
        self.allow("git clean -n")
        self.allow("git -c clean.requireForce=true clean -dx")


class McpSecretAfterNewline(Base):
    """F8: a token after a newline or tab in an MCP argument."""

    def test_token_after_whitespace(self):
        token = fake("github")
        for text in ("x\n" + token, "x\t" + token, "line1\nline2 " + token, "x\\" + token):
            self.assertHit(self.pre("mcp__slack__send_message", {"channel": "c", "text": text}), "MCP02")
        self.assertHit(self.pre("mcp__slack__send_message", {"channel": "c", "blocks": [{"t": ["a\n" + token]}]}),
                       "MCP02")
        self.assertDecision("allow", self.pre("mcp__slack__read_channel", {"channel": "c", "text": "x\nhello"}))


class CharacterRanges(Base):
    """F9: {a..<last code point>} ranges are refused before they are built."""

    def test_unit(self):
        from checkrein import globs
        start = time.time()
        self.assertIsNone(globs.expand_braces("{a..%s}" % chr(0x10FFFF)))
        self.assertEqual(globs.expand_braces("{a..c}"), ["a", "b", "c"])
        self.assertLess(time.time() - start, 0.5)

    def test_many_ranges_decide_in_time(self):
        command = (" echo {a..%s};" % chr(0x10FFFF)) * 60 + " git push --force origin " + BRANCH
        decision, _reason, took = self.bash_timed(command, timeout=15)
        self.assertIn(decision, ("ask", "deny"))
        self.assertLess(took, 5)


class ConfigControlCharacters(Base):
    """F10: control characters in config values make the layer invalid instead of crashing the hook."""

    def test_project_layer_ignored(self):
        self.write_config({"extra_skill_roots": ["/tmp/a\u0000b"]}, where="project")
        self.allow("ls")
        self.assertDecision("deny", self.bash("git push --force origin " + BRANCH), "GIT01")

    def test_validate(self):
        from checkrein import cfg
        registry = cfg.load_registry()
        for layer in ({"extra_skill_roots": ["/tmp/a\u0000b"]}, {"protected_branches": ["a\nb"]},
                      {"extra_skill_roots": ["relative/skills"]}):
            with self.assertRaises(cfg.ConfigError):
                cfg.validate(layer, "test", registry)
        cfg.validate({"extra_skill_roots": ["/abs/skills", "~/skills"]}, "test", registry)


class RelativeMarketplaceSource(Base):
    """A relative local marketplace source is read against the command's folder."""

    def test_command_cwd(self):
        from checkrein import ledger
        here = os.path.join(self.project, "mk")
        os.makedirs(here)
        self.assertEqual(ledger.normalize_source("./mk", cwd=self.project), "local:" + os.path.realpath(here))
        with open(os.path.join(self.data, "ledger.json"), "w") as fh:
            json.dump({"version": 1, "entries": {"marketplace:mk": {
                "kind": "marketplace", "name": "mk", "plugins": ["bar"], "sources": [here]}}}, fh)
        self.allow("cd %s && %s marketplace add ./mk" % (self.project, PLUGIN_CLI), cwd=self.tmp)
        self.assertDecision("deny", self.bash("cd %s && %s marketplace add ./mk" % (self.tmp, PLUGIN_CLI)), "SKL02")


class UnknownFolder(Base):
    """A cd the reader can't follow (cd "$X"): relative protected names count wherever the command may run."""

    def test_relative_protected_names(self):
        for command, rule in (('cd "$X" && rm -rf .checkrein', "SLF01"),
                              ('cd "$X" && echo x > .checkrein/config.json', "SLF01"),
                              ('cd "$X" && echo {} > .claude/settings.json', "SLF01"),
                              ('cd "$X" && cp -r /tmp/evil .claude/skills/', "SKL01"),
                              ('cd "$X" && cp -r /tmp/evil .claude', "SKL01"),
                              ('cd "$X" && cp /tmp/x .git/hooks/pre-commit', "GIT05")):
            self.assertDecision("deny", self.bash(command, cwd=self.tmp), rule)

    def test_folders_seen_before(self):
        self.assertDecision("deny", self.bash('cd %s; cd "$X"; rm config.json' % self.data, cwd=self.tmp), "SLF01")

    def test_ordinary_work_stays_allowed(self):
        for command in ('cd "$X" && rm -rf build', 'cd "$X" && cat .checkrein/config.json',
                        'cd "$X" && cp a.txt b.txt', 'cd "$X" && ls .claude/skills'):
            self.allow(command, cwd=self.tmp)


class LocalSourceRecord(Base):
    """A local marketplace vetted by a relative path is recorded as its real absolute path."""

    def test_relative_vet_matches_anywhere(self):
        repo = os.path.join(self.project, "market")
        os.makedirs(os.path.join(repo, ".claude-plugin"))
        os.makedirs(os.path.join(repo, "plugins", "helper", ".claude-plugin"))
        with open(os.path.join(repo, ".claude-plugin", "marketplace.json"), "w") as fh:
            json.dump({"name": "testmarket", "owner": {"name": "t"},
                       "plugins": [{"name": "helper", "source": "./plugins/helper"}]}, fh)
        with open(os.path.join(repo, "plugins", "helper", ".claude-plugin", "plugin.json"), "w") as fh:
            json.dump({"name": "helper", "version": "1.0.0"}, fh)
        gate = os.path.join(SCRIPTS, "skillgate.py")

        def tool(*args):
            res = subprocess.run([sys.executable, gate, "--data", self.data] + list(args), env=self.env,
                                 cwd=self.project, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 universal_newlines=True, timeout=60)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            return res.stdout

        report = json.loads(tool("vet", "./market", "--json"))
        tool("approve", report["id"], "--override")
        with open(os.path.join(self.data, "ledger.json")) as fh:
            entry = json.load(fh)["entries"]["marketplace:testmarket"]
        self.assertEqual(entry["sources"], [os.path.realpath(repo)])
        self.assertDecision("allow", self.bash("%s marketplace add %s" % (PLUGIN_CLI, repo), cwd=self.tmp))
        self.assertDecision("allow", self.bash("%s marketplace add ./market" % PLUGIN_CLI))
        self.assertDecision("deny", self.bash("%s marketplace add ./market" % PLUGIN_CLI, cwd=self.tmp), "SKL02")


if __name__ == "__main__":
    unittest.main()
