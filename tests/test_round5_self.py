"""Round 5 review findings on checkrein's own protection: shell tools other than Bash, Python start-up files,
settings edits Claude Code applies loosely, symlinked settings, plugins enabled in settings, the config folder,
false denies on settings sources, MCP write verbs, slow secret patterns and the brace reason."""

import json
import os
import re
import subprocess
import sys
import time
import unittest

from helpers import GUARD, PLUGIN, fake
from test_gate_rules import CFGTOOL, SKILLGATE, GateCase, make_skill
from test_round2_rules import Base

HOOKS = os.path.join(PLUGIN, "hooks", "hooks.json")
PUSH = "git push --force origin " + "ma" + "in"
SWITCH = {"enabledPlugins": {"checkrein@checkrein": True}}


class SettingsCase(Base):
    def setUp(self):
        super(SettingsCase, self).setUp()
        self.claude = os.path.join(self.home, ".claude")
        os.makedirs(self.claude)
        self.settings = os.path.join(self.claude, "settings.json")
        self.put(self.settings, SWITCH)
        self.local = os.path.join(self.project, ".claude", "settings.local.json")
        os.makedirs(os.path.dirname(self.local))

    def put(self, path, data):
        with open(path, "w") as fh:
            fh.write(data if isinstance(data, str) else json.dumps(data, indent=2))

    def write(self, path, data, **kw):
        return self.pre("Write", {"file_path": path, "content": data if isinstance(data, str) else json.dumps(data)},
                        **kw)

    def edit(self, path, old, new):
        return self.pre("Edit", {"file_path": path, "old_string": old, "new_string": new})


class ShellTools(Base):
    """H1: any tool with a string command is a shell command."""

    def test_monitor_and_unknown_tools(self):
        for tool in ("Monitor", "SomeFutureTool"):
            self.assertDecision("deny", self.pre(tool, {"command": PUSH}), "GIT01")
        self.assertDecision("allow", self.pre("Monitor", {"command": "tail -f app.log"}))

    def test_matcher_covers_every_tool(self):
        with open(HOOKS) as fh:
            hooks = json.load(fh)["hooks"]
        matcher = hooks["PreToolUse"][0]["matcher"]
        for tool in ("Bash", "Monitor", "SomeFutureTool", "Write", "mcp__x__y"):
            self.assertTrue(matcher in ("*", "") or re.fullmatch(matcher, tool), tool)


class PythonStartup(SettingsCase):
    """H2: .pth, usercustomize and sitecustomize files, and PYTHONPATH from settings."""

    def test_hooks_run_isolated(self):
        with open(HOOKS) as fh:
            hooks = json.load(fh)["hooks"]
        for event in hooks.values():
            for entry in event:
                for hook in entry["hooks"]:
                    self.assertIn("python3 -I -S ", hook["command"])

    def test_isolated_guard_ignores_startup_files(self):
        planted = os.path.join(self.tmp, "planted")
        os.makedirs(planted)
        for name in ("sitecustomize.py", "usercustomize.py"):
            with open(os.path.join(planted, name), "w") as fh:
                fh.write("import os\nos._exit(0)\n")
        with open(os.path.join(planted, "zz.pth"), "w") as fh:
            fh.write("import os; os._exit(0)\n")
        env = dict(self.env, PYTHONPATH=planted, PYTHONSTARTUP=os.path.join(planted, "sitecustomize.py"))
        payload = {"tool_name": "Bash", "tool_input": {"command": PUSH}, "cwd": self.project,
                   "permission_mode": "default"}
        res = subprocess.run([sys.executable, "-I", "-S", GUARD, "pre"], input=json.dumps(payload), env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
        self.assertEqual(res.stderr, "")
        self.assertEqual(json.loads(res.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_startup_file_writes(self):
        for path in (os.path.join(self.home, "Library/Python/3.15/lib/python/site-packages/zz.pth"),
                     os.path.join(self.home, ".local/lib/python3.12/site-packages/zz.pth"),
                     os.path.join(self.home, ".local/lib/python3.12/site-packages/usercustomize.py"),
                     os.path.join(self.project, "lib/sitecustomize.py")):
            self.assertDecision("deny", self.write(path, "import os; os._exit(0)\n"), "SLF01")
        self.assertDecision("deny", self.bash("printf 'import os' > ~/.local/lib/python3.12/site-packages/a.pth"),
                            "SLF01")
        self.assertDecision("allow", self.write(os.path.join(self.project, "venv/lib/python3.12/site-packages/m.py"),
                                                "x = 1\n"))

    def test_settings_env(self):
        for key in ("PYTHONPATH", "PYTHONSTARTUP", "PATH", "HOME", "CLAUDE_CONFIG_DIR"):
            data = dict(SWITCH, env={key: "/tmp/x"})
            self.assertDecision("deny", self.write(self.settings, data), "SLF01")
            self.assertDecision("deny", self.write(self.local, {"env": {key: "/tmp/x"}}), "SLF01")
        self.assertDecision("allow", self.write(self.settings, dict(SWITCH, env={"FOO": "1"})))


class LooseEdits(SettingsCase):
    """H3 and H4: an empty old_string creates the file; quotes and line endings Claude Code matches loosely."""

    def test_empty_old_string(self):
        self.assertDecision("deny", self.edit(self.local, "", '{"disableAllHooks": true}'), "SLF01")
        self.put(self.local, "")
        self.assertDecision("deny", self.edit(self.local, "", '{"disableAllHooks": true}'), "SLF01")

    def test_curly_quotes(self):
        old = "“checkrein@checkrein”: true"
        new = "“checkrein@checkrein”: false"
        self.assertDecision("deny", self.edit(self.settings, old, new), "SLF01")

    def test_crlf(self):
        self.put(self.settings, json.dumps(SWITCH, indent=2).replace("\n", "\r\n"))
        old = '{\n  "enabledPlugins": {\n    "checkrein@checkrein": true'
        self.assertDecision("deny", self.edit(self.settings, old, old.replace("true", "false")), "SLF01")

    def test_unmatched_edit_on_plain_settings_asks(self):
        self.put(self.local, '{"theme": "dark"}')
        self.assertDecision("ask", self.edit(self.local, '"theme": "light"', '"theme": "x"'), "SLF01")


class SymlinkedSettings(SettingsCase):
    """H5: a settings file that is a symlink protects its target."""

    def setUp(self):
        super(SymlinkedSettings, self).setUp()
        self.real = os.path.join(self.home, "dotfiles", "claude", "settings.json")
        os.makedirs(os.path.dirname(self.real))
        os.rename(self.settings, self.real)
        os.symlink(self.real, self.settings)

    def test_target_is_protected(self):
        self.assertDecision("deny", self.write(self.real, "{}"), "SLF01")
        self.assertDecision("deny", self.edit(self.real, "true", "false"), "SLF01")
        for command in ("sed -i '' s/true/false/ %s" % self.real, "printf '{}' > %s" % self.real,
                        "rm %s" % self.real):
            self.assertDecision("deny", self.bash(command), "SLF01")


class PluginsInSettings(SettingsCase):
    """M2: enabling a plugin or adding a marketplace in settings goes through the ledger."""

    def _ledger(self):
        with open(os.path.join(self.data, "ledger.json"), "w") as fh:
            json.dump({"version": 1, "entries": {"plugin:foo@good": {
                "kind": "plugin", "name": "foo", "marketplace": "good", "sources": ["github.com/a/foo"],
                "tree_hash": "x"}}}, fh)

    def test_new_plugin(self):
        self._ledger()
        data = {"enabledPlugins": {"checkrein@checkrein": True, "evil@evilmkt": True}}
        self.assertHit(self.write(self.settings, data), "SKL02")
        self.assertHit(self.write(self.local, {"enabledPlugins": {"evil@evilmkt": True}}), "SKL02")
        data = {"enabledPlugins": {"checkrein@checkrein": True, "foo@good": True}}
        self.assertDecision("allow", self.write(self.settings, data))
        data = {"enabledPlugins": {"checkrein@checkrein": True, "evil@evilmkt": False}}
        self.assertDecision("allow", self.write(self.settings, data))

    def test_marketplaces(self):
        data = dict(SWITCH, extraKnownMarketplaces={"evilmkt": {"source": {"source": "github", "repo": "e/m"}}})
        self.assertHit(self.write(self.settings, data), "SKL02")
        self.assertHit(self.write(self.local, {"extraKnownMarketplaces": {"evilmkt": {}}}), "SKL02")


class ConfigDir(SettingsCase):
    """M3: CLAUDE_CONFIG_DIR moves the settings and .claude.json."""

    def test_config_dir(self):
        cfgdir = os.path.join(self.tmp, "cfgdir")
        os.makedirs(cfgdir)
        self.put(os.path.join(cfgdir, "settings.json"), SWITCH)
        env = {"CLAUDE_CONFIG_DIR": cfgdir}
        self.assertDecision("deny", self.write(os.path.join(cfgdir, "settings.json"), {"disableAllHooks": True},
                                               extra_env=env), "SLF01")
        self.assertDecision("deny", self.bash("rm %s/settings.json" % cfgdir, extra_env=env), "SLF01")
        self.assertDecision("deny", self.write(os.path.join(cfgdir, ".claude.json"), {"disableAllHooks": True},
                                               extra_env=env), "SLF01")
        # Files poured into the folder above it, and an editor run inside it.
        decision, reason = self.bash("tar -xzf a.tgz -C %s" % self.tmp, extra_env=env)
        self.assertIn(decision, ("ask", "deny"), reason)
        decision, reason = self.bash("cd %s && vim settings.json" % cfgdir, extra_env=env)
        self.assertIn(decision, ("ask", "deny"), reason)


class SettingsAsSource(SettingsCase):
    """M4: commands that only read a settings file, or name another one."""

    def test_reads_allowed(self):
        self.put(os.path.join(self.project, ".claude", "settings.json"), {"theme": "dark"})
        for command in ("git add .claude/settings.json", "git commit .claude/settings.json -m x",
                        "git restore --staged .claude/settings.json", "git diff .claude/settings.json",
                        "cp .claude/settings.json %s/x.json" % self.tmp, "cp ~/.claude/settings.json ~/settings.bak",
                        "scp .claude/settings.json host:/tmp/", "tar -czf b.tgz .claude/settings.json",
                        "rsync -a .claude/settings.json backup/"):
            self.allow(command)

    def test_scripts_name_the_right_file(self):
        self.put(os.path.join(self.home, ".claude", "settings.json"), SWITCH)
        self.allow("python3 -m json.tool ~/.claude/settings.json")
        decision, reason = self.bash("""node -e 'console.log(require("./.claude/settings.json"))'""")
        self.assertNotEqual(decision, "deny", reason)
        self.assertNotIn("~/.claude/settings.json", reason)
        self.assertDecision("deny", self.bash(
            """node -e 'require("fs").writeFileSync(require("os").homedir() + "/.claude/settings.json", "{}")'"""),
            "SLF01")
        self.assertDecision("deny", self.bash("python3 -m json.tool x.json ~/.claude/settings.json"), "SLF01")

    def test_moves_name_the_file(self):
        self.put(os.path.join(self.project, ".claude", "settings.json"), {"theme": "dark"})
        decision, reason = self.bash("git mv .claude/settings.json old.json")
        self.assertEqual(decision, "ask", reason)
        self.assertNotIn("~/.claude/settings.json", reason)
        self.assertDecision("deny", self.bash("cp %s/x.json ~/.claude/settings.json" % self.tmp), "SLF01")


class McpWriteVerbs(Base):
    """M5: write verbs anywhere in the tool name."""

    def test_verbs(self):
        self.write_config({"preset": "strict"})
        for tool in ("mcp__slack__slack_send_message", "mcp__slack__chat_postMessage",
                     "mcp__notion__notion-create-pages", "mcp__gmail__gmail_create_draft",
                     "mcp__jira__jira_transition_issue", "mcp__linear__issue_create", "mcp__x__batch"):
            self.assertDecision("ask", self.pre(tool, {"t": "x"}), "MCP01")
        for tool in ("mcp__slack__get_settings", "mcp__x__list_links", "mcp__jira__search_issues"):
            self.assertDecision("allow", self.pre(tool, {"t": "x"}))


class SlowSecrets(Base):
    """L1: long runs that almost look like tokens are scanned in linear time."""

    def test_long_runs(self):
        for word in ("sk-", "eyJ-"):
            command = ("echo " + word * (255 * 1024 // len(word)))[:255 * 1024]
            start = time.time()
            self.bash(command)
            self.assertLess(time.time() - start, 1.5, word)

    def test_mcp_payload(self):
        self.write_config({"preset": "strict"})
        start = time.time()
        decision, _reason = self.pre("mcp__tracker__create_issue", {"body": "eyJ-" * (64 * 1024)})
        self.assertLess(time.time() - start, 1.5)
        self.assertEqual(decision, "ask")

    def test_tokens_still_found(self):
        jwt = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + "." + "Q7w9ErT2yU4iO6pA8sD1fG3h"
        self.assertDecision("deny", self.bash("curl -H 'Authorization: Bearer %s' x" % jwt), "SEC02")
        self.assertDecision("deny", self.bash("echo %s" % fake("anthropic")), "SEC02")
        decision, reason = self.pre("mcp__tracker__create_issue", {"body": "a " * 450 + fake("github")})
        self.assertDecision("deny", (decision, reason), "MCP02")


class BraceReason(Base):
    """L2: a word with too many {a,b} expansions says so."""

    def test_reason(self):
        decision, reason = self.bash("rm -rf " + "{a,b}" * 10 + "/x")
        self.assertIn(decision, ("ask", "deny"))
        self.assertIn("too many expansions", reason)


if __name__ == "__main__":
    unittest.main()


class ConfigDirTools(GateCase):
    """M3 leftovers: skillgate installs and cfgtool's detect follow CLAUDE_CONFIG_DIR."""

    def test_install_and_detect(self):
        cfgdir = os.path.join(self.tmp, "cfgdir")
        os.makedirs(cfgdir)
        with open(os.path.join(cfgdir, ".claude.json"), "w") as fh:
            json.dump({"mcpServers": {"tracker": {"command": "x"}}}, fh)
        self.env["CLAUDE_CONFIG_DIR"] = cfgdir
        src = make_skill(self.tmp, "greeter")
        report = json.loads(self.tool(SKILLGATE, "vet", src, "--json"))
        self.tool(SKILLGATE, "approve", report["id"], "--override")
        self.assertTrue(os.path.isfile(os.path.join(cfgdir, "skills", "greeter", "SKILL.md")))
        self.assertFalse(os.path.exists(os.path.join(self.home, ".claude", "skills", "greeter")))
        detected = json.loads(self.tool(CFGTOOL, "detect", "--json"))
        self.assertIn("tracker", detected["facts"]["mcp_servers"])
