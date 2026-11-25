"""Round 7: deeply nested hook input, MCP tools whose command field is an object, and `claude plugin enable`."""

import json
import os

from helpers import fake
from test_round2_rules import PLUGIN_CLI, PLUGINS_CLI, InstalledDataDir


def nested(value, depth):
    """value wrapped in depth arrays, as JSON text built without recursion."""
    return "[" * depth + json.dumps(value) + "]" * depth


class DeepInput(InstalledDataDir):
    """H2: input nested past what json.loads can parse must come back as a JSON deny, never a crash. hook()
    asserts exit code 0 and an empty stderr."""

    def raw_pre(self, tool, tool_input_text):
        raw = '{"tool_name": %s, "cwd": %s, "permission_mode": "default", "session_id": "t", "tool_input": %s}' % (
            json.dumps(tool), json.dumps(self.project), tool_input_text)
        out = self.hook("pre", None, raw=raw)
        if out is None:
            return "allow", ""
        spec = out["hookSpecificOutput"]
        return spec["permissionDecision"], spec["permissionDecisionReason"]

    def test_deep_bash_input(self):
        for depth in (1200, 20000):
            text = '{"command": "git push -f origin master", "extra": %s}' % nested("x", depth)
            self.assertDecision("deny", self.raw_pre("Bash", text))

    def test_deep_mcp_input(self):
        token = fake("github")
        for depth in (1200, 20000):
            text = '{"channel": "c", "text": %s}' % nested(token, depth)
            self.assertDecision("deny", self.raw_pre("mcp__x__send_message", text))

    def test_brackets_in_strings_do_not_count(self):
        self.assertDecision("allow", self.bash("echo '%s'" % ("[" * 500)))

    def test_ordinary_nesting_passes(self):
        self.assertDecision("allow", self.raw_pre("mcp__x__read", '{"q": %s}' % nested("x", 50)))


class ObjectCommand(InstalledDataDir):
    """L3: an MCP tool whose command field is an object is not a shell, and is judged as itself."""

    def test_object_command_is_judged_as_mcp(self):
        self.assertDecision("allow", self.pre("mcp__vscode__run", {"command": {"id": "x"}}))
        self.assertDecision("allow", self.pre("mcp__vscode__run", {"command": {"id": "x", "args": ["a"]}}))

    def test_shell_shapes_still_checked(self):
        self.assertDecision("deny", self.pre("Bash", {"command": {"id": "x"}}))
        self.assertDecision("deny", self.pre("mcp__x__run", {"command": ["git", 3]}))
        self.assertDecision("deny", self.pre("mcp__x__run", {"command": ["git", "push", "-f", "origin", "master"]}))


class PluginEnable(InstalledDataDir):
    """L1: `claude plugin enable` turns a plugin on, so it needs the install ledger's approval like settings do."""

    def _ledger(self):
        with open(os.path.join(self.data, "ledger.json"), "w") as fh:
            json.dump({"version": 1, "entries": {"plugin:foo@good": {
                "kind": "plugin", "name": "foo", "marketplace": "good", "sources": ["github.com/a/foo"],
                "tree_hash": "x"}}}, fh)

    def test_enable_needs_the_gate(self):
        self._ledger()
        for cmd in ("%s enable evil@mkt" % PLUGIN_CLI, "%s enable --scope project evil@mkt" % PLUGINS_CLI,
                    "%s enable -s local evil@mkt" % PLUGIN_CLI, "%s enable evil" % PLUGIN_CLI,
                    "%s enable checkrein@elsewhere" % PLUGIN_CLI, "%s enable --all" % PLUGIN_CLI,
                    "npx @anthropic-ai/claude-code plugin enable evil@mkt"):
            self.assertDecision("deny", self.bash(cmd), "SKL02")

    def test_approved_and_checkrein_pass(self):
        self._ledger()
        for cmd in ("%s enable foo@good" % PLUGIN_CLI, "%s enable --scope project foo@good" % PLUGINS_CLI,
                    "%s enable checkrein@checkrein" % PLUGIN_CLI, "%s enable checkrein" % PLUGINS_CLI):
            self.assertDecision("allow", self.bash(cmd))

    def test_settings_write_matches(self):
        self._ledger()
        path = os.path.join(self.project, ".claude", "settings.json")
        for key, expected in (("evil@mkt", "deny"), ("checkrein@elsewhere", "deny"), ("foo@good", "allow"),
                              ("checkrein@checkrein", "allow")):
            content = json.dumps({"enabledPlugins": {key: True}})
            self.assertDecision(expected, self.pre("Write", {"file_path": path, "content": content}))
