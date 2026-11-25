"""Test helpers: run the hook as a subprocess with a throwaway HOME and data dir.

Fake secrets are assembled at run time so no token-shaped string sits in the
repository (and secret scanners don't flag the test files).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(ROOT, "plugins", "checkrein")
SCRIPTS = os.path.join(PLUGIN, "scripts")
GUARD = os.path.join(SCRIPTS, "guard.py")
sys.path.insert(0, SCRIPTS)


def fake(kind):
    """Token-shaped test values, built from pieces."""
    body = "Q7w9ErT2yU4iO6pA8sD1fG3hJ5kL0zX"
    if kind == "github":
        return "gh" + "p_" + body + "abcde"
    if kind == "aws-id":
        return "AK" + "IA" + "QW7ER9TY2UI4OP6A"
    if kind == "anthropic":
        return "sk-" + "ant-" + "api03-" + body + body
    if kind == "slack":
        return "xo" + "xb-" + "1234567890-" + body
    if kind == "private-key":
        return "-----BEGIN " + "RSA PRIVATE KEY-----"
    if kind == "url":
        return "postgres://app:" + "Zx9Qw7Er5Ty3" + "@db.internal:5432/app"
    if kind == "assigned":
        return 'api_key = "' + "Zx9Qw7Er5Ty3Ui1Op" + '"'
    raise KeyError(kind)


class HookCase(unittest.TestCase):
    """Base class: a temp HOME, data dir and project per test."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="checkrein-test-")
        self.home = os.path.join(self.tmp, "home")
        self.data = os.path.join(self.tmp, "data")
        self.project = os.path.join(self.tmp, "project")
        for d in (self.home, self.data, self.project):
            os.makedirs(d)
        self.env = {
            "HOME": self.home,
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "CLAUDE_PLUGIN_DATA": self.data,
            "CLAUDE_PROJECT_DIR": self.project,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def hook(self, mode, payload, extra_env=None, raw=None):
        env = dict(self.env)
        env.update(extra_env or {})
        data = raw if raw is not None else json.dumps(payload)
        res = subprocess.run([sys.executable, GUARD, mode], input=data, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stderr, "", res.stderr)
        return json.loads(res.stdout) if res.stdout.strip() else None

    def pre(self, tool, tool_input, mode="default", cwd=None, extra_env=None):
        out = self.hook("pre", {"tool_name": tool, "tool_input": tool_input, "cwd": cwd or self.project,
                                "permission_mode": mode, "session_id": "t"}, extra_env)
        if out is None:
            return "allow", ""
        spec = out["hookSpecificOutput"]
        return spec["permissionDecision"], spec["permissionDecisionReason"]

    def bash(self, command, **kw):
        return self.pre("Bash", {"command": command}, **kw)

    def assertDecision(self, expected, result, rule=None):
        decision, reason = result
        self.assertEqual(decision, expected, reason)
        if rule:
            self.assertIn("checkrein %s" % rule, reason)

    def write_config(self, data, where="user"):
        path = os.path.join(self.data, "config.json") if where == "user" else \
            os.path.join(self.project, ".checkrein", "config.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            json.dump(data, fh)
        return path

    def git(self, *args, cwd=None):
        return subprocess.run(["git"] + list(args), cwd=cwd or self.project, env=self.env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)

    def init_repo(self, branch="master"):
        self.git("init", "-q", "-b", branch)
        self.git("commit", "-q", "--allow-empty", "-m", "first")
