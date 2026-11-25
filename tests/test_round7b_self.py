"""Round 7b: the hook's own Python (PATH entries, sys.executable, the standard library), nested `claude`
launches judged by a list of safe options and variables, and settings env and helper-command changes."""

import json
import os
import sys

from test_round2_rules import PLUGIN_CLI, InstalledDataDir

STDLIB = os.path.dirname(os.path.abspath(os.__file__))


class PythonOnPath(InstalledDataDir):
    """A PATH with a python3 in a temp folder and ~/.local/bin, which doesn't exist yet."""

    def setUp(self):
        super(PythonOnPath, self).setUp()
        self.local_bin = os.path.join(self.home, ".local", "bin")  # On PATH, not made yet.
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        os.symlink(os.path.realpath(sys.executable), os.path.join(self.bin, "python3"))
        self.env["PATH"] = os.pathsep.join((self.local_bin, self.bin, "/usr/bin", "/bin"))


class HookPython(PythonOnPath):
    """H1: the interpreter and standard library the hook runs with can't be swapped."""

    def test_interpreter_on_path(self):
        for command in ("ln -sf /usr/bin/true ~/.local/bin/python3", "ln -sf /usr/bin/true %s/python3" % self.bin,
                        "cp x %s/python3" % self.bin, "cp x %s/python3.12" % self.local_bin,
                        "chmod +x ~/.local/bin/python3", "rm %s/python3" % self.bin,
                        "mv %s/python3 /tmp/old" % self.bin, "printf x > %s/python" % self.bin,
                        "cp x %s" % os.path.realpath(sys.executable)):
            self.assertDecision("deny", self.bash(command), "SLF01")
        for path in (os.path.join(self.bin, "python3"), os.path.join(self.local_bin, "python3")):
            self.assertDecision("deny", self.pre("Write", {"file_path": path, "content": "x"}), "SLF01")

    def test_standard_library(self):
        for name in (os.path.join("encodings", "__init__.py"), os.path.join("json", "__init__.py"), "os.py"):
            path = os.path.join(STDLIB, name)
            self.assertDecision("deny", self.pre("Write", {"file_path": path, "content": "x"}), "SLF01")
            self.assertDecision("deny", self.pre("Edit", {"file_path": path, "old_string": "a", "new_string": "b"}),
                                "SLF01")
            self.assertDecision("deny", self.bash("printf x >> %s" % path), "SLF01")

    def test_python_installs_ask(self):
        for command in ("brew install python@3.13", "brew upgrade python3", "pyenv install 3.12.1",
                        "uv python install 3.12"):
            self.assertDecision("ask", self.bash(command), "SLF01")

    def test_venv_on_path(self):
        self.assertDecision("deny", self.bash("python3 -m venv %s" % os.path.join(self.home, ".local")), "SLF01")
        self.assertDecision("deny", self.bash("uv venv --python 3.12 %s" % os.path.join(self.home, ".local")),
                            "SLF01")

    def test_everyday_python_passes(self):
        for command in ("python3 -c 'print(1)'", "%s/python3 --version" % self.bin, "cat %s/os.py" % STDLIB,
                        "python3 -m venv .venv", "uv venv", "uv venv --python 3.12 env", "virtualenv venv",
                        ".venv/bin/pip install requests", "pip install -r requirements.txt", "brew install jq",
                        "brew upgrade", "ls %s" % self.bin, "cp x %s/mytool" % self.bin,
                        "cp x .venv/bin/python3"):
            self.assertDecision("allow", self.bash(command))


class NestedClaude(InstalledDataDir):
    """H3: a nested claude passes only with options known to keep its hooks, and no variable steering it."""

    def test_launches_that_ask(self):
        for command in ("claude --bare -p hi", "CLAUDE_CODE_SIMPLE=1 claude -p hi", "CLAUDE_CONFIG_DIR=/tmp/x claude",
                        "HOME=/tmp/x claude -p hi", "XDG_CONFIG_HOME=/tmp/x claude -p hi",
                        "env CLAUDE_CONFIG_DIR=/tmp/x claude -p hi", "export HOME=/tmp/x; claude -p hi",
                        "npx @anthropic-ai/claude-code --bare -p hi", "claude --plugin-dir /tmp/evil -p hi",
                        "claude --plugin-url https://example.invalid/p.zip -p hi", "claude --settings x.json -p hi",
                        "claude --setting-sources user -p hi", "claude --dangerously-skip-permissions -p hi",
                        "claude -p hi --permission-mode bypassPermissions", "claude -p --mcp-config x.json hi",
                        "claude -px hi"):
            self.assertDecision("ask", self.bash(command), "SLF01")

    def test_plain_launches_pass(self):
        for command in ("claude -p hi", "claude", "claude -p 'review --bare in this file'",
                        "claude -p hi --model opus --output-format json --max-turns 3",
                        "claude --append-system-prompt '--settings x' -p hi", "claude -c", "claude -r abc -p hi",
                        "claude --allowedTools Bash,Read --disallowedTools Write -p hi", "claude --version",
                        "claude -p hi --permission-mode plan", "claude --add-dir ../a ../b -p hi",
                        "claude mcp list", "claude config get model", "%s list" % PLUGIN_CLI,
                        "npx @anthropic-ai/claude-code -p hi", "MY_VAR=1 claude -p hi"):
            self.assertDecision("allow", self.bash(command))


class SettingsFile(InstalledDataDir):
    """A project settings file with an env block and a status line."""

    def setUp(self):
        super(SettingsFile, self).setUp()
        self.path = os.path.join(self.project, ".claude", "settings.json")
        os.makedirs(os.path.dirname(self.path))
        self.old = {"theme": "dark", "env": {"FOO": "1"}, "statusLine": {"type": "command", "command": "a.sh"}}
        with open(self.path, "w") as fh:
            json.dump(self.old, fh)

    def write(self, **changes):
        new = dict(self.old)
        new.update(changes)
        return self.pre("Write", {"file_path": self.path, "content": json.dumps(new)})


class SettingsEnvAndHelpers(SettingsFile):
    """M1: env names that steer hooks, git, shells or Python deny; other CLAUDE_* names and helper commands ask."""

    def test_env_names_that_deny(self):
        for name in ("GIT_DIR", "HUSKY", "HUSKY_SKIP_HOOKS", "SKIP", "LEFTHOOK", "PRE_COMMIT_ALLOW_NO_CONFIG",
                     "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "ENV", "ZDOTDIR", "SHELL", "XDG_CONFIG_HOME",
                     "PATH", "HOME", "PYTHONPATH", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_SHELL_PREFIX",
                     "CLAUDE_CODE_SIMPLE", "CLAUDE_PLUGIN_ROOT"):
            self.assertDecision("deny", self.write(env={"FOO": "1", name: "x"}), "SLF01")

    def test_other_claude_names_ask(self):
        self.assertDecision("ask", self.write(env={"FOO": "1", "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "8000"}), "SLF01")

    def test_ordinary_env_passes(self):
        self.assertDecision("allow", self.write(env={"FOO": "2", "NODE_OPTIONS": "--max-old-space-size=4096"}))

    def test_helpers_ask(self):
        self.assertDecision("ask", self.write(statusLine={"type": "command", "command": "b.sh"}), "SLF01")
        for key in ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"):
            self.assertDecision("ask", self.write(**{key: "/tmp/helper.sh"}), "SLF01")

    def test_edits_elsewhere_pass(self):
        self.assertDecision("allow", self.write(theme="light"))
        self.assertDecision("allow", self.pre("Edit", {"file_path": self.path, "old_string": '"dark"',
                                                       "new_string": '"light"'}))


class FinalBatch(PythonOnPath):
    """Round 7c: case on macOS, more env names and helper keys, more ways to start claude, fewer false asks."""

    def test_case_of_path_folders(self):
        if not os.path.exists(self.bin.upper()):
            self.skipTest("The file system here tells case apart.")
        self.assertDecision("deny", self.bash("cp x %s/python3" % self.bin.upper()), "SLF01")
        self.assertDecision("deny", self.bash("cp x %s/python3" % self.local_bin.replace(".local", ".LOCAL")),
                            "SLF01")

    def test_python_installs(self):
        for command in ("brew install python-tk", "brew install python-setuptools", "pyenv install --list",
                        "python3 -I -m venv .venv"):
            self.assertDecision("allow", self.bash(command))
        self.assertDecision("ask", self.bash("brew install python@3.13"), "SLF01")
        self.assertDecision("deny", self.bash("python3 -I -s -m venv %s" % os.path.join(self.home, ".local")),
                            "SLF01")

    def test_claude_launch_forms(self):
        for command in ("npm exec @anthropic-ai/claude-code -- --bare -p hi",
                        "~/.local/share/claude/versions/2.1.0 --bare -p hi",
                        "node /x/node_modules/@anthropic-ai/claude-code/cli.js --bare -p hi",
                        "claude --mcp-config x.json -p hi", "claude --agents x.json -p hi"):
            self.assertDecision("ask", self.bash(command), "SLF01")
        for command in ("npm exec @anthropic-ai/claude-code -- -p hi", "claude --effort high -p hi",
                        "claude --fallback-model sonnet --session-id abc -p hi", "claude -d --fork-session -c",
                        "claude --include-partial-messages --no-session-persistence --ide --chrome -p hi",
                        "claude --replay-user-messages -p hi", "%s enable --help" % PLUGIN_CLI):
            self.assertDecision("allow", self.bash(command))


class FinalSettings(SettingsFile):
    def test_more_env_names(self):
        for name in ("BASH_FUNC_ls%%", "__BASH_FUNC<ls>%%", "SHELLOPTS", "BASHOPTS", "PS4", "IFS", "GCONV_PATH",
                     "PROMPT_COMMAND", "LC_ALL"):
            self.assertDecision("deny", self.write(env={"FOO": "1", name: "x"}), "SLF01")

    def test_more_helper_keys(self):
        for key in ("fileSuggestion", "gcpAuthRefresh", "processWrapper", "policyHelpers", "proxyAuthHelper",
                    "subagentStatusLine"):
            self.assertDecision("ask", self.write(**{key: "/tmp/helper.sh"}), "SLF01")
