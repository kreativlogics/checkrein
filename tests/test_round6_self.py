"""Round 6 review findings on checkrein's own protection: recursive and find-driven writers on a folder above a
protected file, chmod's dash modes, git -C and hg --cwd clones, SEC03 on committed paths and -diff files, and
copies of many sources."""

import json
import os
import time
import unittest

from helpers import fake
from test_round2_rules import Base

SWITCH = {"enabledPlugins": {"checkrein@checkrein": True}}
# Built here so no command line in this file names the hooks folder outright.
HOOKS = ".git" + os.sep + "hooks"


class Case(Base):
    def setUp(self):
        super(Case, self).setUp()
        self.claude = os.path.join(self.home, ".claude")
        os.makedirs(self.claude)
        self.put(os.path.join(self.claude, "settings.json"), SWITCH)

    def put(self, path, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(data if isinstance(data, str) else json.dumps(data))

    def hit(self, command, rule=None, **kw):
        decision, reason = self.bash(command, **kw)
        self.assertIn(decision, ("ask", "deny"), command)
        if rule:
            self.assertIn("checkrein %s" % rule, reason)


class RecursiveWriters(Case):
    """A: find, -r/-R writers and removing archivers run on a folder above a protected file."""

    def test_settings_from_above(self):
        h = self.home
        for command in ("find %s/.claude -name settings.json -delete" % h,
                        "find %s/.claude -name settings.json -exec rm {} +" % h,
                        "find %s/.claude -name settings.json -exec rm {} \\;" % h,
                        "find %s/.claude -name settings.json -exec sed -i '' s/true/false/ {} +" % h,
                        "find %s/.claude -maxdepth 1 -type f -delete" % h,
                        "chmod -R 000 %s/.claude" % h):
            self.hit(command, "SLF01")
        for command in ("find . -name settings.json -delete", "gzip -r .claude", "chown -R nobody .claude",
                        "find . -iname 'SETTINGS.*' -delete"):
            self.hit(command, "SLF01", cwd=self.home)

    def test_own_folders_from_above(self):
        self.write_config({"preset": "standard"})
        self.hit("find %s -name ledger.json -delete" % self.tmp, "SLF01")
        for command in ("gzip -r data", "tar --remove-files -cf %s/x.tar data" % self.tmp,
                        "zip -rm %s/x.zip data" % self.tmp, "find data -delete", "chmod -R 000 data",
                        "fd . data -x rm"):
            self.hit(command, "SLF01", cwd=self.tmp)

    def test_project_settings(self):
        self.put(os.path.join(self.project, ".claude", "settings.json"), {"theme": "dark"})
        self.hit("find . -name '*.json' -delete")
        self.hit("find . -type f -exec sed -i '' s/a/b/ {} +")
        self.allow("find . -name '*.pyc' -delete")
        self.allow("find . -name '*.json' -exec grep -l x {} +")

    def test_everyday_commands_pass(self):
        for name in ("node_modules", "dist", "build", "logs"):
            self.put(os.path.join(self.project, name, "a.txt"), "x")
        for command in ("rm -rf node_modules dist", "find . -name '*.pyc' -delete", "chmod -R u+w build",
                        "gzip -r logs", "find . -type f -exec sed -i '' s/a/b/ {} +", "chmod -r notes.txt",
                        "find . -name '*.log' -exec rm {} +", "tar --remove-files -cf logs.tar logs"):
            self.allow(command)


class ChmodModes(Case):
    """B: a mode written with a dash is the mode, not an option, so the file after it is still read."""

    def test_dash_modes(self):
        self.init_repo()
        hook = os.path.join(HOOKS, "pre-commit")
        self.put(os.path.join(self.project, hook), "#!/bin/sh\n")
        for command in ("chmod -x %s" % hook, "chmod -R -x %s" % HOOKS, "chmod a-x,go-w %s" % hook,
                        "chmod -w %s/.claude/settings.json" % self.home):
            self.hit(command)


class GitFolders(Case):
    """C: git -C (every one, in order) and hg --cwd move where a clone lands."""

    def test_clone_destinations(self):
        h = self.home
        os.makedirs(os.path.join(self.claude, "skills"))
        os.makedirs(os.path.join(self.project, ".claude", "skills"))
        for command in ("git -C %s/.claude/skills clone https://example.invalid/x.git" % h,
                        "git -C .claude/skills clone https://example.invalid/x.git",
                        "git -C %s/.claude clone https://example.invalid/x.git skills/evil" % h,
                        "git -C %s -C .claude/skills clone https://example.invalid/x.git" % h,
                        "git -C %s/.claude -C skills/foo pull" % h,
                        "hg --cwd %s/.claude/skills clone https://example.invalid/x" % h,
                        "hg -R %s/.claude/skills/foo pull -u" % h):
            self.hit(command, "SKL01")
        self.allow("git -C %s clone https://example.invalid/x.git" % self.tmp)
        self.allow("hg --cwd %s clone https://example.invalid/x" % self.tmp)

    def test_exec_into_user_skills(self):
        self.put(os.path.join(self.claude, "skills", "foo", "SKILL.md"), "x")
        self.hit("find %s/.claude/skills -name '*.md' -exec sed -i '' s/a/b/ {} +" % self.home, "SKL01")
        self.allow("find %s/.claude/skills -name '*.md' -exec grep -l a {} +" % self.home)


class CommittedPaths(Case):
    """D: git commit <paths> commits the working tree's copy; -diff files are scanned as text."""

    def setUp(self):
        super(CommittedPaths, self).setUp()
        self.init_repo()
        self.write_config({"rules": {"SEC03": "deny"}, "secret_scanner": "builtin"})
        self.put(os.path.join(self.project, "app.env"), "A=1\n")
        self.git("add", "app.env")
        self.git("commit", "-q", "-m", "a")

    def test_unstaged_paths(self):
        with open(os.path.join(self.project, "app.env"), "a") as fh:
            fh.write("KEY=%s\n" % fake("github"))
        self.assertDecision("allow", self.bash("git commit -m x"))
        for command in ("git commit -m x app.env", "git commit -m x -- app.env", "git commit -i -m x app.env",
                        "git commit --only -m x app.env", "git commit -o -m x"):
            self.assertDecision("deny", self.bash(command), "SEC03")
        self.assertDecision("allow", self.bash("git commit -m x other.txt"))

    def test_diff_attribute(self):
        self.put(os.path.join(self.project, ".gitattributes"), "*.env -diff\n*.bin binary\n")
        with open(os.path.join(self.project, "app.env"), "a") as fh:
            fh.write("KEY=%s\n" % fake("github"))
        self.git("add", ".gitattributes", "app.env")
        self.assertDecision("deny", self.bash("git commit -m x"), "SEC03")


class ManySources(Case):
    """E: copies of many sources into a folder above protected ones decide quickly."""

    def test_speed(self):
        sources = " ".join("s%d" % i for i in range(30000))
        for command in ("rsync -a %s ~/" % " ".join("s%d/" % i for i in range(30000)),
                        "cp %s ~/.claude/" % sources):
            start = time.time()
            self.bash(command[:200 * 1024])
            self.assertLess(time.time() - start, 2.5, command[:20])


if __name__ == "__main__":
    unittest.main()


class Round6b(Case):
    """Round 6b: judge recursive writers by what they can change, feed found paths from xargs, and git stash
    with untracked files."""

    def setUp(self):
        super(Round6b, self).setUp()
        self.put(os.path.join(self.project, ".claude", "settings.json"), {"theme": "dark"})
        self.put(os.path.join(self.project, ".checkrein", "config.json"), {"preset": "standard"})

    def test_harmless_recursive_writers_pass(self):
        for name in ("node_modules", "dist", "build", "logs"):
            self.put(os.path.join(self.project, name, "a.txt"), "x")
        os.makedirs(os.path.join(self.project, "empty", "inner"))
        for command in ("chmod -R u+w .", "chmod -R a+r,u+w .", "chmod -R +w .", "find . -type d -empty -delete",
                        "find . -type d -delete", "find . -exec chmod u+w {} +", "find . -name '*.pyc' -delete",
                        "rm -rf node_modules dist build", "gzip -r logs", "find . -name '*.pyc' | xargs rm",
                        "find . -name '*.js' | xargs sed -i '' s/a/b/", "find . -name '*.json' | xargs grep x"):
            self.allow(command)

    def test_removals_and_absolute_modes_count(self):
        for command in ("chmod -R 000 .", "chmod -R go-w .", "chmod -R a=r .", "find . -type f -delete",
                        "find . -type d -o -name '*.json' -delete"):
            self.hit(command, "SLF01")

    def test_xargs_children_of_find(self):
        h = self.home
        self.hit("find %s/.claude -name settings.json | xargs rm" % h, "SLF01")
        self.hit("find %s/.claude -name settings.json -print0 | xargs -0 rm -f" % h, "SLF01")
        self.hit("find . -name config.json | xargs rm", "SLF01")
        self.hit("ls .checkrein | xargs rm", "SLF01")
        # Only a file checkrein may write later matches, so a person confirms it rather than a deny.
        decision, reason = self.bash("find . -name ledger.json | xargs rm")
        self.assertEqual(decision, "ask", reason)

    def test_xargs_into_user_skills(self):
        skills = os.path.join(self.claude, "skills", "demo")
        self.put(os.path.join(skills, "SKILL.md"), "x")
        self.hit("find %s -name SKILL.md | xargs sed -i '' s/a/b/" % skills, "SKL01")
        self.allow("find %s -name SKILL.md | xargs grep x" % skills)

    def test_stash_with_untracked(self):
        self.init_repo()
        for command in ("git stash -u", "git stash push --include-untracked", "git stash -a", "git stash --all",
                        "git stash push -k -u"):
            self.hit(command, "GIT03")
        self.git("add", ".claude", ".checkrein")
        self.git("commit", "-q", "-m", "settings")
        self.allow("git stash -u")
        self.allow("git stash")
