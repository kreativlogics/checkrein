"""Round-6 git rules: found and listed paths in .git/hooks, symlinks to the hooks folder or config, long git -C
chains, partial protected refs and removed include sections."""

import os
import time
import unittest

from helpers import HookCase

from checkrein import shell

# Built from pieces so the test file itself reads as plain text to the rules it tests.
HOOKS_KEY = "hooks" + "Path"
HOOKS_LINE = "[core]\n\t%s = /dev/null\n" % HOOKS_KEY


class Base(HookCase):
    def stopped(self, result, rule):
        decision, reason = result
        self.assertIn(decision, ("ask", "deny"), reason)
        self.assertIn("checkrein %s" % rule, reason)

    def denied(self, result, rule):
        self.assertDecision("deny", result, rule)

    def allowed(self, result):
        self.assertEqual(result[0], "allow", result[1])

    def write(self, path, content):
        return self.pre("Write", {"file_path": path, "content": content})

    def hooks(self):
        path = os.path.join(self.project, ".git", "hooks")
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "pre-commit"), "w") as fh:
            fh.write("#!/bin/sh\n")
        with open(os.path.join(self.project, ".git", "config"), "w") as fh:
            fh.write("[core]\n\tbare = false\n")
        return path


class FoundPaths(Base):
    """A2: find and xargs reach .git/hooks through roots, tests and listed words."""

    def setUp(self):
        super().setUp()
        self.hooks()

    def test_find_in_hooks(self):
        self.stopped(self.bash("find .git/hooks -name pre-commit -delete"), "GIT05")
        self.stopped(self.bash("find .git/hooks -type f -exec chmod -x {} +"), "GIT05")
        self.stopped(self.bash("find .git -path '*hooks/pre-commit' -delete"), "GIT05")
        self.stopped(self.bash("find .git -name config -exec rm {} +"), "GIT05")
        self.denied(self.bash("rm -rf .git/hooks"), "GIT05")

    def test_xargs_items(self):
        self.stopped(self.bash("echo .git/hooks/pre-commit | xargs rm"), "GIT05")
        self.stopped(self.bash("printf '%s\\n' .git/hooks/pre-commit | xargs chmod -x"), "GIT05")
        self.stopped(self.bash("printf '.git/hooks/pre-commit\\n' | xargs -I{} rm {}"), "GIT05")
        self.stopped(self.bash("find .git/hooks -type f | xargs rm"), "GIT05")

    def test_shell_attributes(self):
        found = shell.parse("find .git/hooks -name pre-commit -exec rm {} +", self.project, self.home).cmds
        rm = [c for c in found if c.name == "rm"][0]
        self.assertEqual(rm.found_roots, (".git/hooks",))
        self.assertEqual(rm.found_predicates, (("-name", "pre-commit"),))
        piped = shell.parse("find .git/hooks -type f | xargs rm", self.project, self.home).cmds
        rm = [c for c in piped if c.name == "rm"][0]
        self.assertEqual(rm.found_roots, (".git/hooks",))
        echoed = shell.parse("echo a b | xargs rm -f", self.project, self.home).cmds
        self.assertEqual([c.argv for c in echoed if c.name == "rm"], [["rm", "-f", "a", "b"]])

    def test_ordinary_finds_stay_allowed(self):
        for command in ("find . -name '*.pyc' -delete", "find . -name '*.log' | xargs rm -f",
                        "find src -name '*.orig' -exec rm {} \\;", "echo a.txt | xargs rm",
                        "find .git/hooks -type f", "find .git -name config"):
            self.allowed(self.bash(command))

    def test_writers_that_spare_hooks(self):
        self.init_repo()
        self.hooks()
        for command in ("chmod -R u+w .", "chmod -R +x .", "chmod -R 755 .", "find . -type d -empty -delete"):
            self.allowed(self.bash(command))
        for command in ("chmod -R -x .", "chmod -R 644 .", "chmod -R u=rw .", "find . -type d -exec rm -rf {} +",
                        "find . -type f -delete"):
            self.stopped(self.bash(command), "GIT05")


class Symlinks(Base):
    """F: a link to .git/hooks or .git/config reaches the same files."""

    def setUp(self):
        super().setUp()
        hooks = self.hooks()
        os.symlink(hooks, os.path.join(self.project, "gh"))
        os.symlink(os.path.join(self.project, ".git", "config"), os.path.join(self.project, "gc"))

    def test_through_hooks_link(self):
        self.stopped(self.write(os.path.join(self.project, "gh", "pre-commit"), "#!/bin/sh\nexit 0\n"), "GIT05")
        self.stopped(self.bash("cp /tmp/x gh/pre-commit"), "GIT05")
        self.stopped(self.bash("rm gh/pre-commit"), "GIT05")
        self.stopped(self.bash("chmod -x gh/pre-commit"), "GIT05")

    def test_through_config_link(self):
        self.stopped(self.write(os.path.join(self.project, "gc"), HOOKS_LINE), "GIT05")
        self.stopped(self.bash("echo x >> gc"), "GIT05")

    def test_making_links(self):
        self.stopped(self.bash("ln -s .git/hooks hk"), "GIT05")
        self.stopped(self.bash("ln -s .git/hooks/pre-commit pc"), "GIT05")
        self.stopped(self.bash("ln .git/config cfg"), "GIT05")
        self.allowed(self.bash("ln -s docs/readme.md readme"))


class LongChdirChain(Base):
    """E: thousands of git -C folders read in well under the guard's deadline."""

    def test_chain(self):
        command = ("git " + " ".join("-C d%d" % i for i in range(40000)))[:250 * 1024] + " status"
        start = time.time()
        shell.parse(command, self.project, self.home)
        self.assertLess(time.time() - start, 1.0)
        start = time.time()
        self.bash(command)
        self.assertLess(time.time() - start, 3.0)


class Minor(Base):
    def test_partial_protected_refs(self):
        self.denied(self.bash("git push --force-with-lease origin HEAD:heads/master"), "GIT01")
        self.denied(self.bash("git push --force-with-lease origin HEAD:refs/heads/master"), "GIT01")

    def test_remove_include_sections(self):
        self.stopped(self.bash("git config --remove-section include"), "GIT05")
        self.stopped(self.bash("git config --remove-section 'includeIf.gitdir:/x/'"), "GIT05")
        self.stopped(self.bash("git config --rename-section include other"), "GIT05")


if __name__ == "__main__":
    unittest.main()
