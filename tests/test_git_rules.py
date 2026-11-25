import os
import unittest

from helpers import HookCase


class ForcePush(HookCase):
    def test_force_to_protected_is_denied(self):
        self.assertDecision("deny", self.bash("git push --force origin main"), "GIT01")
        self.assertDecision("deny", self.bash("git push -f origin master"), "GIT01")
        self.assertDecision("deny", self.bash("git push origin +release/1.2"), "GIT01")

    def test_force_to_protected_denied_even_when_relaxed(self):
        self.write_config({"preset": "relaxed"})
        self.assertDecision("deny", self.bash("git push --force origin main"), "GIT01")

    def test_force_to_feature_branch_follows_level(self):
        self.assertDecision("deny", self.bash("git push --force origin feature/x"), "GIT01")
        self.write_config({"preset": "relaxed"})
        self.assertDecision("ask", self.bash("git push --force origin feature/x"), "GIT01")

    def test_lease_is_one_step_softer(self):
        self.assertDecision("ask", self.bash("git push --force-with-lease origin feature/x"), "GIT01")

    def test_current_branch_is_read_from_git(self):
        self.init_repo("main")
        self.assertDecision("deny", self.bash("git push -f"), "GIT01")
        self.git("checkout", "-q", "-b", "topic")
        self.assertDecision("deny", self.bash("git push -f"), "GIT01")  # standard: force push denied anywhere
        self.write_config({"preset": "relaxed"})
        self.assertDecision("ask", self.bash("git push -f"), "GIT01")

    def test_delete_and_mirror(self):
        self.assertDecision("deny", self.bash("git push origin --delete main"), "GIT01")
        self.assertDecision("deny", self.bash("git push origin :main"), "GIT01")
        self.assertDecision("deny", self.bash("git push --mirror backup"), "GIT01")

    def test_wrapped_and_chained(self):
        self.assertDecision("deny", self.bash("cd /tmp && git -C . push --force origin main"), "GIT01")
        self.assertDecision("deny", self.bash("bash -c 'git push -f origin main'"), "GIT01")
        self.assertDecision("deny", self.bash("echo $(git push -f origin main)"), "GIT01")
        self.assertDecision("deny", self.bash("timeout 30 git push origin +main"), "GIT01")

    def test_near_misses(self):
        self.assertDecision("allow", self.bash("git push origin feature/x"))
        self.assertDecision("allow", self.bash("git push -u origin feature/x"))
        self.assertDecision("allow", self.bash("echo 'git push --force origin main'"))
        self.assertDecision("allow", self.bash("git log --format='%h push -f'"))
        self.assertDecision("allow", self.bash("grep -r 'push --force' docs/"))

    def test_off_means_off(self):
        self.write_config({"rules": {"GIT01": "off"}})
        self.assertDecision("allow", self.bash("git push --force origin main"))

    def test_custom_protected_branch(self):
        self.write_config({"preset": "relaxed", "protected_branches": ["staging"]})
        self.assertDecision("deny", self.bash("git push -f origin staging"), "GIT01")


class DiscardWork(HookCase):
    def test_hard_reset_and_forced_checkout_ask(self):
        self.assertDecision("ask", self.bash("git reset --hard HEAD~1"), "GIT02")
        self.assertDecision("ask", self.bash("git checkout -f main"), "GIT02")
        self.assertDecision("ask", self.bash("git switch --discard-changes main"), "GIT02")

    def test_unattended_ask_becomes_deny(self):
        decision, reason = self.bash("git reset --hard", mode="bypassPermissions")
        self.assertEqual(decision, "deny")
        self.assertIn("No one can confirm", reason)
        self.assertDecision("deny", self.bash("git reset --hard", mode="dontAsk"), "GIT02")

    def test_clean(self):
        self.assertDecision("ask", self.bash("git clean -fd"), "GIT03")
        self.assertDecision("ask", self.bash("git clean --force"), "GIT03")
        self.assertDecision("allow", self.bash("git clean -nd"))
        self.assertDecision("allow", self.bash("git clean -fdn"))

    def test_near_misses(self):
        self.assertDecision("allow", self.bash("git reset --soft HEAD~1"))
        self.assertDecision("allow", self.bash("git checkout -b topic"))
        self.assertDecision("allow", self.bash("git switch main"))


class HookSkipping(HookCase):
    def test_no_verify(self):
        self.assertDecision("deny", self.bash("git commit --no-verify -m wip"), "GIT04")
        self.assertDecision("deny", self.bash("git push --no-verify origin topic"), "GIT04")
        self.assertDecision("deny", self.bash("git commit -nm wip"), "GIT04")
        self.assertDecision("deny", self.bash("git commit -an -m wip"), "GIT04")

    def test_env_switches(self):
        self.assertDecision("deny", self.bash("HUSKY=0 git commit -m wip"), "GIT04")
        self.assertDecision("deny", self.bash("SKIP=eslint git commit -m wip"), "GIT04")
        self.assertDecision("deny", self.bash("export HUSKY=0"), "GIT04")
        self.assertDecision("deny", self.bash("env HUSKY=0 git commit -m x"), "GIT04")

    def test_near_misses(self):
        self.assertDecision("allow", self.bash("git commit -m 'explain why we never use -n'"))
        self.assertDecision("allow", self.bash("git commit -m n"))
        self.assertDecision("allow", self.bash("HUSKY=1 git commit -m x"))
        self.assertDecision("allow", self.bash("git log -n 5"))

    def test_hooks_path(self):
        self.assertDecision("deny", self.bash("git config core.hooksPath /dev/null"), "GIT05")
        self.assertDecision("deny", self.bash("git -c core.hooksPath=/tmp/x commit -m y"), "GIT05")
        self.assertDecision("deny", self.bash("git config --unset core.hooksPath"), "GIT05")
        self.assertDecision("allow", self.bash("git config --get core.hooksPath"))
        self.assertDecision("allow", self.bash("git config core.hooksPath"))

    def test_hooks_dir_writes(self):
        self.assertDecision("deny", self.bash("echo 'exit 0' > .git/hooks/pre-commit"), "GIT05")
        self.assertDecision("deny", self.bash("rm .git/hooks/pre-push"), "GIT05")
        self.assertDecision("deny", self.bash("cp /tmp/x .git/hooks/pre-commit"), "GIT05")
        target = os.path.join(self.project, ".git", "hooks", "pre-commit")
        self.assertDecision("deny", self.pre("Write", {"file_path": target, "content": "exit 0\n"}), "GIT05")
        self.assertDecision("allow", self.bash("cat .git/hooks/pre-commit"))


class SharedTree(HookCase):
    def test_off_by_default(self):
        self.assertDecision("allow", self.bash("git stash"))
        self.assertDecision("allow", self.bash("git add -A"))

    def test_strict_asks(self):
        self.write_config({"preset": "strict"})
        self.assertDecision("ask", self.bash("git stash"), "GIT06")
        self.assertDecision("ask", self.bash("git stash push -m x"), "GIT06")
        self.assertDecision("ask", self.bash("git restore src/app.py"), "GIT06")
        self.assertDecision("ask", self.bash("git checkout -- src/app.py"), "GIT06")
        self.assertDecision("ask", self.bash("git add -A"), "GIT06")
        self.assertDecision("ask", self.bash("git add ."), "GIT06")
        self.assertDecision("ask", self.bash("git commit -am wip"), "GIT06")

    def test_strict_near_misses(self):
        self.write_config({"preset": "strict"})
        self.assertDecision("allow", self.bash("git stash list"))
        self.assertDecision("allow", self.bash("git restore --staged src/app.py"))
        self.assertDecision("allow", self.bash("git add src/app.py"))
        self.assertDecision("allow", self.bash("git commit -m 'add all'"))


if __name__ == "__main__":
    unittest.main()
