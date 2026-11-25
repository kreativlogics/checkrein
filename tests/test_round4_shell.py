"""Round-4 shell reader fixes: speed limits, variables, the environment, text run by git and launchers, wrappers."""

import os
import time
import unittest

from helpers import HookCase

from checkrein import context, shell

PUSH = "git push --force origin master"
QPUSH = "'%s'" % PUSH


class Base(HookCase):
    def setUp(self):
        super(Base, self).setUp()
        # The data dir where Claude Code puts it, so SLF01 knows it as checkrein's own.
        self.data = os.path.join(self.home, ".claude", "plugins", "data", "checkrein-checkrein")
        os.makedirs(self.data)
        self.env["CLAUDE_PLUGIN_DATA"] = self.data

    def allow(self, command, **kw):
        self.assertDecision("allow", self.bash(command, **kw))

    def push_denied(self, command):
        self.assertDecision("deny", self.bash(command), "GIT01")

    def own_denied(self, command):
        self.assertDecision("deny", self.bash(command), "SLF01")

    def hooks_denied(self, command):
        self.assertDecision("deny", self.bash(command), "GIT04")

    def asks(self, command, text="cannot see what it runs"):
        decision, reason = self.bash(command)
        self.assertEqual(decision, "ask", command + " | " + reason)
        self.assertIn(text, reason)


def timed(command):
    start = time.time()
    result = shell.parse(command, cwd="/p", home="/h")
    return result, time.time() - start


class Speed(unittest.TestCase):
    """R6: every command up to the size limit is read or refused quickly."""

    def test_many_folders(self):
        for unit in ("cd a && ", "cd a; ", "cd a | ", "pushd a; ", "f() { cd a; }; ", "cd a && cd .. && "):
            command = (unit * (256 * 1024 // len(unit)))[:256 * 1024 - 40] + PUSH
            _result, seconds = timed(command)
            self.assertLess(seconds, 1.5, unit)

    def test_many_words_and_variables(self):
        for unit in ("echo a ", "echo a; ", "A=b; ", "A=b; echo $A; ", "export A=1; ", "a | ", "sudo "):
            command = (unit * (256 * 1024 // len(unit)))[:256 * 1024 - 40] + PUSH
            _result, seconds = timed(command)
            self.assertLess(seconds, 1.5, unit)

    def test_folder_candidates_are_capped(self):
        cmd = shell.parse("cd a; " * 100 + "ls", cwd="/p").cmds[-1]
        self.assertLessEqual(len(cmd.cwds), shell.MAX_DIRS)
        self.assertTrue(cmd.cwd_unknown)

    def test_step_budget_denies(self):
        result = shell.parse("cd a; " * 40000 + "ls", cwd="/p")
        self.assertEqual(result.problem_level, "deny")
        self.assertIn("more words, folders or variables", result.problem)

    def test_wrapper_chain_asks(self):
        result = shell.parse("sudo " * 40 + PUSH)
        self.assertEqual(result.problem_level, "ask")


class Variables(Base):
    """R9: literal NAME=value assignments earlier in the line resolve $NAME and ${NAME}."""

    def test_literal_values_resolve(self):
        self.own_denied("DIR=%s; rm -f $DIR/config.json" % self.data)
        self.own_denied("DIR=%s; rm -f \"${DIR}/config.json\"" % self.data)
        self.own_denied("A=%s; B=$A; rm -f $B/config.json" % self.data)
        self.push_denied("G=git; $G push --force origin master")
        self.assertEqual(shell.parse("DIR=/x; DIR=/z; rm $DIR/y").cmds[-1].argv[-1], "/z/y")
        argv = shell.parse("DIR=~/.claude; rm -f $DIR/settings.json").cmds[-1].argv
        self.assertEqual(argv[-1], "~/.claude/settings.json")

    def test_program_name_built_at_run_time_asks(self):
        self.asks("set -- %s; \"$@\"" % PUSH)
        self.asks("read -r a <<< git; $a push --force origin master")
        self.asks("cmd=(git push); \"${cmd[@]}\" --force origin master")


class Environment(Base):
    """R10: Cmd.inherited_env holds what the variables assigned or exported earlier in the line and a parent shell
    pass on; Cmd.env holds the command's own prefix assignments, which override it."""

    def test_env_contract(self):
        cases = {
            "export HUSKY=0; git commit -m x": "0",
            "declare -x HUSKY=0; git commit -m x": "0",
            "typeset -x HUSKY=0; git commit -m x": "0",
            "HUSKY=0; export HUSKY; git commit -m x": "0",
            "set -a; HUSKY=0; git commit -m x": "0",
            "HUSKY=0 sh -c 'git commit -m x'": "0",
            "HUSKY=0 bash -c 'sh -c \"git commit -m x\"'": "0",
            "export HUSKY=0; bash -c 'git commit -m x'": "0",
            "HUSKY=0 find . -exec git commit -m x \\;": "0",
            "HUSKY=0 timeout 5 git commit -m x": "0",
        }
        for command, value in cases.items():
            git = [c for c in shell.parse(command).cmds if c.name == "git"]
            self.assertEqual([context.env_of(c).get("HUSKY") for c in git], [value], command)
        self.assertNotIn("HUSKY", context.env_of(shell.parse("(HUSKY=0); git commit").cmds[-1]))
        cmd = shell.parse("export A=1; B=2 git commit").cmds[-1]
        self.assertEqual((cmd.inherited_env, cmd.env), ({"A": "1"}, {"B": "2"}))

    def test_hooks_skipped_through_the_environment(self):
        for command in ("declare -x HUSKY=0; git commit -m x",
                        "HUSKY=0; export HUSKY; git commit -m x", "set -a; HUSKY=0; git commit -m x",
                        "HUSKY=0 sh -c 'git commit -m x'", "HUSKY=0 bash -c 'git commit -m x'"):
            self.hooks_denied(command)


class GitRuns(Base):
    """R11: shell text git runs from its config, environment and subcommands."""

    def test_literal_text_is_read(self):
        for command in ("git -c alias.x='!%s' x" % PUSH, "git -c alias.pf='push --force' pf origin master",
                        "git -c core.fsmonitor=%s status" % QPUSH, "git -c core.sshCommand=%s fetch" % QPUSH,
                        "git -c diff.external='%s;:' diff --ext-diff" % PUSH,
                        "git -c core.editor='%s;:' commit" % PUSH, "git -c core.pager=%s log" % QPUSH,
                        "git -c sequence.editor='%s;:' rebase -i HEAD~1" % PUSH,
                        "git -c credential.helper='!%s' fetch" % PUSH, "git -c Core.Pager=%s log" % QPUSH,
                        "GIT_SSH_COMMAND=%s git fetch" % QPUSH, "GIT_EDITOR='%s;:' git commit" % PUSH,
                        "GIT_SEQUENCE_EDITOR=%s git rebase -i x" % QPUSH, "GIT_PAGER=%s git log" % QPUSH,
                        "GIT_EXTERNAL_DIFF=%s git diff" % QPUSH, "export GIT_PAGER=%s; git log" % QPUSH,
                        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.pager GIT_CONFIG_VALUE_0=%s git log" % QPUSH,
                        "git rebase --exec %s HEAD~1" % QPUSH, "git rebase -x %s HEAD~1" % QPUSH,
                        "git rebase -ix %s HEAD~1" % QPUSH, "git rebase --exec=%s HEAD~1" % QPUSH,
                        "git bisect run sh -c %s" % QPUSH, "git submodule foreach %s" % QPUSH,
                        "git submodule foreach --recursive " + PUSH):
            self.push_denied(command)

    def test_text_built_at_run_time_asks(self):
        self.asks("git -c core.pager=\"$P\" log")
        self.asks("git -c alias.x=\"!$X\" x")
        self.asks("GIT_EDITOR=\"$E\" git commit")
        self.asks("git rebase --exec \"$C\" HEAD~1")


class Launchers(Base):
    """R11: commands started by trap, terminal multiplexers, schedulers and runners."""

    def test_literal_commands_are_read(self):
        for command in ("trap %s EXIT" % QPUSH, "trap -- %s EXIT; true" % QPUSH,
                        "tmux new -d %s" % QPUSH, "tmux new-session -s x -d %s" % QPUSH,
                        "tmux send-keys -t x %s Enter" % QPUSH, "tmux -c %s" % QPUSH,
                        "screen -dm " + PUSH, "screen -dmS name " + PUSH, "screen -X stuff %s" % QPUSH,
                        "dtach -n /tmp/s " + PUSH, "expect -c 'spawn %s'" % PUSH,
                        "at now <<< %s" % QPUSH, "echo %s | batch" % QPUSH,
                        "echo '* * * * * %s' | crontab -" % PUSH, "launchctl submit -l x -- " + PUSH,
                        "direnv exec . " + PUSH, "npm exec -c %s" % QPUSH, "npx -c %s" % QPUSH,
                        "yarn exec %s" % QPUSH, "just --shell sh -c %s" % QPUSH, "just -c " + PUSH,
                        "make -f /dev/stdin <<< $'x:\\n\\t%s'" % PUSH, "uv run " + PUSH,
                        "uv run --with x " + PUSH, "poetry run " + PUSH, "bundle exec " + PUSH,
                        "PS4='$(%s)' bash -xc true" % PUSH, "x='$(%s)'; : ${x@P}" % PUSH,
                        "PROMPT_COMMAND=%s" % QPUSH):
            self.push_denied(command)

    def test_unread_sources_ask(self):
        self.asks("crontab /tmp/jobs")
        self.asks("cat jobs | crontab -")
        self.asks("at -f /tmp/job now")
        self.asks("trap \"$X\" EXIT")
        self.asks("cat Makefile | make -f -")


class WrapperOptions(Base):
    """The berth review: option clusters, env -S and unclosed quotes."""

    def test_clusters(self):
        self.push_denied("env -iS %s" % QPUSH)
        self.push_denied("sudo -Hu me " + PUSH)
        self.push_denied("xargs -0I {} " + PUSH)
        self.push_denied("watch -tn 5 " + PUSH)

    def test_env_split_string(self):
        self.push_denied("env -S \"sh -c '%s'\"" % PUSH)
        self.push_denied("env -S 'git\\_push\\_--force origin master'")
        self.assertEqual(shell._env_split("echo\\_a\\_b"), ["echo", "a", "b"])
        self.assertEqual(shell._env_split('echo "a\\_b"'), ["echo", "a b"])
        self.assertEqual(shell._env_split("a b\\c c d"), ["a", "b"])
        self.assertIsNone(shell._env_split("echo ${HOME}"))
        self.assertIsNone(shell._env_split("echo 'a"))
        self.assertIsNone(shell._env_split("echo \\q"))

    def test_env_split_string_that_cannot_be_split_asks(self):
        self.asks("env -S \"sh -c 'git push -f origin master\"", "never closed")
        self.asks("env -S 'git ${X} push'")
        self.asks("env -S 'git \\q push'")

    def test_unclosed_quote_asks(self):
        self.asks("sh -c \"echo 'unclosed; %s\"" % PUSH, "never closed")
        self.asks("echo 'unclosed", "never closed")


if __name__ == "__main__":
    unittest.main()
