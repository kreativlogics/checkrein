"""Regression tests for review findings on the Bash-side rules (shell parsing, write targets, git, own tools)."""

import os
import subprocess
import sys
import unittest

from helpers import HookCase, SCRIPTS

CFGTOOL = os.path.join(SCRIPTS, "cfgtool.py")
SKILLGATE = os.path.join(SCRIPTS, "skillgate.py")


class Base(HookCase):
    def assertHit(self, result, rule):
        decision, reason = result
        self.assertIn(decision, ("ask", "deny"), reason)
        self.assertIn("checkrein %s" % rule, reason)

    def allow(self, command, **kw):
        self.assertDecision("allow", self.bash(command, **kw))

    @property
    def skills(self):
        return os.path.join(self.home, ".claude", "skills")


class OwnToolParsing(Base):
    """Finding 1: option abbreviations must not hide the real subcommand."""

    def test_abbreviated_options_are_treated_as_mutating(self):
        base = "python3 %s --data %s " % (CFGTOOL, self.data)
        self.assertDecision("ask", self.bash(base + "--project-d show set rules.SLF01 off"), "SLF01")
        self.assertDecision("ask", self.bash(base + "--proj show set rules.SLF01 off"), "SLF01")
        self.assertDecision("ask", self.bash("python3 %s --da %s show" % (CFGTOOL, self.data)), "SLF01")
        self.assertDecision("ask", self.bash("python3 %s --data=%s show" % (CFGTOOL, self.data)), "SLF01")
        self.assertDecision("ask", self.bash(base + "bogus"), "SLF01")
        self.assertDecision("deny", self.bash(base + "--project-d show set rules.SLF01 off", mode="dontAsk"),
                            "SLF01")

    def test_skillgate_abbreviation_is_a_gate_decision(self):
        cmd = "python3 %s --data %s --pro %s list approve abc" % (SKILLGATE, self.data, self.project)
        self.assertHit(self.bash(cmd), "SKL04")

    def test_plain_own_tool_reads_still_allowed(self):
        self.allow("python3 %s --data %s show" % (CFGTOOL, self.data))
        self.allow("python3 %s --data %s --project-dir %s show --json" % (CFGTOOL, self.data, self.project))
        self.allow("python3 %s --data %s list" % (SKILLGATE, self.data))
        self.allow("python3 %s --data %s --project %s audit" % (SKILLGATE, self.data, self.project))

    def test_cfgtool_rejects_abbreviations(self):
        res = subprocess.run([sys.executable, CFGTOOL, "--data", self.data, "--project-d", self.project, "show"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30,
                             env=self.env)
        self.assertNotEqual(res.returncode, 0)
        res = subprocess.run([sys.executable, CFGTOOL, "--data", self.data, "set", "rules.GIT06", "ask", "--proj"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30,
                             env=self.env)
        self.assertNotEqual(res.returncode, 0)


class QuotedHash(Base):
    """Finding 2: a quoted word starting with # is not a comment."""

    def test_quoted_hash_does_not_hide_the_rest(self):
        self.assertDecision("deny", self.bash('gh issue comment 12 -b "#12 fixed" && git push --force origin master'),
                            "GIT01")
        self.assertHit(self.bash('git commit -m "#123 fix" --no-verify'), "GIT04")
        self.assertDecision("deny", self.bash("echo '#' ; rm -rf %s" % self.data), "SLF01")
        self.assertDecision("deny", self.bash("git log --grep '#1' && git push --force origin master"), "GIT01")
        self.assertDecision("deny", self.bash("echo a#b && git push -f origin master"), "GIT01")
        self.assertDecision("deny", self.bash("echo \\# ; git push -f origin master"), "GIT01")

    def test_real_comments_still_end_the_line(self):
        self.allow("git log --grep '#1'")
        self.allow("echo hi # git push --force origin master")
        self.allow("echo hi;# git push --force origin master")
        self.assertDecision("deny", self.bash("git push --force origin master # done"), "GIT01")
        self.assertDecision("deny", self.bash("echo hi # note\ngit push --force origin master"), "GIT01")
        self.allow("echo ${#x}")


class WritingReaders(Base):
    """Finding 3: sort/uniq/sed/awk/git/tree/patch can write."""

    def test_writes_into_data_dir(self):
        d = self.data
        cases = [
            "sort -o %s/config.json x" % d,
            "sort -o%s/config.json x" % d,
            "sort --output=%s/config.json x" % d,
            "sort --output %s/config.json x" % d,
            "uniq x %s/config.json" % d,
            "uniq -c x %s/config.json" % d,
            "sed -n 'w %s/config.json' x" % d,
            "sed -n '1W %s/config.json' x" % d,
            "sed 's/a/b/w %s/config.json' x" % d,
            "awk '{print>\"%s/config.json\"}' x" % d,
            "awk '{print > \"%s/config.json\"}' x" % d,
            "awk '{printf \"%%s\", $0 >> \"%s/config.json\"}' x" % d,
            "awk '{print | \"cat > %s/config.json\"}' x" % d,
            "git diff --output=%s/config.json" % d,
            "git log --output %s/config.json" % d,
            "tree -o %s/config.json ." % d,
            "cd %s && patch -p0 < /tmp/x.diff" % d,
            "patch -d %s -p0 < /tmp/x.diff" % d,
            "patch --directory=%s -p0 < /tmp/x.diff" % d,
            "cd %s && git apply /tmp/x.patch" % d,
            "tee %s/config.json < x" % d,
        ]
        for c in cases:
            with self.subTest(c=c):
                self.assertDecision("deny", self.bash(c), "SLF01")

    def test_writes_into_skill_root(self):
        target = os.path.join(self.skills, "x", "SKILL.md")
        self.assertDecision("deny", self.bash("sort -o %s y" % target), "SKL01")
        self.assertDecision("deny", self.bash("awk '{print>\"%s\"}' y" % target), "SKL01")

    def test_reading_is_still_fine(self):
        d = self.data
        for c in ("sort file", "sort %s/config.json" % d, "uniq %s/config.json" % d, "uniq -c %s/config.json" % d,
                  "sed -n p %s/config.json" % d, "sed -n '/w/p' %s/config.json" % d,
                  "awk '{print $1}' %s/config.json" % d, "awk '$1 > 3 {print}' %s/config.json" % d,
                  "git diff", "git log --oneline", "tree %s" % d, "patch -p0 --dry-run < /tmp/x.diff",
                  "git apply --check /tmp/x.patch"):
            with self.subTest(c=c):
                self.allow(c)


class OwnToolRedirects(Base):
    """Finding 4: own-tool commands still have their redirects checked."""

    def test_redirects_from_own_tools(self):
        self.assertDecision("deny", self.bash("python3 %s --data %s show > %s/config.json"
                                              % (CFGTOOL, self.data, self.data)), "SLF01")
        self.assertDecision("deny", self.bash("python3 %s --data %s list > %s/x/SKILL.md"
                                              % (SKILLGATE, self.data, self.skills)), "SKL01")

    def test_harmless_redirect_allowed(self):
        self.allow("python3 %s --data %s show > %s/out.txt" % (CFGTOOL, self.data, self.project))


class InlineSettingsEdits(Base):
    """Finding 7: inline scripts that edit Claude settings."""

    def test_inline_settings_edit(self):
        py = ("python3 -c \"import json;p='~/.claude/settings.json';d=json.load(open(p));"
              "d['disableAllHooks']=True;json.dump(d,open(p,'w'))\"")
        self.assertDecision("deny", self.bash(py), "SLF01")
        node = ("node -e \"const f=require('fs');const p=process.env.HOME+'/.claude/settings.json';"
                "const d=JSON.parse(f.readFileSync(p));d.disableAllHooks=true;f.writeFileSync(p,JSON.stringify(d))\"")
        self.assertDecision("deny", self.bash(node), "SLF01")
        perl = "perl -e 'open F, \">$ENV{HOME}/.claude/settings.local.json\"; print F q({\"disableAllHooks\":true})'"
        self.assertDecision("deny", self.bash(perl), "SLF01")
        proj = "python3 -c \"open('.claude/settings.json','w').write('{\\\"enabledPlugins\\\":{}}')\""
        self.assertDecision("deny", self.bash(proj), "SLF01")

    def test_reads_and_unrelated_scripts_allowed(self):
        self.allow("cat ~/.claude/settings.json")
        self.allow("jq .disableAllHooks ~/.claude/settings.json")
        self.allow("python3 -c \"print(1)\"")
        self.allow("python3 -c \"import json;print(json.load(open('/x/.claude/settings.json'))['theme'])\"")


class GitBypasses(Base):
    """Finding 8: abbreviations, config forms, env config, flag clusters."""

    def test_long_option_prefixes(self):
        self.assertHit(self.bash("git commit --no-verif -m x"), "GIT04")
        self.assertHit(self.bash("git push --no-verif origin feature/x"), "GIT04")
        self.assertDecision("deny", self.bash("git push --delet origin main"), "GIT01")
        self.assertHit(self.bash("git push --mirro backup"), "GIT01")
        self.assertHit(self.bash("git reset --har"), "GIT02")
        self.assertDecision("deny", self.bash("git push --forc origin main"), "GIT01")
        self.assertHit(self.bash("git clean --forc"), "GIT03")
        self.assertHit(self.bash("git switch --discard main"), "GIT02")

    def test_config_forms(self):
        self.assertHit(self.bash("git config set core.hooksPath x"), "GIT05")
        self.assertHit(self.bash("git config unset core.hooksPath"), "GIT05")
        self.assertHit(self.bash("git config --file .git/config core.hooksPath x"), "GIT05")
        self.assertHit(self.bash("git config -f .git/config core.hooksPath x"), "GIT05")
        self.assertHit(self.bash("git config --local --replace-all core.hooksPath x"), "GIT05")
        self.assertHit(self.bash("git --config-env=core.hooksPath=HP commit -m x"), "GIT05")
        self.assertHit(self.bash("git --config-env core.hooksPath=HP commit -m x"), "GIT05")
        self.assertHit(self.bash("git -c core.hooksPath=x commit -m x"), "GIT05")
        self.assertHit(self.bash("git -c Core.HooksPath=x commit -m x"), "GIT05")

    def test_env_config(self):
        self.assertHit(self.bash("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null "
                                 "git commit -m x"), "GIT05")
        self.assertHit(self.bash("export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath"), "GIT05")
        self.assertHit(self.bash("env GIT_CONFIG_PARAMETERS=\"'core.hooksPath'='/x'\" git commit -m x"), "GIT05")

    def test_writes_into_git_config(self):
        self.assertHit(self.bash("printf '[core]\\n\\thooksPath = /dev/null\\n' >> .git/config"), "GIT05")
        self.assertHit(self.bash("echo 'hooksPath = /x' | tee -a %s/.git/config" % self.project), "GIT05")
        self.assertHit(self.pre("Write", {"file_path": os.path.join(self.project, ".git", "config"),
                                          "content": "[core]\n\thooksPath = /x\n"}), "GIT05")

    def test_flag_clusters(self):
        self.assertHit(self.bash("git checkout -qf main"), "GIT02")
        self.assertHit(self.bash("git switch -qf main"), "GIT02")

    def test_near_misses(self):
        for c in ("git commit -m x", "git config core.hooksPath", "git config get core.hooksPath",
                  "git config --get core.hooksPath", "git config --file .git/config user.name x",
                  "git config set user.name x", "git checkout -q main", "git checkout -b feature",
                  "git push --follow-tags origin feature/x", "git reset --soft HEAD~1",
                  "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=user.name GIT_CONFIG_VALUE_0=x git commit -m x",
                  "git -c user.name=x commit -m x", "git restore --stag x", "git clean -n"):
            with self.subTest(c=c):
                self.allow(c)
        # Appended text can land in a trailing [include] section, so a shell write to the config asks (round 5).
        self.assertDecision("ask", self.bash("echo x >> .git/config"), "GIT05")


class SkillRootGit(Base):
    """Finding 9: gh repo clone and git updates inside skill/plugin roots."""

    def test_bring_ins(self):
        foo = os.path.join(self.skills, "foo")
        cases = [
            "gh repo clone x/y ~/.claude/skills/x",
            "cd ~/.claude/skills && gh repo clone x/y",
            "git -C %s pull" % foo,
            "git -C ~/.claude/skills/foo fetch",
            "cd %s && git checkout v2" % foo,
            "git -C %s reset --soft v2" % foo,
            "git -C %s merge origin/main" % foo,
            "git -C %s submodule update --init" % foo,
            "git worktree add ~/.claude/skills/y",
            "git -C ~/.claude/plugins/marketplaces/m pull",
        ]
        for c in cases:
            with self.subTest(c=c):
                self.assertDecision("deny", self.bash(c), "SKL01")

    def test_near_misses(self):
        foo = os.path.join(self.skills, "foo")
        for c in ("gh repo clone x/y", "gh repo clone x/y %s/y" % self.project, "git -C %s status" % foo,
                  "git -C %s log" % foo, "git pull", "git worktree add ../wt"):
            with self.subTest(c=c):
                self.allow(c)


class Heredocs(Base):
    """Finding 10: heredoc bodies are data."""

    def test_bodies_are_not_commands(self):
        self.allow("cat > notes.md <<'EOF'\ngit push --force origin master\nEOF")
        self.allow("cat > notes.md <<EOF\nrm -rf %s\nEOF" % self.data)
        self.allow("git commit -m \"$(cat <<'EOF'\nRelease notes\n\ngit push --force origin master is blocked now\n"
                   "EOF\n)\"")
        self.allow("cat <<-EOF\n\tgit push -f origin master\n\tEOF")
        self.allow("cat <<\"END\" > notes.md\ngit reset --hard\nEND")
        self.allow("git commit -m \"$(cat <<'EOF'\nfix (part 1\nEOF\n)\"")

    def test_commands_around_heredocs_still_seen(self):
        self.assertDecision("deny", self.bash("cat > %s/config.json <<'EOF'\n{}\nEOF" % self.data), "SLF01")
        self.assertDecision("deny", self.bash("cat <<EOF\nhi\nEOF\ngit push --force origin master"), "GIT01")
        self.assertDecision("deny", self.bash("cat <<EOF\n$(git push -f origin master)\nEOF"), "GIT01")
        self.assertDecision("deny", self.bash("cat <<EOF\n`git push -f origin master`\nEOF"), "GIT01")
        self.assertDecision("deny", self.bash("cat <<EOF && git push -f origin master\nhi\nEOF"), "GIT01")
        self.assertDecision("deny", self.bash("echo $((1<<2))\ngit push -f origin master"), "GIT01")
        self.assertDecision("deny", self.bash("git commit -m \"$(cat <<'EOF'\nfix (part 1\nEOF\n)\" && "
                                              "git push -f origin master"), "GIT01")
        self.assertDecision("deny", self.bash("cat <<<'x'\ngit push -f origin master"), "GIT01")


class MarketplaceRemove(Base):
    """Finding 14: removing checkrein's marketplace turns it off."""

    def test_remove_marketplace(self):
        self.assertDecision("deny", self.bash("claude plugin marketplace remove checkrein"), "SLF01")
        self.assertDecision("deny", self.bash("claude plugin marketplace rm checkrein"), "SLF01")

    def test_other_marketplaces(self):
        self.allow("claude plugin marketplace remove other-market")
        self.allow("claude plugin marketplace list")


class PushAllForce(Base):
    """Finding 15: --all/--branches/--mirror with force reaches protected branches."""

    def test_all_force_is_denied_even_when_relaxed(self):
        self.init_repo("topic")
        self.write_config({"preset": "relaxed"})
        self.assertDecision("deny", self.bash("git push --all --force"), "GIT01")
        self.assertDecision("deny", self.bash("git push --branches -f origin"), "GIT01")
        self.assertDecision("deny", self.bash("git push --mirror --force backup"), "GIT01")
        self.assertDecision("deny", self.bash("git push --al --forc origin"), "GIT01")

    def test_near_misses(self):
        self.init_repo("topic")
        self.write_config({"preset": "relaxed"})
        self.assertDecision("ask", self.bash("git push --force origin feature/x"), "GIT01")
        self.allow("git push --all origin")


class CoordinatorItems(Base):
    """Doctor reports a skipped project config; approve --marketplace stays SKL04; bare plugin specs are refused."""

    def doctor(self):
        return subprocess.run([sys.executable, CFGTOOL, "--data", self.data, "--project-dir", self.project, "doctor"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=60,
                              env=self.env, cwd=self.project)

    def test_doctor_reports_skipped_project_config(self):
        self.write_config({"rules": {"GIT01": "maybe"}}, where="project")
        res = self.doctor()
        self.assertNotEqual(res.returncode, 0, res.stdout)
        self.assertIn("FAIL project config", res.stdout)

    def test_doctor_clean_project(self):
        self.assertNotIn("FAIL project config", self.doctor().stdout)

    def test_approve_with_marketplace_is_gate_decision(self):
        base = "python3 %s --data %s " % (SKILLGATE, self.data)
        self.assertDecision("ask", self.bash(base + "approve --marketplace good-market abc123"), "SKL04")
        self.assertDecision("ask", self.bash(base + "approve abc123 --marketplace=good-market --override"), "SKL04")

    def test_bare_plugin_spec_needs_marketplace(self):
        verb = "in" + "stall"
        decision, reason = self.bash("claude plugin %s foo" % verb)
        self.assertIn(decision, ("ask", "deny"), reason)
        self.assertIn("checkrein SKL02", reason)
        self.assertIn("foo@<marketplace>", reason)
        self.assertDecision("deny", self.bash("claude plugin %s foo" % verb[0]), "SKL02")


if __name__ == "__main__":
    unittest.main()
