# Security policy

## Reporting a problem

Please report a way around checkrein, or a bug that could leak a secret, through GitHub's private vulnerability
reporting: the **Security** tab of this repository, then **Report a vulnerability**. Please do not open a public issue
for these.

Include the checkrein version (`plugins/checkrein/scripts/checkrein/__init__.py`), the tool call or command, and what you expected.
Never include a real secret: build test values from pieces, as `tests/helpers.py` does.

You should hear back within a week.

## Scope

A bypass of a rule listed in [docs/limits.md](docs/limits.md) under "Known misses" is already known; a new technique
for one is still welcome. Anything else that lets the agent get past a rule at its configured level, read or reveal a
secret value through checkrein's own output, or change checkrein's config or ledger without a person, is in scope.

## What checkrein does with your data

Nothing leaves your machine. checkrein makes no network calls except the `git clone` that `vet` runs on a source you
name. Logs and reports in its data folder mask secret values.

## Scanner notes

Scanned with SkillSpector 2.13.1 (static rules plus its LLM pass) on `plugins/checkrein/`, the folder Claude Code
installs. Result: risk score 40, CAUTION, no high or critical findings. Each remaining note, and why it stays:

| Rule | Where | Why it is there |
|---|---|---|
| BH1 bundled hooks | `hooks/hooks.json` | checkrein is a hook: a PreToolUse check on every tool call and a SessionStart report. The scanner cannot expand `${CLAUDE_PLUGIN_ROOT}` in the hook command, so it marks that file as partly inspected. Both hooks run `scripts/guard.py`. |
| AST4 subprocess | `rules/git.py`, `rules/sec.py` | Reads the current branch (`git symbolic-ref`) for GIT01, and the staged diff (`git diff --cached`, or `gitleaks` when you chose it) for SEC03. Argument lists, never a shell; short timeouts. |
| AST4 subprocess | `checkrein/gate.py` | `vet` clones the source you name (`git clone --depth 1`, file protocol off) and runs the third-party scanner you configured. Both get a minimal environment, not your shell's. |
| AST4, TT2 | `cfgtool.py` | `detect` reads git's default branch in your project; `doctor` times the hook by running it once on a harmless sample and checks the data folder is writable. The "tainted" values are the project and data folder paths Claude Code passes in. |

Scanning the whole repository instead of the plugin folder gives DO_NOT_INSTALL. Every high finding in that run (28,
rules AS1, P1, PE3, SC2, SC3, TM1, YR1) is in `tests/` or `docs/`, which quote the commands and paths checkrein blocks
(force pushes, `curl … | sh`, credential paths, a prompt-injection phrase, invisible characters). They are test
inputs and documentation, never run, and are not part of the installed plugin. The plugin folder's own findings are
the same medium notes as in the table above.
