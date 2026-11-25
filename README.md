# checkrein

An enforcing install gate and secret guard for Claude Code.

Skill and plugin scanners tell you what looks risky. checkrein makes the check hard to skip: new skills and plugins go
through a quarantine and a verdict before they land, the common ways to copy them in some other way are stopped, and
so are the ways the agent could turn the guard off that checkrein knows (the rest: [limits](docs/limits.md)). It
also stops secrets being written into files, typed into commands or sent to MCP tools, and blocks the git commands
that lose work or skip hooks.

- Stdlib Python 3.9+, no dependencies, no network, no telemetry.
- Every rule has a level (`off`, `ask`, `deny`) and a preset (`relaxed`, `standard`, `strict`).
- About 40–80 ms per tool call, almost all of it Python start-up.

## Install

```
/plugin marketplace add kreativlogics/checkrein
/plugin install checkrein@checkrein
```

Then run `/checkrein:config` once. It looks at what you have (gitleaks, a skill scanner, hook managers, MCP servers),
suggests a preset and writes your config after you agree. Run `/checkrein:status` to bring the skills and plugins
you already have under the ledger.

## What it does

**Install gate.** `/checkrein:vet <source>` copies a skill, plugin or marketplace into quarantine (a GitHub link,
`owner/repo`, or a local folder), runs the built-in static checks and, if you configured one, a third-party scanner,
then shows a PASS, REVIEW or BLOCK verdict with every finding. You approve; it installs the skill, or records the
plugin and prints the install command. Meanwhile:

- copying, cloning, downloading or unpacking into skill or plugin folders with the common commands is denied
  (SKL01); other tools that write files can still bring one in (see [limits](docs/limits.md));
- `claude plugin install` and `marketplace add` for anything not approved are denied (SKL02);
- third-party skill installers run through `npx`, `uvx` and friends are denied (SKL03);
- approving is always a person's decision (SKL04);
- each session start reports skills and plugins that changed since approval or were never vetted (SKL05).

**Secrets.** New lines with a real-format token or private key are denied in Write and Edit calls (SEC01), shell
commands (SEC02) and outbound MCP calls (MCP02). Generic `password = "…"` patterns ask instead. The message names the
kind of secret and the line, never the value. Optional: scan staged changes at commit, with gitleaks if installed
(SEC03).

**Git.** Force pushes, mirror pushes and remote deletes (always denied on protected branches), also when set by
git config, `reset --hard`, forced `clean` (or `clean.requireForce` turned off),
`--no-verify` and its environment-variable cousins, and moving `core.hooksPath` (GIT01–GIT05). For checkouts several
agents share, `stash`, `restore`, `add -A` and `commit -a` can ask (GIT06, strict).

**Self-protection.** The agent can read checkrein's config and ledger but not change them, disable the plugin, or turn
hooks off in settings by the means checkrein recognizes (SLF01); a program that changes files on its own, out of
checkrein's sight, can still reach them, and a repository's committed `.claude/settings.json` can switch checkrein off
there (see [limits](docs/limits.md)). Config changes go through `/checkrein:config`,
which asks you.

**MCP writes (strict).** MCP tools that create, update, send or delete ask first and show the payload (MCP01).

Full list with levels: [docs/rules.md](docs/rules.md). What it cannot catch: [docs/limits.md](docs/limits.md).

## Configure

| Where | File | Can |
|---|---|---|
| Plugin options | set when you enable the plugin | preset, fail mode, scanner command |
| Your config | checkrein's data folder, via `/checkrein:config` | anything |
| Project config | `.checkrein/config.json`, committed | only tighten |

```
/checkrein:config set rules.GIT06 ask
/checkrein:config set protected_branches --add staging
/checkrein:config set secret_ignore_paths --add "tests/fixtures/*"
/checkrein:config explain SEC01
```

A project file that tries to loosen a rule is ignored and reported. Project entries that would run a program
(`scanner`) or skip secret checks (`secret_ignore_paths`) wait for your `approve`.

If checkrein itself fails (a broken config file, a crash), `fail_mode` decides: `ask` (default), `deny` or `allow`.
Hook input nested more than 200 levels deep is denied as unreadable before it is parsed.
The strictest of the plugin option and your config wins; a project can only raise it. An invalid project file is
ignored as a whole: your config and the defaults still apply, and checkrein says so.
In `dontAsk` and `bypassPermissions` modes, every `ask` becomes `deny`.

## With a scanner

checkrein's built-in checks look for the usual bad signs: pipe-to-shell, credential reads, persistence, hidden
Unicode, bundled binaries, symlinks out of the package. For a deeper read, plug in a scanner:

```
/checkrein:config set scanner "skillspector scan {path} --no-llm --format json --output {report}"
```

The scanner runs with a minimal environment (PATH, HOME, locale, temp and proxy settings). If it needs an API key,
name the variable: `{"command": [...], "env": ["SCANNER_API_KEY"]}` in your config.

Without a scanner, the best verdict is REVIEW. Any scanner that writes a JSON report works; `{path}` is the quarantined
folder and `{report}` the report file.

## Works with

checkrein is narrow on purpose. It pairs well with a broad destructive-command guard and with Claude Code's own
permission rules and sandbox. Rules that overlap can be set to `off`.

## Scanning checkrein before you install it

The plugin Claude Code installs is the `plugins/checkrein/` folder; tests and docs stay in the repository. Scan that
folder:

```
skillspector scan plugins/checkrein
```

Expect a REVIEW, not a PASS: a plugin with hooks and scripts always gets the "bundled hooks" and "subprocess" notes.
Each remaining note is explained in [SECURITY.md](SECURITY.md#scanner-notes). Scanning the whole repository flags much
more, because the tests and docs quote the very commands and paths checkrein blocks.

## Development

```
cd tests && python3 -m unittest discover
```

The plugin lives in `plugins/checkrein/`; `.claude-plugin/marketplace.json` at the root points to it. To try a local
copy: `claude --plugin-dir plugins/checkrein`.

Fake secrets in tests are assembled from pieces at run time; please keep it that way. If you work on checkrein from its
installed folder, set `rules.SLF01` to `off` in your own config.

## License

MIT. See [LICENSE](LICENSE). Security reports: [SECURITY.md](SECURITY.md).
