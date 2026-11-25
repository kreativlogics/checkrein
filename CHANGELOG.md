# Changelog

## 0.1.0 (unreleased)

First release.

- Install gate: `vet` quarantines a skill, plugin or marketplace, runs the built-in static scan and an optional
  third-party scanner, and gives a PASS, REVIEW or BLOCK verdict. `approve` installs a skill or records a plugin or
  marketplace in the ledger. `audit` and `adopt` bring already-installed items under the ledger.
- Session-start drift report for changed, never-vetted and removed skills and plugins.
- Rules: git safety (GIT01–GIT06), secrets in writes, commands and commits (SEC01–SEC03), install side doors
  (SKL01–SKL04), self-protection (SLF01), MCP writes and secrets (MCP01–MCP02).
- Presets (relaxed, standard, strict), per-rule levels, and layered config where a project file can only tighten.
- The plugin ships from `plugins/checkrein/`, so installs and scans cover only what runs; tests and docs stay in the
  repository.
- Child processes (the `git clone` of a source, a third-party scanner) get a minimal environment; `scanner.env` names
  any extra variables a scanner needs.
- Built-in credential check matches credential folders and files only under the home folder (so a project's own
  dotfiles no longer trigger it), adds a medium check for other hidden files and app data in the home folder, and
  covers browser password stores.
- The hook caches its bytecode in checkrein's data folder, never in the plugin folder.
- Marketplace vets scan only what gets installed (the `.claude-plugin` folder and each relative plugin folder), and
  run the third-party scanner once per plugin; the report lists what was scanned.
- Static checks report actions, not mentions: the bypass and persistence checks look for the setting, flag or git
  command itself, and a match inside a regex pattern on a pattern-only line is low.
- Plugin approvals name a marketplace (`approve <id> --marketplace <name>`), and installs must match it; an install
  with no marketplace is unapproved. A downloaded copy that differs from what was vetted is reported every session.
- An invalid project config is ignored as a whole instead of sending every call to `fail_mode`; `fail_mode` in your
  own config now applies.
- MCP patterns are length- and shape-checked so they cannot stall the hook.
- SEC03 works whatever git's diff prefix settings are, and with quoted file names.
- Ledger and config writes are atomic and locked; skill installs are checked before they replace anything; `--name`
  must be one plain folder name; abbreviated command options are refused.
- Shell parsing: a quoted `#` no longer ends the command, heredoc bodies are data, and `);`-style runs are split.
- Git rules accept git's abbreviated long options and short-flag clusters, and cover every core.hooksPath form
  (`config set/--file`, `--config-env`, `GIT_CONFIG_*`, `.git/config` writes); `push --all/--mirror --force` is judged
  against protected branches.
- SKL01 covers `gh repo clone` and git commands that update a skill or plugin folder; SLF01 covers write-capable
  readers (`sort -o`, sed `w`, awk `print >`, `patch`), inline scripts that edit settings, redirects on checkrein's own
  tools, and removing checkrein's marketplace. A bare `plugin install foo` must name its marketplace.
- `mcp_write_tools` and `mcp_routine` now hold globs (`mcp__*__create*`, `{a,b}`), matched in linear time and
  ignoring case; regexes are refused as a config error. Rewrite any regex entries as globs.
- The plugin CLI is read with its real options: `plugin` and `plugins`, `-s/--scope` values, `disable --all`,
  `configure checkrein --values-stdin` (SLF01), and `plugin update`, `marketplace update` and
  `install --marketplace <source>` (SKL02). `install -s project foo@m` is no longer misread.
- Glob and `{a,b}` words that could name a protected path count as naming it, for SKL01 and SLF01.
- Config, ledger and approval files are read only when they are regular files under a size cap, without blocking;
  an odd project config (a folder, FIFO, device link) is ignored like an invalid one.
- SKL01 also covers `curl -sSLo`/`wget -qO`, copies into the folder above a skill root, and git work trees. SLF01
  also covers `sed --in-place=`, `-ni`, `find -fprint0`, `rg --pre`, `fd -x`, `git grep -O`, pager and `LESSOPEN`
  settings, and interpreter scripts in heredocs. `grep -i` and `git -C <dir> status` on checkrein's files are reads.
- SEC02 joins quoted pieces of a word before scanning.
- On a file system that ignores case (macOS, Windows), other spellings of protected paths (`~/.Claude/SKILLS/x`,
  `~/.CLAUDE/settings.json`) count as those paths for SKL01 and SLF01, for literal and glob paths alike. Case-sensitive
  file systems compare exactly.
- Only a plainly written `python3 <plugin>/scripts/<tool>.py ...` counts as checkrein's own tool; interpreter
  options or variables in front (`-c`, `PYTHONPATH=`) make it an ordinary command, checked like any other.
- SLF01 reads relative names against the folder a command runs in, and a writing command run inside a protected
  folder counts as changing it (`cd <data> && ed -s config.json`).
- SLF01 judges a settings change by its result: an edit must keep checkrein enabled, hooks unchanged and
  `disableAllHooks` unset; a shell command that changes a settings file holding those keys is denied.
- GIT01 reads `remote.<name>.push` and `remote.<name>.mirror` from `-c` and the repository config, wildcard refspecs,
  `git send-pack`, and `--signed` no longer swallows `--force`. GIT03 covers `clean.requireForce=false`.
- MCP02 scans each string of the input, so a token after a newline or tab is found.
- `{a..z}` character ranges are size-checked before they are built, and one command's brace expansion has a work
  budget; past it the command asks.
- Config values with control characters, and relative `extra_skill_roots`, are refused as a config error.
- A relative local marketplace source is read against the command's folder.
- After a `cd` checkrein can't follow (`cd "$DIR"`), a writing command's relative `.checkrein`, `.claude/...` and
  `.git/hooks` names count as protected (SLF01, SKL01, GIT05).
- The install gate records a vetted local marketplace by its real absolute path, so an approval matches from any
  folder, whatever path it was vetted by.
- Marketplace sources are compared in one normal form on both sides: `a/mk`, `github.com/a/mk`, `https://…/a/mk.git/`
  and `git@github.com:a/mk` match each other; another host, owner, repo or `#ref` does not, nor does `http://`.
- Round 4: SLF01 counts a settings file named by any path from the command's folder (`cd ~/.claude && ed -s
  settings.json`), interpreters and editors run inside `.claude`, removing or moving a folder that holds protected
  files, and archives unpacked over home; `pluginConfigs` for checkrein must stay unchanged, `disableAllHooks` must be
  unset or `false`, and settings with `NaN` are refused; a shell change to any other settings file asks. A nested
  `claude` with `--settings`, `--dangerously-skip-permissions` or a bypass mode asks; `plugin rm` and any case of
  `checkrein` count. `open` and `code` are no longer read-only. GIT05 covers `include.path`, `includeIf`, config-file
  variables on hook-running commands, `--rename-section core` and any case of `.git/hooks`. GIT04 asks for
  hook-skip variables on other programs. SKL01 covers unpacking into home and `.claude`, cpio, svn, hg, aria2c, sftp,
  `http -d` and `pip download`. checkrein's own tools with another `--data` or `--project` ask. `file://` sources stay
  local. Long lines are scanned in overlapping windows. `${…}` and the xargs `{}` placeholder are values, not globs.
- Round 4: every package runner form (npx, npm exec, pnpm dlx, yarn dlx, bunx, corepack, `deno run npm:`, pipx run,
  uvx) is read as the program it runs, for SKL03 and for SLF01's nested `claude` check; a runner package checkrein
  can't name (URL, tarball, git source, variable) asks. Long command lines are checked faster.
- Round 4: a failing check no longer cancels what the others found (fail_mode applies only when stricter); malformed
  input to a known tool is denied; a check past 5 seconds is denied; unattended reasons say deny.
- Shell reading (round 2): command substitutions inside `$(( ))`, `(( ))`, `$[ ]` and `${ }` are read; `$'...'`
  quotes honor `\'`; heredoc delimiters are read as whole words, `EOF)` ends a heredoc inside `$(...)`, and `<<`
  inside `${ }` or `$[ ]` no longer starts one; a script fed to a shell on stdin (`bash <<EOF`, `sh -s`, `bash <<<`,
  `source /dev/stdin`, or literal text piped in: `cat <<EOF | sh`, `echo … | bash`) is read as commands, and
  unknown text piped into a shell (`curl … | sh`) asks; commands after `if`, `then`, `do`, `while`, `!` are
  checked. Nesting deeper than 64 levels is denied, and commands over 256 KB ask, instead of failing or timing out.
- Shell reading (round 3): a `cd`, `pushd` or `popd` moves later commands only where it surely took effect, and each
  command carries every folder it may run in (`Cmd.cwds`); substitutions are checked in the folders their line
  reaches. `(( ))` is told from nested subshells honoring quotes and `${ }`. `$(…)` in quoted subscripts and
  arithmetic the shell evaluates (`let`, `declare`, `[[ … -eq … ]]`, `a['…']=`, `${a['…']}`) is read. Commands
  run through find `-exec`, `env -S`, arch, xcrun, script, flock, ssh, su `-c`, `sudo -s`, parallel, watch, zsh's
  `repeat` and `-`, and `sh <(…)` / `source <(…)` are read. `sh -c` and `eval` of text built at run time ask.
  Program names match in any case (`GIT push`), and unquoted `{a,b}` groups are expanded into the words that run.
  `env -C`/`--chdir`, `sudo -D`/`--chdir` and `make -C`/`--directory` move only that command's folder.
- Shell reading (round 4): literal `NAME=value` assignments made earlier in the line resolve `$NAME` and `${NAME}`;
  each command gets `Cmd.inherited_env`, what earlier assignments, `export`, `declare -x`, `typeset -x`, `set -a` and
  a parent shell's prefix pass on. Shell text run by `trap`, git (`-c alias.x='!…'` and aliases, `core.pager`,
  `core.sshCommand`, `core.fsmonitor`, editors, `diff.external`, `credential.helper '!…'`, `GIT_*` command
  variables, `rebase --exec`, `bisect run`, `submodule foreach`), tmux, screen, dtach, expect, at, batch, crontab,
  launchctl, direnv, npm/npx/yarn exec, just, nix, uv run, poetry run and bundle exec is read; text built at run
  time asks. Short-option clusters (`env -iS`, `sudo -Hu me`, `xargs -0I {}`, `watch -tn 5`) and `script -F` are
  read; `env -S` follows its own splitting rules (`\_`, `\c`). Unclosed quotes in nested text ask. Folder candidates
  are capped and a reading-step budget denies, so any line up to 256 KB is decided in about a second.
- Round 5: GIT05 covers every git config file (`~/.gitconfig`, XDG and system config, `config.worktree`) and any
  change to hooksPath or includes, removals too; shell copies onto a config file ask; submodule hooks count. GIT01
  covers `push --prune` over every branch and `gh api` DELETE/PATCH of a protected ref. SKL01 covers nested
  `.claude/skills`, `commands` and `agents` folders and `$CLAUDE_CONFIG_DIR`; SKL05 lists nested project skills.
- Round 5 (shell tools and self-protection): the hook matches every tool, and any tool with a text `command`
  (Monitor, unknown tools) is judged as Bash. Hooks run as `python3 -I -S`. SLF01 covers Python startup files,
  settings `env` changes to `PYTHON*`, PATH, HOME and `CLAUDE_CONFIG_DIR`, symlinked settings, `$CLAUDE_CONFIG_DIR`,
  empty-`old_string` and loosely matched Edits; commands that only read a settings file pass
  (`git add`, `cp` from it, `python3 -m json.tool`), and a relative name in a script points at the project's file. Settings edits that
  enable an unapproved plugin or change `extraKnownMarketplaces` get SKL02. MCP01 finds write verbs anywhere in the
  tool name. Secret patterns are bounded and a large MCP payload is masked only where shown, so 256 KB inputs decide
  within a second and a half; a word with too many `{a,b}` expansions says so.
- Round 6 (self-protection): find `-delete`/`-exec`, `fd -x`, `-r`/`-R` writers and removing archivers on a folder
  above a protected file count as changing it (`recursive_targets` in context.py), narrowed by find's `-name` tests.
  `chmod -x` reads `-x` as the mode. Every `git -C` applies in order, clone destinations follow it, and hg `--cwd`
  and `-R` count for SKL01. SEC03 scans the paths a commit names and files marked `-diff` or binary. Copies of many
  sources into one folder compare that folder once. A chmod that only adds permissions and `find -type d -delete`
  pass; `find | xargs <writer>` counts like `find -exec`; `git stash -u`/`-a` asks over untracked protected files.
- Round 6 (git): GIT05 follows symlinks (a link to `.git/hooks` or a config file, and `ln` making one, count), reads
  find `-delete`/`-exec` and xargs from find, ls, echo or printf that reach `.git/hooks` or a config file, and counts
  removing the `[include]` and `[includeIf]` sections. GIT01 reads partial refs (`HEAD:heads/master`). Past 32
  `git -C` folders the folder is unknown, so a 256 KB chain reads in well under a second.
- Round 7: reading and parsing the hook input can no longer crash the hook. Input nested more than 200 levels
  deep is denied, and any failure, SystemExit included, goes through `fail_mode` with a decision. An MCP tool whose
  `command` is an object is judged as an MCP call, not as malformed shell input. `claude plugin enable` needs the
  install ledger's approval like an `enabledPlugins` settings entry; checkrein itself passes.
- Round 7b: SLF01 protects the Python the hook runs with (python names on its PATH, `sys.executable`, the
  standard library); Python installs ask and a venv on that PATH is denied. A nested `claude` is judged by a list of
  safe options and asks for anything else or for `CLAUDE_*`, HOME or `XDG_CONFIG_HOME` set for it. Settings `env`
  denies more variables that steer hooks, git, shells and Python, asks for other `CLAUDE_*` names, and changes to
  `statusLine` and the auth and telemetry helpers ask.
- Round 7c: python folders on PATH are compared ignoring case where the file system does. Settings `env` denies the
  shell names Claude Code itself treats as dangerous (`BASH_FUNC_*`, `SHELLOPTS`, `IFS`, `LC_*`...), and every helper
  command setting asks. `npm exec <pkg> -- …`, Claude Code's versions folder and `node …/cli.js` count as
  `claude`; more everyday `claude` options pass. `brew install python-tk`, `pyenv install --list` and
  `python3 -I -m venv` pass.
