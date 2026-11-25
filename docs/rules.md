# checkrein rules

Each rule has a level: `off`, `ask` (Claude Code asks you first) or `deny` (the call is blocked and Claude is told why).
SKL05 is a report, not a gate, so its levels are `off` and `report`.

| Rule | relaxed | standard | strict |
|---|---|---|---|
| [GIT01](#git01) Force push, remote branch delete, mirror push | ask | deny | deny |
| [GIT02](#git02) Discarding local work | ask | ask | ask |
| [GIT03](#git03) Forced `git clean` | ask | ask | ask |
| [GIT04](#git04) Skipping git hooks | ask | deny | deny |
| [GIT05](#git05) Changing `core.hooksPath` or `.git/hooks` | deny | deny | deny |
| [GIT06](#git06) Shared-tree commands | off | off | ask |
| [SEC01](#sec01) Secret written into a file | ask | deny | deny |
| [SEC02](#sec02) Token typed into a shell command | deny | deny | deny |
| [SEC03](#sec03) Secret in staged changes at commit | off | off | deny |
| [SKL01](#skl01) Files dropped into skill or plugin folders | deny | deny | deny |
| [SKL02](#skl02) Plugin install or marketplace add not approved | ask | deny | deny |
| [SKL03](#skl03) Third-party skill installers | ask | deny | deny |
| [SKL04](#skl04) Gate decisions need a person | ask | ask | ask |
| [SKL05](#skl05) Drift report at session start | report | report | report |
| [SLF01](#slf01) Changes to checkrein itself | deny | deny | deny |
| [MCP01](#mcp01) MCP tools that write elsewhere | off | off | ask |
| [MCP02](#mcp02) Secret in an outbound MCP call | deny | deny | deny |

**Unattended runs.** In the `dontAsk` and `bypassPermissions` permission modes nobody can answer a question, so every
`ask` becomes `deny`.

**Commands checkrein cannot read.** A Bash command over 256 KB asks, and one nested more than 64 levels deep is
denied, whatever the rule levels; the reason starts with `checkrein (ask)` or `checkrein (deny)` with no rule name.
Shell text built at run time and given to `sh -c`, `eval`, `su -c`, `ssh` or `watch`, or run from a non-literal
`<(…)`, asks the same way.

**Changing a level.** `/checkrein:config set rules.GIT06 ask` changes your own config; add `--project` to write the
project's `.checkrein/config.json`. A project file can only make rules stricter. Anything looser in it is ignored and
reported at session start.

---

## GIT01

Force pushes (`-f`, `--force`, a `+refspec`), deleting a remote branch (`--delete`, `-d`, `:branch`) and `--mirror`,
from `git push` and `git send-pack` alike. A wildcard refspec (`+refs/heads/*:refs/heads/*`) counts as naming every
protected branch. `--prune` with `--all`, `--branches` or a wildcard refspec deletes every remote branch it covers
that has no local branch, so it counts as deleting each protected branch. `gh api -X DELETE` or `PATCH` on
`repos/<owner>/<repo>/git/refs/heads/<branch>` deletes or moves that branch and counts the same way; other GitHub API
calls (GraphQL `deleteRef`, branch rules) are not read.

- A force push or delete aimed at a protected branch is **denied at every level except off**.
- `--force-with-lease` to an unprotected branch is one step softer than the rule level (deny becomes ask).
- A destination written as a partial ref (`HEAD:heads/master`, `HEAD:refs/heads/master`) counts as that branch.
- With no refspec, git's `remote.<name>.push` and `remote.<name>.mirror` (from `-c`, `GIT_CONFIG_KEY_<n>` or the
  repository's config) are read as if typed; failing those, the current branch is read from git.

Protected branches come from `protected_branches` (default `main`, `master`, `develop`, `trunk`, `production`, `prod`,
`release/*`; globs allowed). Lists from every config layer add up.

## GIT02

Commands that throw away uncommitted work: `git reset --hard`, `git checkout -f`, `git switch --discard-changes` / `-f`.

## GIT03

`git clean` with `-f` and without `-n` / `--dry-run`, or without `-f` when `clean.requireForce` is false (from `-c` or
the repository's config). Also `git stash -u` / `-a` when the working tree holds an untracked `.checkrein/` or
settings file, which the stash would take away.

## GIT04

Skipping hooks: `--no-verify` on commit, merge, rebase, am, cherry-pick, revert, pull and push; `git commit -n`
(also inside a flag cluster such as `-anm`); and hook-skipping environment switches (`HUSKY=0`, `HUSKY_SKIP_HOOKS`,
`SKIP=`, `LEFTHOOK=0`, `LEFTHOOK_EXCLUDE`, `PRE_COMMIT_ALLOW_NO_CONFIG`, `GIT_HOOKS_SKIP`) on git or a JS package
manager, or exported. Set for another program that may run git (`make`, `node`, a script, a git front end), they ask.
Variables set where checkrein can't see them (your shell profile, a script's own `export`) are not seen.

## GIT05

Moving or disabling the hooks themselves: `git -c core.hooksPath=…` or `--config-env`, `git config [set|unset|--file …]
core.hooksPath …` (reading it is fine), `GIT_CONFIG_KEY_<n>=core.hooksPath`, any write into `.git/hooks` (or a
submodule's `.git/modules/<name>/hooks`), and changes to a git config file: a repository's `.git/config` or
`config.worktree`, `~/.gitconfig`, `~/.config/git/config` (or under `$XDG_CONFIG_HOME`) and the system `gitconfig`. A
Write or Edit is compared before and after, and any added, changed or removed hooksPath or include counts; a shell write
that mentions hooksPath or include is denied, and any other shell copy, move, truncation or edit of such a file asks.
`include.path` and `includeIf.*.path` (set or passed in any of those ways) count, since an included file can set
hooksPath; so do removing or renaming the `[core]`, `[include]` or `[includeIf …]` section and running commit,
merge, rebase, am, cherry-pick, revert, pull or push with `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`,
`GIT_CONFIG_NOSYSTEM`, `HOME` or `XDG_CONFIG_HOME` set.
Where the file system ignores case, `.GIT/HOOKS` is `.git/hooks`. Paths are also read after following symlinks, so a
link to `.git/hooks` or a config file counts as its target, and making such a link with `ln` asks. find `-delete` or
a writing `-exec`, `-r` writers, and xargs fed by find, ls, echo or printf count for the folders they reach: a folder
in `.git/hooks` is denied, and one holding the repository asks unless find's `-name` tests rule out every hook name
and `config`. The folder `core.hooksPath` points to (such as `.husky/`) is not protected: editing the hooks in it is
ordinary project work.

Across the git rules, an abbreviated long option that git accepts (`--no-verif`, `--forc`) counts as the full option,
and short flags are read inside clusters (`checkout -qf`).

## GIT06

For checkouts several agents share: `git stash` (except `list` and `show`), `git restore` (except `--staged` only),
`git add -A` / `--all` / `.` / `-u`, `git checkout -- <path>`, `git checkout .` and `git commit -a`. Off unless you pick
strict or turn it on.

## SEC01

A secret in content Claude writes with Write, Edit, MultiEdit or NotebookEdit.

- Only **new** lines count, so a file that already holds a secret is not flagged on every edit.
- High-confidence formats (provider tokens, private key blocks) use the rule level. Generic patterns such as
  `api_key = "…"` are capped at ask.
- Placeholders (`changeme`, `your-key-here`, `${VAR}`, `<…>`, `xxxx`, documented examples) are skipped.
- The reason names the kind of secret and the line, never the value.
- `secret_ignore_paths` (globs) skips files such as test fixtures. In a project file the list applies only after
  `/checkrein:config approve secret_ignore_paths`.

## SEC02

A real-format token typed into a Bash command, for example a bearer token in a `curl` header. Use an environment
variable instead (`$GITHUB_TOKEN`). A password inside a URL (`scheme://user:pass@host`) only asks. A token split by
quotes (`ab''cd`) is joined the way the shell joins it before the check.

## SEC03

Scans staged changes when `git commit` runs, plus unstaged tracked changes for `commit -a`, and for the paths a
commit names (`git commit -m x app.env`, `-- app.env`, `-i`, `--only`), which git takes from the working tree. Files
`.gitattributes` marks binary or `-diff` are scanned as text; the built-in scan runs alongside gitleaks for them. `secret_scanner` picks the
engine: `auto` (gitleaks when installed, else built-in), `gitleaks` or `builtin`. Off unless you pick strict or turn it
on; a pre-commit secret scanner in the repo does the same job.

## SKL01

Bringing files into a skill or plugin folder outside the gate: copying, moving, linking, downloading, cloning
(including `gh repo clone`), unpacking, or git commands that update a working tree (pull, fetch, checkout, reset,
merge, submodule, worktree add) into or inside `~/.claude/skills`, `commands`, `agents` or `plugins` (in
`$CLAUDE_CONFIG_DIR` when that is set), a `.claude/skills`, `.claude/commands` or `.claude/agents` folder at any depth
of the project (`packages/app/.claude/skills`), a `.claude` folder copied or cloned into the project, or a folder in
`extra_skill_roots`. A plain `cp` or `mv` of files already in the project into a `commands` or `agents` folder is
fine. Writing your own skill with the Write tool is fine; writing into the plugin cache is not. Use
`/checkrein:vet <source>` instead. A copy that lands as a skill folder or a folder holding one
(`cp -r stage/skills ~/.claude/`), pouring a folder's contents into the folder above one (`rsync -a stage/ ~/.claude/`,
`ditto`), clustered download flags (`curl -sSLo`, `wget -qO`) and `git --work-tree`/`GIT_WORK_TREE` count too.
Unpacking, checking out or pouring a folder into a folder above a skill root, up to your home folder or the project's
`.claude` (`tar -xf x.tar -C ~`, `cd ~ && unzip x.zip`, `rsync -a stage/ ~/`, `cpio -idm`), counts, as do `svn
checkout`, `hg clone`, `aria2c`, `sftp`, `http -d` and `pip download` into a skill folder. Unpacking into the project
folder itself is not checked, and neither is what a program you run writes on its own (an installer script, a build).
Every `git -C` counts, each read from the one before it (`git -C ~/.claude -C skills/foo pull`), as do hg's `--cwd`
and `-R`. A `find` or `fd` that runs a writing program on the files of a skill or plugin folder outside the project
(`find ~/.claude/skills -exec sed -i …`) counts too.

## SKL02

`claude plugin install` and `claude plugin marketplace add` for anything the ledger has not approved. Vet and approve
it with `/checkrein:vet` first; the approval prints the exact commands to run. An approval covers one marketplace:
`approve <id> --marketplace <name>` allows installing `<plugin>@<name>` only, and a vetted marketplace covers the
plugins it lists. An install that names no marketplace is treated as unapproved. If the ledger file is unreadable,
installs are denied until it is fixed. A spec without a marketplace (`foo`) can't match an approval; name it as
`foo@<marketplace>`. `install foo --marketplace <source>` needs that source approved for `foo`. A Write or Edit of a
settings file that turns on an `enabledPlugins` entry the ledger has not approved, or changes
`extraKnownMarketplaces`, counts the same, and so does `claude plugin enable <spec>` (`enable --all` included).
Turning checkrein itself back on passes; a plugin named checkrein from another marketplace does not. `plugin update` and
`plugin marketplace update` count too, at the same level: they bring in versions nobody vetted, so run them yourself
from `/plugin` and check the result with `/checkrein:status`. `plugin` and `plugins` are read alike, and option values
(`-s project`) are never taken for the plugin name.

## SKL03

Package runners that fetch and run third-party skill installers (`npx`, `bunx`, `pnpx`, `uvx`, `uv tool run`,
`pnpm dlx`, `yarn dlx`, `pipx run`, `npm exec`/`npm x`, `bun x`, `corepack <manager> …`, `deno run npm:…`) with a
package named in `extra_installers`, and those installers run directly with `add`, `install` or similar. The program
is read from the package spec: scope, version and `npm:`/`github:` prefixes are dropped and case is ignored. A runner
whose package can't be named (a URL, a git source, a tarball, a variable or substitution, or a shell string given
with `-c`) asks. The defaults cover the common skill installers; add more to the list. The same reading applies to
SLF01: `npx @anthropic-ai/claude-code …` is checked as `claude …`.

## SKL04

`skillgate.py approve`, `adopt` and `forget` always go to a person, so Claude cannot approve its own install.

## SKL05

At session start, lists skills and plugins that changed since they were approved, were never vetted, or were approved
but are no longer installed. Skill folders nested in the project (`packages/app/.claude/skills`) are listed too; the
search skips `node_modules` and `.git` and stops 8 folders deep or after 20,000 folders. If the copy Claude Code
downloaded differs from what was vetted, it is listed under changed at every session start until you vet and approve
that content. Nothing is blocked. Turn it off with `rules.SKL05 off`. Run `/checkrein:status` to review or adopt what is
already installed.

## SLF01

Changes to checkrein's own files: its data folder (config, ledger, quarantine), the plugin folder, and the project's
`.checkrein/`, including any writing command run from inside one of them, and removing, moving or replacing a folder
that holds them (`rm -rf ~/.claude`, `mv ~/.claude x`, an archive unpacked over home). Also settings changes: a Write
or Edit to a settings file is let through only when the file afterwards is strict JSON that still has checkrein
enabled, its `pluginConfigs` entry and hooks unchanged and `disableAllHooks` unset or `false`; a shell command that
changes a settings file holding checkrein, `enabledPlugins`, `pluginConfigs`, `hooks` or `disableAllHooks`, or naming
them, is denied, and one that changes any other settings file asks, since its result can't be known. A settings file
counts as named by any path that leads to it from the command's folder (`cd ~/.claude && vim settings.json`), and an
interpreter or editor run inside a `.claude` folder (or `$CLAUDE_CONFIG_DIR`) counts as changing its settings files.
Paths are compared after following symlinks, so a settings file that links elsewhere protects its target.
Programs that act on everything below a folder count when the folder holds a protected file: `find` with `-delete`
or a writing `-exec`, `fd -x`, `-r`/`-R` writers (rm, chmod, chown, gzip, xz…) and archivers that remove what they
archive (`tar --remove-files`, `zip -m`, `7z -sdel`). A `find` whose `-name` tests can't match any protected name
(`find . -name '*.pyc' -delete`) passes, and so do a `chmod` that only adds permissions (`chmod -R u+w .`) and
`find -type d -delete`, which removes only empty folders. A writer that `xargs` feeds with what `find` or `ls`
finds counts the same way. When the name tests reach only files checkrein may write later (`ledger.json`), a person
confirms. A mode written with a dash (`chmod -x file`) is read as the mode. An Edit with
an empty `old_string` writes the file whole; an Edit whose `old_string` is found only after curly quotes and line
endings are evened out is judged on that text, and one that can't be matched at all is denied when the file holds
checkrein and asks otherwise. In a settings `env`, setting or removing a variable that steers hooks, git, shells
or Python is denied (`GIT_*`, `HUSKY*`, `SKIP`, `LEFTHOOK*`, `PRE_COMMIT*`, `LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`,
`ZDOTDIR`, `SHELL`, `XDG_*`, PATH, HOME, `PYTHON*`, `CLAUDE_CONFIG_DIR`, `CLAUDE_CODE_SHELL_PREFIX`,
`CLAUDE_CODE_SIMPLE`, `CLAUDE_PLUGIN_*`, `BASH_FUNC_*`, `__BASH_FUNC*`, `SHELLOPTS`, `BASHOPTS`, `PS4`, `IFS`,
`GCONV_PATH`, `PROMPT_COMMAND`, `LC_*`); any other `CLAUDE_*` name asks. Changing a helper command (`apiKeyHelper`,
`awsAuthRefresh`, `awsCredentialExport`, `fileSuggestion`, `gcpAuthRefresh`, `otelHeadersHelper`, `processWrapper`,
`policyHelpers`, `proxyAuthHelper`, `statusLine`, `subagentStatusLine`) asks; edits elsewhere in the file pass. Writing a
`.pth` file, sitecustomize or usercustomize, or into a `site-packages` folder, which Python loads at start, is
denied. So is changing the Python the hook runs with: `python`, `python3` or `python3.N` in any folder on its PATH
(`~/.local/bin` before it exists too; case is ignored where the file system ignores it), the file `sys.executable` leads to, and the standard library, which `-I -S`
still loads. A virtual environment made in a folder whose `bin` is on that PATH is denied; `brew install python`,
`python@3.N`, `pyenv install` (not `--list`) and `uv python install` ask. Commands that only read a settings file (`git add`, `git diff`, `cp` or
`scp` from it, `tar -c`) are fine. A nested `claude` passes with the options known to keep its hooks (`-p`,
`--model`, `--output-format`, `--input-format`, `--max-turns`, `--system-prompt`, `--append-system-prompt`,
`--allowedTools`, `--disallowedTools`, `-c`, `-r`, `--verbose`, `--add-dir`, `--json-schema`, `--version`, `--help`,
`--effort`, `--fallback-model`, `--session-id`, `--include-partial-messages`, `-d`, `--fork-session`,
`--no-session-persistence`, `-n`, `--ide`, `--chrome`, `--replay-user-messages`, `--permission-mode` default, plan
or acceptEdits) and its management subcommands (`mcp list`, `config get`,
`plugin list`). Any other option (`--bare`, `--plugin-dir`, `--plugin-url`, `--settings`, `--setting-sources`,
`--dangerously-skip-permissions`, `--mcp-config`, `--agents`) asks, and so does a `CLAUDE_*`, HOME or `XDG_CONFIG_HOME` variable set for it.
`npm exec <pkg> -- …`, Claude Code's `~/.local/share/claude/versions/*` files and `node …/cli.js` count as `claude`.
Disabling or uninstalling checkrein (`plugin disable --all` too, any case), saving its options with
`plugin configure checkrein --values-stdin`, and removing its marketplace. Commands that write or run something while
looking read-only count as writes (`sort -o`, sed `w` and `--in-place`, awk `print >`, `patch`, `find -fprint0`,
`rg --pre`, `fd -x`, `git grep -O`, a `LESSOPEN` or pager setting). A glob or `{a,b}` word that could name one of
these paths counts as naming it, and so does an interpreter's script read from a heredoc. Reading these files is fine.
`cfgtool set`, `unset`, `approve` and `init` ask instead of being denied, so `/checkrein:config` still works;
checkrein commands with options it can't read exactly ask too. A checkrein command counts as one only when written
plainly, `python3 <plugin>/scripts/<tool>.py ...`: interpreter options (`-c`, `-W`, `-i`) or variables in front
(`PYTHONPATH=...`) make it an ordinary command, and `--data` or `--project` naming any folder but checkrein's own
asks (SKL04 for skillgate), since that folder's config could name any scanner.

If you develop checkrein from its installed folder, turn this rule off in your own config.

## MCP01

MCP tools whose names look like writes to another system: the name after the server, split at `_`, `-`, `.` and
camelCase, holds a write verb as a whole word (create, update, delete, send, post, comment, merge, transition, batch…,
so `slack_send_message`, `chat_postMessage` and `notion-create-pages` count and `get_settings` does not), or the name
matches `mcp_write_tools`. The question shows the masked payload so you can see what will be sent. Tools matching
`mcp_routine` pass; that list is read from your own config only, never a project file. Off unless you pick strict.
Both lists hold globs matched against the whole tool name, ignoring case: `*`, `?`, `[ab]`, `[!a]` and `{a,b}`, for
example `mcp__*__create*` or `*__set_session_title`. Regexes are refused. Glob matching takes time in proportion to
the pattern and the name, so no pattern can stall the hook.

## MCP02

A high-confidence secret, or a password in a URL, anywhere in an MCP tool call's input. Each string (keys too) is
scanned as sent, so a token after a newline or tab is found, and a long line is scanned in overlapping windows up to
the size cap. Tokens split across strings or encoded (base64, URL-encoded) are not found.
