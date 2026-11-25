# What checkrein cannot do

checkrein is a guardrail, not a sandbox. It reads each tool call before it runs and matches it against rules. Anything
that hides the real action from that reading gets through. Use it alongside, not instead of, Claude Code's permission
rules, a sandbox for untrusted work, and server-side protections (branch protection, secret scanning in CI).

## Known misses

Most are tested as expected failures in `tests/test_cfgtool.py`, so a change that fixes one shows up.

- **Aliases and wrappers.** `git pf` where `pf` is an alias for `push --force` in a config file, or a shell function,
  is not expanded (an alias given with `git -c alias.pf=…` in the same call is). Wrappers and launchers are unwrapped
  only from a fixed list (sudo, env and `env -S`, timeout, xargs, nohup, arch, xcrun and the rest of `WRAPPERS` in
  `shell.py`, plus find `-exec`, ssh, su `-c`, flock, script, watch, parallel, trap, tmux, screen, dtach, expect,
  at, batch, crontab, launchctl, direnv, npm/npx/yarn/pnpm/bun exec, just, nix, uv run, poetry run, bundle exec);
  a command run through any other launcher (`kubectl exec`, `docker exec`) is not read. xargs input is read only
  when echo, printf (`%s\n`) or a heredoc gives it literally; paths from find or ls stay unknown, and only their
  roots and find's tests are known. `npm --prefix` and `-C` are not
  treated as a folder move: npm itself stays put. A command sent with `ssh host
  '…'` is checked as if it ran here.
- **Encoded or generated commands.** `echo … | base64 -d | sh`, `eval "$(…)"`, a command built from variables, or a
  path an inline script builds at run time (`'/'.join([...])`). A `$NAME` is replaced by its value only when an
  earlier `NAME=value` or `export NAME=value` in the same line gave it a literal value with no blanks or glob
  characters and surely ran (not after `&&`, `||`, in a subshell or pipeline, or inside `if`/loops), and nothing else
  in the line may change it; otherwise it stays unknown. A program name built at run time (`$a push`, `"$@"`) asks.
- **Inline code in other languages.** `python -c`, `node -e`, `perl -e`, `ruby -e`, `osascript -e` and the like are
  not read as shell commands: a `git push` or `rm` such code runs through `os.system`, `child_process` or `do shell
  script` is not seen.
- **Scripts written, then run.** A file written with one call and run with `sh file.sh` in the next. The write itself
  is checked for secrets, not for what the script will do.
- **Secrets split across lines or calls.** Each new line is scanned on its own.
- **Programs that act on their own.** A build tool, test runner or package `postinstall` script that pushes, deletes
  or phones home is not visible from the command line that started it.
- **Writes through variables.** An awk `print > f` whose file is a variable, or a sed script read from a file
  (`-f`), is treated as a writer when it names a protected path, but the file it writes is not known. A `git pull` in
  a folder above a skill folder (a home folder kept under git) is not treated as a write into it.
- **Globs that match dotfiles.** A `*` is taken not to match a leading dot, as in a default bash or zsh. With
  `dotglob` or `GLOB_DOTS` set, `rm -rf *` in a project also removes `.checkrein/`, and checkrein does not see that.
- **Case on mixed volumes.** Protected paths are compared ignoring case when a probe of the nearest existing folder
  shows its file system ignores case (macOS and Windows by default); git's `.git/hooks` and `.git/config` are judged
  by the path's own folder. A case-insensitive volume mounted below a case-sensitive protected root, or the reverse,
  is judged by the root's folder, and may be judged wrongly.
- **Time limit.** One check may take 5 seconds; past that the call is denied with a reason saying so.
- **Shell text checkrein will not read.** A command over 256 KB asks instead of being read; one that nests
  substitutions, quotes, `sh -c`, `eval` or shell stdin more than 64 levels deep is denied. Text piped into a shell
  is read when it is literal (`cat <<EOF`, `echo`/`printf` of plain words); anything else piped into a shell
  (`curl … | sh`, a file, a variable) asks, and so do `sh -c`, `eval`, `su -c`, `ssh` and `watch` given text built
  at run time (`bash -c "$(curl …)"`, `eval "$X"`) and `sh <(…)` or `source <(…)` of anything but literal text.
  After a `cd` that may not have taken effect (a subshell, a pipeline, `;` after it, a variable target) every
  folder it could leave a command in is checked, up to 32 folders and 1,024 characters per folder; past that the
  folder counts as unknown. A line that takes more than about a million reading steps (words, folders and variables
  together) is denied. `env -S` text that cannot be split exactly (an unclosed quote, an unknown escape, `${VAR}`)
  asks, and so does git shell text (`core.pager`, `GIT_SSH_COMMAND`, `rebase --exec`, …) built at run time. zsh's
  `${(e)…}` and glob qualifiers, and a variable holding an array subscript that arithmetic later evaluates, are not
  read as commands.
- **MCP servers' own side effects.** MCP01 and MCP02 see the call's name and input, not what the server does with it.
- **Tools with no command or file path.** Every tool call reaches the hook, but only Bash and any tool with a text
  `command` (Monitor, an unknown or MCP tool), the file tools (Write, Edit, MultiEdit, NotebookEdit) and MCP tools are
  judged. Read, Grep, Glob, WebFetch and the like pass unread.
- **A `python3` shim on PATH.** The hook runs `python3 -I -S`, so `PYTHON*` variables, `.pth` files and
  sitecustomize can't change it, but a `python3` placed earlier on PATH before the session starts runs instead of
  it. Settings and commands that change PATH, HOME or `PYTHON*` for the hook are refused (SLF01); a shim already in
  place is not seen.
- **Other ways into a skill or plugin folder.** SKL01 knows a fixed list of copy, download, clone and unpack
  commands. Other tools that write files can still bring a skill in: package installers with a target folder, cloud
  copy tools, `npx degit`-style fetchers, `gh release download`, `git subtree` or `git stash pop`, a patch applied
  inside the folder, and so on. Vetting with `/checkrein:vet` is the supported route. checkrein stops the common
  routes; it does not contain a model that is trying to get around it.
- **Hard links.** A hard link made to a protected file (`cp -l`, `rsync --link-dest`, `pax -l`) and then written
  through is not detected. Only `ln` and `link` are checked.
- **A repository can switch checkrein off.** Project settings take precedence. A committed `.claude/settings.json`
  that sets checkrein to false in `enabledPlugins`, or sets `disableAllHooks: true`, turns checkrein off when a
  session starts there. A git checkout, pull or merge mid-session that brings in such a file is not checked. Before
  you open a repository you don't trust with Claude Code, look at its `.claude/settings*.json`.
- **Git config includes and unusual git folders.** Files that git config pulls in with `include` or `includeIf` are
  not protected. Neither are git folders in non-standard places: `--separate-git-dir`, bare repositories, or
  `GIT_DIR` pointing elsewhere.
- **The hook's Python, beyond its files.** SLF01 protects python names on the hook's PATH, the interpreter file and
  the standard library, but not the interpreter's own library (the framework Python dylib, libpython), nor a whole
  folder above them replaced at once (`ln -sfn`, an unpack, or rsync into a PATH folder).
- **Installers that put a python3 on PATH.** pipx, `npm -g`, cargo, `go install` and `brew link` can place a program
  named python3 in a PATH folder without naming it on the command line; they are not checked for it.
- **conda environments.** `conda create -p <folder>` on a PATH folder is not read as making a Python there.
- **pyvenv.cfg.** On Python builds that are not macOS frameworks, a `pyvenv.cfg` beside the interpreter (or one
  folder up) changes where it looks for its library; writing one there is not checked.

## By design

- **No network.** The gate never fetches anything except the `git clone` you ask `vet` to make. No telemetry.
- **Pattern-based secret detection.** High-confidence token formats are denied; generic `key = "…"` patterns only
  ask, to keep false alarms down. A real secret in an unusual format can pass.
- **Plugin installs are bound after the fact.** Claude Code downloads a plugin again when you install it. checkrein
  approves the vetted source for one marketplace and, at every session start, checks the installed copy hashes to what
  was vetted (SKL05). A difference is reported each session until you re-vet it, not blocked.
- **Marketplace vetting covers what gets installed.** For a marketplace, `vet` scans the `.claude-plugin` folder and
  each plugin folder it points to, because those are all Claude Code copies to your machine. Tests, docs and other
  files beside them are left out. An entry that points at another repository is listed as not covered; vet that
  repository on its own.
- **Patterns are not actions.** A match that sits inside a regex pattern, on a line that only defines patterns, is
  reported as low: guards and scanners name what they look for. The same text anywhere else keeps its severity.
- **Static scan, not a full audit.** The built-in checks look for the common bad signs (pipe-to-shell, credential
  reads, persistence, hidden characters, binaries, symlinks out of the package). Without a third-party scanner, a
  verdict stops at REVIEW, never PASS.
- **A person can always turn it off.** checkrein stops the agent from loosening or disabling it (SLF01). You can still
  edit the files or disable the plugin yourself.

## Unattended runs

In `dontAsk` and `bypassPermissions` modes every `ask` becomes `deny`, because nobody can answer. If an unattended job
needs one of those actions, set that rule to `off` in your own config for that machine, knowingly.
