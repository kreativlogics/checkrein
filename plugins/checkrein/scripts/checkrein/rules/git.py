"""GIT01-GIT06: force pushes, discarded work, skipped hooks, shared-tree commands."""

import fnmatch
import os
import subprocess

from .. import context
from ..context import Hit, case_insensitive, env_of, git_globals, git_subcommand, inside, long_option, real_path, \
    same_path, write_targets
from .. import ledger
from .. import shell

HOOK_SKIP_ENV = {
    "HUSKY": ("0", "false"),
    "HUSKY_SKIP_HOOKS": None,
    "SKIP": None,  # pre-commit: SKIP=hook-id,...
    "LEFTHOOK": ("0", "false"),
    "PRE_COMMIT_ALLOW_NO_CONFIG": None,
    "GIT_HOOKS_SKIP": None,
    "LEFTHOOK_EXCLUDE": None,
}
# Programs that never run git, so a hook-skip variable set for them does nothing.
_NO_GIT = {"echo", "printf", "cat", "ls", "pwd", "true", "false", ":", "test", "[", "head", "tail", "wc", "grep"}
# Variables that change which config files git reads, and so which core.hooksPath applies.
_CONFIG_FILE_ENV = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG", "HOME",
                    "XDG_CONFIG_HOME")
# Subcommands that run hooks.
_HOOKED = ("commit", "merge", "rebase", "am", "cherry-pick", "revert", "pull", "push")
# --signed takes a value only as --signed=<v>; written alone it leaves the next word (--force) to be read.
_PUSH_VALUE = {"--repo", "--receive-pack", "--exec", "-o", "--push-option", "--recurse-submodules"}
_COMMIT_VALUE = "mFCcSt"  # -m msg, -F file, -C/-c commit, -S keyid (optional, but treat as value), -t template


def _opt(args, *names):
    """True when any arg is one of the long options names, written in full or as a prefix git accepts."""
    return any(long_option(a.split("=", 1)[0], n) for a in args for n in names)


def _short(args, letter, takes_value=""):
    return any(a.startswith("-") and not a.startswith("--") and letter in shell.short_flags(a, takes_value)
               for a in args)


def check(ctx):
    hits = []
    for cmd in ctx.parsed.cmds:
        env = env_of(cmd)
        hits.extend(_env_hook_skip(cmd, env))
        hits.extend(_env_hooks_path(env))
        if cmd.name == "export":
            exported = {}
            for a in cmd.args:
                if "=" in a:
                    k, v = a.split("=", 1)
                    exported[k] = v
                    if _skips_hooks(k, v):
                        hits.append(Hit("GIT04", "Sets %s, which turns off git hooks for later commands." % k))
            hits.extend(_env_hooks_path(exported))
            continue
        if cmd.name != "git":
            if cmd.name == "gh":
                hits.extend(_gh_api(cmd.args, ctx))
            hits.extend(_hooks_dir_writes(cmd, ctx))
            continue
        configs, cdir = git_globals(cmd.args)
        gcwd = ctx.path(cdir, cmd.cwd) if cdir else cmd.cwd or ctx.cwd
        for kv in configs:
            if _redirects_hooks(kv.split("=", 1)[0]):
                hits.append(Hit("GIT05", "Sets %s for this command, which can point core.hooksPath somewhere else "
                                         "and skip the repository's hooks." % kv.split("=", 1)[0].strip()))
        configs = configs + _env_configs(env)
        sub, args = git_subcommand(cmd.args)
        changed = [k for k in _CONFIG_FILE_ENV if k in env]
        if sub in _HOOKED and changed:
            hits.append(Hit("GIT05", "Sets %s, which points git at other config files, where a hooks path can "
                                     "skip the repository's hooks." % ", ".join(changed)))
        if sub == "push":
            hits.extend(_no_verify(sub, args))
            hits.extend(_push(args, gcwd, ctx, configs))
        elif sub == "send-pack":
            hits.extend(_push(args, gcwd, ctx, configs, from_config=False))
        elif sub == "reset" and _opt(args, "--hard"):
            hits.append(Hit("GIT02", "A hard reset throws away uncommitted changes."))
        elif sub == "checkout":
            hits.extend(_checkout(args))
        elif sub == "switch" and (_opt(args, "--discard-changes", "--force") or _short(args, "f", "cC")):
            hits.append(Hit("GIT02", "git switch --discard-changes throws away uncommitted changes."))
        elif sub == "clean":
            hits.extend(_clean(args, gcwd, configs))
        elif sub in ("commit", "merge", "rebase", "am", "cherry-pick", "revert", "pull"):
            hits.extend(_no_verify(sub, args))
            if sub == "commit":
                hits.extend(_commit_all(args))
        elif sub == "config":
            hits.extend(_config(args))
        elif sub == "stash" and (not args or args[0] not in ("list", "show")):
            hits.append(Hit("GIT06", "git stash takes changes out of a tree others may be working in."))
            hits.extend(_stash_untracked(args, gcwd or cmd.cwd or ctx.cwd, ctx))
        elif sub == "restore":
            staged = _opt(args, "--staged") or _short(args, "S", "s")
            worktree = _opt(args, "--worktree") or _short(args, "W", "s")
            if not (staged and not worktree):
                hits.append(Hit("GIT06", "git restore discards changes to files in the working tree."))
        elif sub == "add" and (any(a in (".", ":/") for a in args) or _opt(args, "--all", "--update")
                               or _short(args, "A") or _short(args, "u")):
            hits.append(Hit("GIT06", "git add with -A, -u or . stages changes you may not have made."))
        hits.extend(_hooks_dir_writes(cmd, ctx))
    for target in _tool_targets(ctx):
        if _hooks_path(target):
            hits.append(Hit("GIT05", "Writes into .git/hooks, which changes what runs on every commit."))
            continue
        config = _config_path(target, ctx)
        if config:
            hits.extend(_config_file_edit(ctx, config))
    return hits


# Largest git config file read to compare its hook settings before and after an edit.
_CONFIG_LIMIT = 1024 * 1024
_CONFIG_KEYS_CHANGED = ("Changes core.hooksPath, include.path or includeIf.*.path in %s, which decides which git "
                        "hooks run.")


def _config_file_edit(ctx, path):
    """A Write or Edit of a git config file that adds, changes or removes a setting deciding which hooks run."""
    try:
        old = ledger.read_regular(path, _CONFIG_LIMIT)
    except FileNotFoundError:
        old = ""
    except (OSError, ValueError):
        return [Hit("GIT05", "Edits the git config file %s, which checkrein cannot read to compare its hook "
                             "settings. A person confirms this." % path, level="ask")]
    new = _edited_text(ctx, old)
    if new is None or _hook_settings(old) == _hook_settings(new):
        return []
    return [Hit("GIT05", _CONFIG_KEYS_CHANGED % path)]


def _edited_text(ctx, old):
    """The file's text after this Write, Edit or MultiEdit; None when an edit's old text isn't in the file (Claude
    Code then refuses it) or the tool is not one of those."""
    ti = ctx.tool_input
    if ctx.tool_name == "Write":
        content = ti.get("content")
        return content if isinstance(content, str) else ""
    if ctx.tool_name == "Edit":
        edits = [ti]
    elif ctx.tool_name == "MultiEdit":
        edits = [e for e in ti.get("edits") or [] if isinstance(e, dict)]
    else:
        return None
    text = old
    for e in edits:
        before, after = e.get("old_string"), e.get("new_string")
        if not isinstance(before, str) or not isinstance(after, str) or not before or before not in text:
            return None
        text = text.replace(before, after) if e.get("replace_all") else text.replace(before, after, 1)
    return text


def _hook_settings(text):
    """The core.hooksPath, include.path and includeIf.*.path entries of git config text, in order, as
    (section header, key, value)."""
    out = []
    section = ""
    lines = text.replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        # A value continues on the next line after a trailing backslash.
        while line.endswith("\\") and (len(line) - len(line.rstrip("\\"))) % 2 and i < len(lines):
            line = line[:-1] + lines[i]
            i += 1
        rest = line.strip()
        if rest.startswith("["):
            end = rest.find("]")
            section = rest[1:end if end >= 0 else len(rest)].strip()
            rest = rest[end + 1:].strip() if end >= 0 else ""
        if not rest or rest[0] in "#;":
            continue
        key, _eq, value = rest.partition("=")
        key = key.strip().lower()
        base = section.split(None, 1)[0].split(".", 1)[0].lower() if section else ""
        if (base == "core" and key == "hookspath") or (base in ("include", "includeif") and key == "path"):
            out.append((section, key, value.strip()))
    return out


def _parts(path):
    """The path's parts, in lower case where its file system ignores case (git's own names then match any
    case: .GIT/HOOKS is .git/hooks there)."""
    parts = os.path.normpath(path).split(os.sep)
    try:
        fold = case_insensitive(path)
    except (ValueError, OSError):
        fold = True
    return [p.lower() for p in parts] if fold else parts


def _in_hooks_dir(path):
    """A path in .git/hooks, or a submodule's .git/modules/<name>/hooks (submodules nest: modules/a/modules/b)."""
    if ".git" not in path.lower():
        return False
    parts = _parts(path)
    for i in range(len(parts) - 1):
        if parts[i] != ".git":
            continue
        j = i + 1
        while j + 2 < len(parts) and parts[j] == "modules":
            if parts[j + 2] == "hooks":
                return True
            j += 2
        if parts[i + 1] == "hooks":
            return True
    return False


# System config files git reads, by install: /etc, Homebrew and /usr/local builds.
_SYSTEM_CONFIGS = ("/etc/gitconfig", "/usr/local/etc/gitconfig", "/opt/homebrew/etc/gitconfig")


def _is_git_config(path, ctx):
    """A repository's config or config.worktree (any worktree or submodule), or the user's or system's config."""
    if ".git" in path.lower():
        parts = _parts(path)
        if parts[-1] in ("config", "config.worktree") and ".git" in parts[:-1]:
            return True
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(ctx.home, ".config")
    files = (os.path.join(ctx.home, ".gitconfig"), os.path.join(xdg, "git", "config"),
             os.path.join(ctx.home, ".config", "git", "config")) + _SYSTEM_CONFIGS
    return os.path.basename(path).lower() in ("config", ".gitconfig", "gitconfig") and \
        any(same_path(path, f) for f in files)


def _redirects_hooks(key):
    """True for config keys that set core.hooksPath or pull in another config file that can set it."""
    key = key.strip().lower()
    return key in ("core.hookspath", "include.path") or (key.startswith("includeif.") and key.endswith(".path"))


def _env_hooks_path(env):
    """GIT_CONFIG_KEY_<n> or GIT_CONFIG_PARAMETERS naming core.hooksPath or an include set it for git runs."""
    for k, v in env.items():
        if (k.startswith("GIT_CONFIG_KEY_") and _redirects_hooks(v)) or (
                k == "GIT_CONFIG_PARAMETERS" and ("core.hookspath" in v.lower() or ".path" in v.lower())):
            return [Hit("GIT05", "%s sets %s, which can point core.hooksPath somewhere else and skip the "
                                 "repository's hooks." % (k, v.strip() if k != "GIT_CONFIG_PARAMETERS" else "config"))]
    return []


def _tool_targets(ctx):
    if ctx.tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        fp = ctx.file_path()
        return [fp] if fp else []
    return []


def _skips_hooks(key, value):
    if key not in HOOK_SKIP_ENV:
        return False
    falsy = HOOK_SKIP_ENV[key]
    if falsy is None:
        return value != ""
    return value.lower() in falsy


def _env_hook_skip(cmd, env):
    hits = []
    for k, v in env.items():
        if not _skips_hooks(k, v) or cmd.name in _NO_GIT:
            continue
        if cmd.name in ("git", "npm", "yarn", "pnpm", "bun", "npx"):
            hits.append(Hit("GIT04", "%s=%s turns off git hooks for this command." % (k, v)))
        else:
            # Scripts, make targets and git front ends run git themselves, with this variable set.
            hits.append(Hit("GIT04", "%s=%s turns off git hooks for git commands that %s may run." % (k, v, cmd.name),
                            level="ask"))
    return hits


def current_branch(cwd):
    try:
        res = subprocess.run(["git", "symbolic-ref", "--quiet", "--short", "HEAD"], cwd=cwd,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3,
                             universal_newlines=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout.strip() or None


def _protected(branch, patterns):
    if not branch:
        return False
    # git reads a partial ref (heads/master) as refs/heads/master.
    b = branch
    for prefix in ("refs/heads/", "heads/"):
        if b.startswith(prefix):
            b = b[len(prefix):]
            break
    return any(fnmatch.fnmatch(b, pat) for pat in patterns)


def _softer(level):
    return "ask" if level == "deny" else level


def _env_configs(env):
    """key=value pairs that GIT_CONFIG_COUNT / GIT_CONFIG_KEY_<n> / GIT_CONFIG_VALUE_<n> set for this command."""
    out = []
    for k, v in (env or {}).items():
        if k.startswith("GIT_CONFIG_KEY_"):
            out.append("%s=%s" % (v, env.get("GIT_CONFIG_VALUE_" + k[len("GIT_CONFIG_KEY_"):], "")))
    return out


def config_values(key, configs, cwd):
    """Values of a git config key for a command: the repository's and user's config, then -c pairs, in the order
    git reads them (the last one wins for single-valued keys)."""
    values = []
    try:
        res = subprocess.run(["git", "config", "--get-all", key], cwd=cwd or None, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=3, universal_newlines=True)
        values.extend(v for v in res.stdout.splitlines() if res.returncode == 0)
    except (OSError, subprocess.SubprocessError):
        pass
    for kv in configs:
        k, eq, v = kv.partition("=")
        if _same_key(k.strip(), key):
            values.append(v if eq else "true")
    return values


def _same_key(a, b):
    # Section and variable names ignore case; a subsection (the remote's name) does not.
    sa, sb = a.split("."), b.split(".")
    if len(sa) != len(sb) or len(sa) < 2:
        return False
    return sa[0].lower() == sb[0].lower() and sa[-1].lower() == sb[-1].lower() and sa[1:-1] == sb[1:-1]


def _is_true(value):
    return (value or "").strip().lower() in ("true", "yes", "on", "1", "")


def _push(args, cwd, ctx, configs=(), from_config=True):
    force = lease = delete = mirror = every = prune = False
    words = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in _PUSH_VALUE or (a.startswith("--") and "=" not in a and any(
                long_option(a, v, 3) for v in _PUSH_VALUE if v.startswith("--"))):
            skip = True
            continue
        opt = a.split("=", 1)[0]
        if a == "-f" or long_option(a, "--force", 3):
            force = True
        elif long_option(opt, "--force-with-lease", 7) or long_option(opt, "--force-if-includes", 7):
            lease = True
        elif a == "-d" or long_option(a, "--delete", 2):
            delete = True
        elif long_option(a, "--mirror", 2):
            mirror = True
        elif long_option(a, "--prune", 3):
            prune = True
        elif long_option(a, "--all", 2) or long_option(a, "--branches", 2):
            every = True
        elif a.startswith("--"):
            continue
        elif a.startswith("-"):
            letters = shell.short_flags(a, "o")
            force = force or "f" in letters
            delete = delete or "d" in letters
        else:
            words.append(a)
    refspecs = words[1:]
    if from_config and not refspecs and not (every or mirror):
        # With no refspec, git pushes what remote.<name>.push says, and mirrors when remote.<name>.mirror is set.
        remote = words[0] if words else "origin"
        if "/" not in remote and ":" not in remote:
            mirror_values = config_values("remote.%s.mirror" % remote, configs, cwd)
            mirror = bool(mirror_values) and _is_true(mirror_values[-1])
            refspecs = config_values("remote.%s.push" % remote, configs, cwd)
    protected = ctx.eff.get("protected_branches") or []
    targets = []
    for spec in refspecs:
        plus = spec.startswith("+")
        spec = spec.lstrip("+")
        if spec.startswith(":"):
            targets.append((spec[1:], "delete"))
            continue
        dst = spec.split(":", 1)[1] if ":" in spec else spec
        if _unreadable(dst):
            targets.append((_UNREADABLE, "force" if plus else None))
            continue
        if dst in ("HEAD", "@"):
            dst = current_branch(cwd) or dst
        if "*" in dst:
            # A wildcard refspec pushes every matching branch, the protected ones among them; with --prune it
            # deletes those with no local branch.
            kind = "delete" if prune else "force" if plus else None
            targets.extend((b, kind) for b in protected or ["every branch"])
            continue
        targets.append((dst, "force" if plus else None))
    if every or mirror:
        # Every local branch is pushed, so judge it as if each protected branch were named; --prune deletes the
        # remote ones with no local branch.
        kind = "delete" if prune else None
        targets = [(b, kind) for b in protected] or [("every branch", kind)]
    elif not refspecs:
        targets.append((current_branch(cwd), None))

    level = ctx.eff.level("GIT01")
    hits = []
    if mirror:
        hits.append(Hit("GIT01", "A mirror push overwrites and deletes every branch on the remote."))
    for branch, kind in targets:
        is_del = delete or kind == "delete"
        is_force = force or kind == "force"
        is_prot = _protected(branch, protected) or branch is _UNREADABLE
        name = branch or "the current branch"
        if is_del:
            hits.append(Hit("GIT01", "Deletes the remote branch %s." % name, level="deny" if is_prot else None))
        elif is_force:
            if is_prot:
                hits.append(Hit("GIT01", "Force push to the protected branch %s." % name, level="deny"))
            else:
                hits.append(Hit("GIT01", "Force push to %s rewrites its history on the remote." % name))
        elif lease:
            if is_prot:
                hits.append(Hit("GIT01", "Force push (with lease) to the protected branch %s." % name,
                                level=None if level == "off" else level))
            else:
                hits.append(Hit("GIT01", "Force push (with lease) to %s." % name, level=_softer(level)))
    return hits


_GH_METHOD_OPTS = ("-X", "--method")
_GH_REF = "git/refs/heads/"


def _gh_api(args, ctx):
    """gh api DELETE or PATCH on repos/<o>/<r>/git/refs/heads/<branch>: deletes or moves (force=true) a branch."""
    if not args or args[0] != "api":
        return []
    method = ""
    endpoints = []
    i = 1
    while i < len(args):
        a = args[i]
        if a in _GH_METHOD_OPTS and i + 1 < len(args):
            method = args[i + 1]
            i += 2
            continue
        if a.startswith("--method="):
            method = a.split("=", 1)[1]
        elif a.startswith("-X") and len(a) > 2:
            method = a[2:]
        elif _GH_REF in a:
            endpoints.append(a)
        i += 1
    if method.upper() not in ("DELETE", "PATCH"):
        return []
    protected = ctx.eff.get("protected_branches") or []
    hits = []
    for endpoint in endpoints:
        branch = endpoint.split(_GH_REF, 1)[1].split("?", 1)[0].rstrip("/")
        prot = _unreadable(branch) or _protected(branch, protected)
        what = "Deletes" if method.upper() == "DELETE" else "Moves (can force)"
        hits.append(Hit("GIT01", "%s the remote branch %s through the GitHub API." % (
            what, _UNREADABLE if _unreadable(branch) else branch), level="deny" if prot else None))
    return hits


# A branch named by a variable or command: checkrein can't tell which, so it may be a protected one.
_UNREADABLE = "a branch named by a variable or command"


def _unreadable(name):
    return any(t in name for t in ("__SUBST__", "$", "`", "{", "}"))


def _checkout(args):
    if _opt(args, "--force") or _short(args, "f", "bB"):
        return [Hit("GIT02", "git checkout -f throws away uncommitted changes.")]
    if "--" in args:
        idx = args.index("--")
        if args[idx + 1:]:
            return [Hit("GIT06", "git checkout -- <path> discards changes to those files.")]
    if args == ["."]:
        return [Hit("GIT06", "git checkout . discards changes to every file.")]
    return []


def _clean(args, cwd=None, configs=()):
    letters = ""
    dry = False
    for a in args:
        if long_option(a, "--force", 2):
            letters += "f"
        elif long_option(a, "--dry-run", 2):
            dry = True
        elif a.startswith("-") and not a.startswith("--"):
            fl = shell.short_flags(a, "e")
            letters += fl
            dry = dry or "n" in fl
    if "f" in letters and not dry:
        return [Hit("GIT03", "git clean -f deletes untracked files for good.")]
    if not dry and "i" not in letters and not any(long_option(a, "--interactive", 3) for a in args):
        # Without -f git refuses to clean, unless clean.requireForce is false.
        values = config_values("clean.requireForce", configs, cwd)
        if values and not _is_true(values[-1]):
            return [Hit("GIT03", "git clean deletes untracked files for good (clean.requireForce is false).")]
    return []


_STASH_SAVES = ("push", "save")


def _stash_untracked(args, cwd, ctx):
    """git stash -u or -a removes untracked files from the working tree. Ask when checkrein's own files or a
    settings file it is switched on in are among them (an untracked .checkrein/ or project Claude settings file)."""
    if args and not args[0].startswith("-") and args[0] not in _STASH_SAVES:
        return []
    every = _opt(args, "--all") or _short(args, "a", "m")
    if not (every or _opt(args, "--include-untracked") or _short(args, "u", "m")):
        return []
    top = _repo_top(cwd) if cwd else None
    if not top:
        return []
    mine = [ctx.data_dir, ctx.plugin_root] + context.settings_files(ctx)
    if ctx.project_dir:
        mine.append(os.path.join(ctx.project_dir, ".checkrein"))
    mine = [p for p in mine if p and inside(p, top) and os.path.lexists(p)]
    if not mine:
        return []
    found = _untracked(top, mine, every)
    if found is None or found:
        what = ", ".join(sorted(found)) if found else "files checkrein reads"
        return [Hit("GIT03", "git stash with untracked files takes %s out of the working tree, which turns checkrein's "
                             "settings off until it is popped." % what, level="ask")]
    return []


def _untracked(top, paths, ignored_too):
    """The paths git counts as untracked (ignored ones too when ignored_too), as names below top, or None when
    git can't tell."""
    cmd = ["git", "ls-files", "--others", "--directory", "-z"]
    if not ignored_too:
        cmd.append("--exclude-standard")
    try:
        res = subprocess.run(cmd + ["--"] + [os.path.relpath(p, top) for p in paths], cwd=top,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, universal_newlines=True)
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return [n.rstrip("/") for n in res.stdout.split("\0") if n]


def _no_verify(sub, args):
    if any(long_option(a, "--no-verify", 4) for a in args):
        return [Hit("GIT04", "--no-verify skips the repository's git hooks.")]
    if sub == "commit":
        for a in args:
            if a.startswith("-") and not a.startswith("--") and "n" in shell.short_flags(a, _COMMIT_VALUE):
                return [Hit("GIT04", "git commit -n skips the repository's git hooks.")]
    return []


def _commit_all(args):
    for a in args:
        if long_option(a, "--all", 3) or (a.startswith("-") and not a.startswith("--") and "a" in shell.short_flags(a, _COMMIT_VALUE)):
            return [Hit("GIT06", "git commit -a commits every changed tracked file, including other people's.")]
    return []


_CONFIG_VALUE = ("--file", "--blob", "--type", "--default", "--comment", "--value")
_CONFIG_READ = ("--get", "--get-all", "--get-regexp", "--get-urlmatch", "--get-color", "--get-colorbool", "--list",
                "--show-origin", "--show-scope", "--name-only")
_CONFIG_SUBS = {"set", "unset", "get", "list", "edit", "rename-section", "remove-section"}


def _config(args):
    words = []
    reading = unset = section = False
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        opt = a.split("=", 1)[0]
        if a in ("-f", "--file") or (a.startswith("--") and "=" not in a and any(
                long_option(a, v, 3) for v in _CONFIG_VALUE)):
            skip = True
            continue
        if a.startswith("--"):
            reading = reading or any(long_option(opt, r, 5) for r in _CONFIG_READ)
            unset = unset or long_option(opt, "--unset", 3) or long_option(opt, "--unset-all", 7)
            section = section or long_option(opt, "--remove-section", 4) or long_option(opt, "--rename-section", 4)
            continue
        if a.startswith("-") and len(a) > 1:
            reading = reading or a == "-l"
            continue
        words.append(a)
    if words[:1] and words[0] in _CONFIG_SUBS:
        sub = words.pop(0)
        reading = sub in ("get", "list")
        unset = unset or sub == "unset"
        section = section or sub in ("remove-section", "rename-section")
    if section and words and (words[0].lower() in ("core", "include") or words[0].lower().startswith("includeif.")):
        return [Hit("GIT05", "Removes or renames the [%s] config section, which holds core.hooksPath or pulls in "
                             "a config file that can set it." % words[0])]
    if words and not section and _redirects_hooks(words[0]) and not reading and (len(words) >= 2 or unset):
        return [Hit("GIT05", "Changes %s, which decides which git hooks run." % words[0])]
    return []


def _hooks_dir_writes(cmd, ctx):
    hits = []
    for path, _kind in write_targets(cmd, ctx):
        if _hooks_path(path):
            hits.append(Hit("GIT05", "Changes files in .git/hooks, which decides what runs on every commit."))
            break
        config = _config_path(path, ctx)
        if config:
            text = ctx.command.lower()
            if "hookspath" in text or "include" in text:
                hits.append(Hit("GIT05", "Writes core.hooksPath or an include into the git config, which decides "
                                         "which git hooks run."))
            else:
                # A copy, move, truncation or in-place edit can drop or change core.hooksPath unseen.
                hits.append(Hit("GIT05", "Replaces or edits the git config file %s from the shell, which can change "
                                         "core.hooksPath. A person confirms this." % config, level="ask"))
            break
    if not hits:
        hits.extend(_links_to_hooks(cmd, ctx))
    if not hits:
        hits.extend(_found_writes(cmd, ctx))
    return hits


def _hooks_path(path):
    """True for a path in .git/hooks, as written or once its symlinks are followed (a link gh -> .git/hooks)."""
    if _in_hooks_dir(path):
        return True
    try:
        real = real_path(path)
    except (OSError, ValueError):
        return False
    return real != path and _in_hooks_dir(real)


def _config_path(path, ctx):
    """The git config file path is, as written or once its symlinks are followed, or None."""
    if _is_git_config(path, ctx):
        return path
    try:
        real = real_path(path)
    except (OSError, ValueError):
        return None
    return real if real != path and _is_git_config(real, ctx) else None


def _links_to_hooks(cmd, ctx):
    """ln making a link to .git/hooks, a hook or a git config: writes through the link reach them."""
    if cmd.name not in ("ln", "gln"):
        return []
    words = [w for w in cmd.args if not w.startswith("-")]
    for view in context.at_each_cwd(cmd):
        for w in words:
            path = ctx.path(w, view.cwd)
            if _hooks_path(path) or _config_path(path, ctx):
                return [Hit("GIT05", "Links to %s, so writes through the link change the git hooks or the git "
                                     "config. A person confirms this." % w, level="ask")]
    return []


# Names git runs as hooks (githooks(5)), the hooks folder and the config files: a find name test matching one of
# them can reach them.
_HOOK_NAMES = ("applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
               "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge",
               "pre-push", "pre-receive", "update", "proc-receive", "post-receive", "post-update",
               "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate",
               "fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit",
               "post-index-change", "hooks", "config", "config.worktree")
_NAME_TESTS = {"-name": False, "-iname": True}


def _found_writes(cmd, ctx):
    """Writers acting on folders recursively or on paths find or ls produces (find -delete, find -exec, xargs,
    rm -r), where those folders hold .git/hooks or a git config and the name tests can reach them."""
    if _spares_hooks(cmd):
        return []
    folders = []
    recursive = getattr(context, "recursive_targets", None)
    if recursive is not None:
        folders.extend(recursive(cmd, ctx))
    roots = getattr(cmd, "found_roots", ())
    if roots and write_targets(cmd, ctx):
        names = _found_names(getattr(cmd, "found_predicates", ()))
        for view in context.at_each_cwd(cmd):
            folders.extend((ctx.path(r, view.cwd), names) for r in roots)
    for folder, names in folders:
        if _hooks_path(folder) or _config_path(folder, ctx):
            return [Hit("GIT05", "Changes files in .git/hooks or the git config through %s, which decides what "
                                 "runs on every commit." % folder)]
        if _names_reach(names) and _holds_hooks(folder, cmd, ctx):
            return [Hit("GIT05", "Acts on files found under %s, which holds .git/hooks and the git config. A person "
                                 "confirms this." % folder, level="ask")]
    return []


def _spares_hooks(cmd):
    """True when a recursive or found-path writer cannot change a hook or a config file: chmod that can't take x
    away (+x, u+w, 755), and find -type d -delete, which removes only empty folders."""
    if cmd.name == "chmod":
        removes = context.chmod_removes(cmd.args)
        return removes is not None and "x" not in removes
    if cmd.name in ("find", "gfind"):
        return context.find_spares_files(list(cmd.args))
    return False


def _found_names(predicates):
    """find's name tests as (pattern, ignore_case), or None when any name can be found (no name test, or a path,
    regex, negated or ls listing widens them)."""
    names = []
    for test, value in predicates:
        if test in _NAME_TESTS:
            names.append((value, _NAME_TESTS[test]))
        elif test not in ("-type", "-o", "-or"):
            return None
    return tuple(names) or None


def _names_reach(names):
    """True when a found name may be a hook, the hooks folder or a config file."""
    if names is None:
        return True
    for pattern, fold in names:
        pat = pattern.lower() if fold else pattern
        if any(fnmatch.fnmatchcase(n, pat) for n in _HOOK_NAMES):
            return True
    return False


def _holds_hooks(folder, cmd, ctx):
    """True when folder is in a .git folder, holds one, or holds the repository the command runs in."""
    if ".git" in _parts(folder) or os.path.isdir(os.path.join(folder, ".git")):
        return True
    top = _repo_top(cmd.cwd or ctx.cwd)
    return bool(top) and inside(top, folder)


# The repository folder found for each folder, for this hook call.
_REPO_TOPS = {}


def _repo_top(folder):
    """The nearest folder at or above folder that holds .git, or None."""
    if folder in _REPO_TOPS:
        return _REPO_TOPS[folder]
    found, here = None, folder
    for _ in range(64):
        if os.path.exists(os.path.join(here, ".git")):
            found = here
            break
        up = os.path.dirname(here)
        if up == here:
            break
        here = up
    _REPO_TOPS[folder] = found
    return found
