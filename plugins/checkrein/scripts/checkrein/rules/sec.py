"""SEC01-SEC03: secrets in written content, in shell commands, and in staged changes."""

import json
import os
import shutil
import subprocess
import tempfile

from ..context import Hit, git_globals, git_subcommand, matches_globs
from .. import secrets
from .. import shell

_FIX = (" Keep the value in an environment variable or a secret store. If this file is meant to hold it "
        "(a git-ignored .env), add the path to secret_ignore_paths in your own config.")


def check(ctx):
    hits = []
    if ctx.tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        hits.extend(_content(ctx))
    elif ctx.tool_name == "Bash":
        hits.extend(_command(ctx))
        hits.extend(_staged(ctx))
    return hits


def _ignored(ctx, path):
    globs = ctx.eff.get("secret_ignore_paths") or []
    return bool(globs) and matches_globs(path, globs, ctx.project_dir)


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(5 * 1024 * 1024)
    except OSError:
        return ""


def _content(ctx):
    path = ctx.file_path()
    if path and _ignored(ctx, path):
        return []
    ti = ctx.tool_input
    found = []
    if ctx.tool_name == "Write":
        found = secrets.scan_added(_read(path) if path else "", ti.get("content") or "")
    elif ctx.tool_name == "Edit":
        found = secrets.scan_added(ti.get("old_string") or "", ti.get("new_string") or "")
    elif ctx.tool_name == "MultiEdit":
        for edit in ti.get("edits") or []:
            if isinstance(edit, dict):
                found.extend(secrets.scan_added(edit.get("old_string") or "", edit.get("new_string") or ""))
    elif ctx.tool_name == "NotebookEdit":
        found = secrets.scan_text(ti.get("new_source") or "")
    return _hits("SEC01", "The content being written", found, os.path.basename(path or ""))


def _hits(rule, what, found, where=""):
    if not found:
        return []
    high = [h for h in found if h.confidence == secrets.HIGH]
    shown = high or found
    kinds = sorted(set(h.label for h in shown))
    lines = sorted(set(h.line for h in shown))
    loc = (" in %s" % where if where else "") + (" (line %s)" % ", ".join(str(n) for n in lines[:5]) if lines else "")
    reason = "%s contains what looks like a %s%s." % (what, " and a ".join(kinds), loc)
    if rule == "SEC01":
        reason += _FIX
    # Generic patterns (assigned values, URL passwords) guess; they ask at most.
    return [Hit(rule, reason, cap=None if high else "ask")]


# Words longer than this that appear in the raw text as typed are not scanned a second time.
_SCANNED_WORD = 256


def _shell_words(ctx):
    """The command's words as the shell passes them on: quotes removed, so a'b'c reads as abc. A long word typed
    as it stands was read in the raw text already and is left out, so a large command isn't scanned twice."""
    lines = []
    raw = ctx.command or ""
    for cmd in ctx.parsed.cmds:
        words = ["%s=%s" % kv for kv in sorted((cmd.env or {}).items())] + list(cmd.argv)
        words.extend(t for _op, t in cmd.redirects)
        lines.append(" ".join(w for w in words if not (len(w) > _SCANNED_WORD and w in raw)))
    return "\n".join(lines)


def _command(ctx):
    found = []
    # The raw text first (its line numbers match what was typed), then the words with quotes joined, so a token
    # split by quotes (ab''cd) is still seen.
    for text in (ctx.command, _shell_words(ctx)):
        found = [h for h in secrets.scan_text(text) if h.confidence == secrets.HIGH or h.kind == "url-password"]
        if found:
            break
    if not found:
        return []
    hits = _hits("SEC02", "This command", found)
    hits[0].reason += " Commands end up in shell history, logs and transcripts; read the value from an " \
                      "environment variable instead."
    return hits


def _staged(ctx):
    if ctx.eff.level("SEC03") == "off":
        return []
    hits = []
    for cmd in ctx.parsed.cmds:
        if cmd.name != "git":
            continue
        sub, args = git_subcommand(cmd.args)
        if sub != "commit":
            continue
        _configs, cdir = git_globals(cmd.args)
        cwd = ctx.path(cdir, cmd.cwd) if cdir else cmd.cwd or ctx.cwd
        include_worktree = "--all" in args or any(
            "a" in shell.short_flags(a, "mFCcSt") for a in args)
        paths = _commit_pathspecs(args)
        if paths is not None and not include_worktree:
            # git commit <paths> (and -i, --only) commits the named files as they are in the working tree,
            # staged or not.
            include_worktree = paths or True
        hits.extend(scan_staged(ctx, cwd, include_worktree))
    return hits


# git commit options that take a value as the next word.
_COMMIT_VALUES = {"-m", "--message", "-F", "--file", "-C", "--reuse-message", "-c", "--reedit-message", "--author",
                  "--date", "-t", "--template", "--cleanup", "--fixup", "--squash", "--trailer"}


def _commit_pathspecs(args):
    """The paths git commit takes from the working tree: its pathspecs, [] for -i, -o or --pathspec-from-file
    without a list read here, or None when it commits only what is staged."""
    paths = []
    whole = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            paths.extend(args[i + 1:])
            break
        if a in _COMMIT_VALUES:
            i += 2
            continue
        if a in ("-i", "--include", "-o", "--only") or a.startswith("--pathspec-from-file"):
            whole = True
        elif a.startswith("-") and not a.startswith("--") and len(a) > 1:
            letters = shell.short_flags(a, "mFCcSt")
            if "i" in letters or "o" in letters:
                whole = True
            if letters and letters[-1:] in ("m", "F", "C", "c", "t") and a.endswith(letters[-1]) and \
                    a.lstrip("-") == letters:
                i += 2  # -am msg: the last letter takes the next word.
                continue
        elif not a.startswith("-"):
            paths.append(a)
        i += 1
    if paths:
        return paths
    return [] if whole else None


def scan_staged(ctx, cwd, include_worktree=False):
    """Secrets in what a commit takes in: the index, plus the working tree when include_worktree is true or a
    list of paths (only those)."""
    paths = include_worktree if isinstance(include_worktree, list) else None
    choice = ctx.eff.get("secret_scanner") or "auto"
    gitleaks = shutil.which("gitleaks") if choice in ("auto", "gitleaks") else None
    if choice == "gitleaks" and not gitleaks:
        return [Hit("SEC03", "secret_scanner is set to gitleaks, but gitleaks is not installed.", level="ask")]
    found = []
    if gitleaks:
        count = _gitleaks(gitleaks, cwd)
        if count:
            found.append("%d finding(s) from gitleaks" % count)
    # The built-in scan runs with gitleaks too: it reads files .gitattributes marks binary or -diff, which
    # gitleaks's staged scan skips.
    found.extend(_builtin(ctx, cwd, staged=True))
    if include_worktree:
        found.extend(_builtin(ctx, cwd, staged=False, paths=paths))
    return _staged_hits(found)


def _staged_hits(found):
    if not found:
        return []
    return [Hit("SEC03", "The changes being committed contain what looks like a secret: %s. Remove it from the "
                         "files, then stage them again." % "; ".join(found[:5]))]


def _gitleaks(binary, cwd):
    fd, report = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        res = subprocess.run([binary, "git", "--staged", "--redact", "--no-banner", "--report-format", "json",
                              "--report-path", report, "--exit-code", "3"], cwd=cwd, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, timeout=12)
        if res.returncode not in (0, 3):
            return None  # Older gitleaks or another failure: use the built-in scan.
        try:
            with open(report) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            data = []
        return len(data) if isinstance(data, list) else 0
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        try:
            os.unlink(report)
        except OSError:
            pass


_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _unquote_path(name):
    """Undo git's C-style quoting of a diff path ("b/t\\303\\251st.txt")."""
    if len(name) < 2 or not (name.startswith('"') and name.endswith('"')):
        return name
    body, out, i = name[1:-1], bytearray(), 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            digits = body[i + 1:i + 4]
            if len(digits) == 3 and all(c in "01234567" for c in digits):
                out.append(int(digits, 8) & 0xFF)
                i += 4
                continue
            if nxt in _C_ESCAPES:
                out.append(_C_ESCAPES[nxt])
                i += 2
                continue
        out.extend(ch.encode("utf-8"))
        i += 1
    return out.decode("utf-8", "replace")


def _builtin(ctx, cwd, staged, paths=None):
    # Pin the path prefixes: diff.noprefix or diff.mnemonicPrefix in the user's git config would otherwise change
    # the "+++ b/" lines this parser reads, and the check would find nothing. --text and --no-textconv show files
    # that .gitattributes marks binary, -diff or textconv as they are.
    cmd = ["git", "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false", "diff", "-U0", "--no-color",
           "--no-ext-diff", "--text", "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/"]
    if staged:
        cmd.insert(6, "--cached")
    if paths:
        cmd.append("--")
        cmd.extend(paths)
    try:
        res = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8,
                             universal_newlines=True, errors="replace")
    except (OSError, subprocess.SubprocessError):
        return []
    out = []
    current = None
    for line in res.stdout.splitlines():
        if line.startswith("+++ "):
            name = line[4:]
            if name.endswith("\t"):
                name = name[:-1]  # Git ends a name holding a space with a tab; a real tab would be quoted.
            name = _unquote_path(name)
            current = name[2:] if name.startswith("b/") else None
            continue
        if not line.startswith("+") or current is None:
            continue
        if _ignored(ctx, os.path.join(cwd, current)):
            continue
        for hit in secrets.scan_text(line[1:]):
            if hit.confidence == secrets.HIGH or hit.kind == "url-password":
                out.append("%s in %s" % (hit.label, current))
    return sorted(set(out))
