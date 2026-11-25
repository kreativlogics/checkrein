"""SLF01: checkrein's own files, config, approvals and ledger.

The agent may read them. Changes go through checkrein's own commands, which a
person confirms, or through the person editing files themselves.
"""

import json
import os
import re
import site
import sys
import sysconfig

from ..context import (Hit, at_each_cwd, awk_writes_or_runs, case_insensitive, claude_dir, cwds, env_of, git_globals,
                       git_subcommand, inside, long_option, real_path, recursive_touches, replaces, same_path,
                       sed_in_place, sed_writes_or_runs, settings_files, unknown_relative, write_targets)
from .. import globs
from .. import ledger
from .. import runners
from .. import shell
from .skl import is_checkrein, is_own_tool, own_checkrein, own_marketplaces, own_tool_shape, own_tool_subcommand, \
    plugin_call

READ_ONLY = {"cat", "less", "more", "head", "tail", "ls", "stat", "file", "wc", "grep", "egrep", "fgrep", "rg",
             "ag", "find", "fd", "diff", "cmp", "shasum", "sha256sum", "md5", "md5sum", "jq", "bat", "tree",
             "du", "readlink", "realpath", "basename", "dirname", "test", "[", "echo", "printf", "column",
             "sort", "uniq", "cut", "awk", "sed", "git", "pwd", "true", ":"}
CFG_MUTATING = {"set", "unset", "approve", "init"}
# find actions that delete, run or write files.
_FIND_ACTIONS = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"}
# Environment that makes a reader run a command (less's input filter, git's pager or diff tool).
_RUNNER_ENV = {"LESSOPEN", "LESSCLOSE", "PAGER", "GIT_PAGER", "GIT_EXTERNAL_DIFF", "GIT_EDITOR", "GIT_SSH_COMMAND"}
# Interpreters whose script may come from a heredoc or here-string on stdin.
_INTERPRETER = re.compile(r"^(python[0-9.]*|pypy[0-9.]*|node|nodejs|ruby|perl[0-9.]*|php[0-9.]*|deno|bun|osascript|"
                          r"lua[0-9.]*|luajit|Rscript|tclsh[0-9.]*|pwsh|powershell|swift|julia|ts-node|tsx)$")
# Editors and rewriters: run in a folder holding a settings file, they may change it by a name built at run time.
_EDITORS = {"vim", "vi", "nvim", "ex", "view", "ed", "red", "emacs", "nano", "pico", "micro", "sqlite3", "sponge",
            "dd", "rename", "prename", "perl-rename", "file-rename"}


# Files and folders checkrein keeps in its own folders, whether or not they exist yet.
OWN_NAMES = ("config.json", "ledger.json", "approvals.json", "quarantine", "trash", "pycache", "rules.json",
             "hooks.json", "plugin.json", "guard.py")


def protected_roots(ctx):
    out = [ctx.data_dir]
    if ctx.plugin_root:
        out.append(ctx.plugin_root)
    if ctx.project_dir:
        out.append(os.path.join(ctx.project_dir, ".checkrein"))
    return out


def check(ctx):
    if ctx.tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        return _tool_write(ctx)
    if ctx.tool_name == "Bash":
        return _bash(ctx)
    return []


def _tool_write(ctx):
    fp = ctx.file_path()
    if not fp:
        return []
    for root in protected_roots(ctx):
        if inside(fp, root):
            return [Hit("SLF01", "Edits checkrein's own files (%s). Change settings with /checkrein:config; a "
                                 "person can also edit the file directly." % os.path.basename(fp))]
    if python_startup(fp, ctx):
        return [_startup_hit(fp)]
    for s in settings_files(ctx):
        if same_path(fp, s):
            return _settings_tool_write(ctx, fp)
    return []


_STARTUP_NAMES = {"sitecustomize.py", "usercustomize.py", "sitecustomize", "usercustomize"}
_SITE_DIRS = {"site-packages", "dist-packages"}
# User and system site folders of any Python version, beside the ones of the Python running checkrein.
_SITE_PATTERNS = (r"/library/python/[^/]+/lib/python/site-packages", r"/\.local/lib/python[^/]*/site-packages",
                  r"^/opt/homebrew/lib/python[^/]*/site-packages", r"^/usr/local/lib/python[^/]*/site-packages",
                  r"^/library/frameworks/python\.framework/versions/[^/]+/lib/python[^/]*/site-packages")
_SITE_RE = re.compile("(?:%s)(?:/|$)" % "|".join(_SITE_PATTERNS))


_SITES = []


def _site_folders():
    if not _SITES:
        _SITES.append(_find_site_folders())
    return _SITES[0]


def _find_site_folders():
    out = []
    try:
        out.extend(site.getsitepackages())
        out.append(site.getusersitepackages())
    except AttributeError:
        pass
    paths = sysconfig.get_paths()
    out.extend(paths.get(k) for k in ("purelib", "platlib"))
    return [p for p in out if p]


def python_startup(path, ctx=None):
    """True for a file Python runs at start-up: a .pth file in a site folder, sitecustomize or usercustomize, or
    anything in the user's or the system's site folders. Python programs the agent runs load them, and so would
    a hook run without -I -S. The hook's own interpreter counts too: python, python3 and python3.N in every
    folder on its PATH (one that doesn't exist yet, such as ~/.local/bin, included), the file sys.executable
    leads to, and the standard library, which -I -S still loads."""
    # A long command line writes the same paths many times; the answer depends on the path alone.
    found = _STARTUP.get(path)
    if found is None:
        found = _STARTUP[path] = _python_startup(path)
    return found


_STARTUP = {}


def _python_startup(path):
    return _site_startup(path) or _hook_python(path)


# Names a shell finds the hook's interpreter by: python, python3, python3.12.
_PYTHON_NAME = re.compile(r"^python(?:3(?:\.[0-9]+)?)?$")
_HOOK_PYTHON = []


def _hook_python_places():
    """(PATH folders, the interpreter's real file, the standard library folder), found once."""
    if not _HOOK_PYTHON:
        folders = set()
        for entry in os.environ.get("PATH", "").split(os.pathsep):
            if entry and os.path.isabs(entry):
                folders.add(os.path.normpath(entry))
                folders.add(os.path.realpath(entry))
        exe = os.path.realpath(sys.executable) if sys.executable else ""
        _HOOK_PYTHON.append((folders, exe, os.path.dirname(os.path.abspath(os.__file__))))
    return _HOOK_PYTHON[0]


def _hook_python(path):
    """True for the interpreter the hook runs with, a python name a shell would find first on its PATH, or a
    file of the standard library."""
    folders, exe, stdlib = _hook_python_places()
    norm = os.path.normpath(path)
    real = real_path(norm)
    if _PYTHON_NAME.match(os.path.basename(norm).lower()):
        parent = os.path.dirname(norm)
        # Compared as the other protected paths are, ignoring case where the file system does (~/.LOCAL/bin).
        places = {parent, os.path.realpath(parent)}
        if any(same_path(p, f) for p in places for f in folders):
            return True
    if exe and same_path(real, exe):
        return True
    return inside(norm, stdlib) or inside(real, stdlib)


def _site_startup(path):
    norm = os.path.normpath(path)
    parts = norm.lower().split(os.sep)
    if any(p in _STARTUP_NAMES for p in parts):
        return True
    if parts[-1].endswith(".pth") and any(p in _SITE_DIRS for p in parts):
        return True
    if _SITE_RE.search(norm.lower()):
        return True
    return any(inside(path, folder) for folder in _site_folders())


# Package managers that install or replace Python itself: (program, subcommand words) before the version.
_PYTHON_INSTALLS = {"brew": ("install", "upgrade", "reinstall", "link", "unlink", "uninstall", "remove", "rm"),
                    "pyenv": ("install", "uninstall", "global"), "asdf": ("install", "global"),
                    "mise": ("install", "use"), "rtx": ("install", "use")}


# A Python formula or plugin name: python, python3, python@3, python@3.13 (not python-tk or python-setuptools).
_BREW_PYTHON = re.compile(r"^python(?:@?3(?:\.[0-9]+)?)?$")


def _python_swap(cmd, ctx):
    """A command that may replace the Python the hook runs with: a package manager installing Python (a person
    confirms), or a virtual environment made where the hook's PATH looks for python (denied)."""
    name, args = cmd.name, [a for a in cmd.args if not a.startswith("-")]
    if name in _PYTHON_INSTALLS and args and args[0] in _PYTHON_INSTALLS[name] and (
            (name == "pyenv" and not set(cmd.args) & {"--list", "-l", "--help", "-h"})
            or any(_BREW_PYTHON.match(a.lower().rsplit("/", 1)[-1]) for a in args[1:])):
        return Hit("SLF01", "Installs or replaces Python with %s %s, which can change the interpreter checkrein's "
                            "hook runs with. A person confirms this." % (name, args[0]), level="ask")
    if name == "uv" and args[:2] == ["python", "install"]:
        return Hit("SLF01", "Installs Python with uv python install, which can change the interpreter checkrein's "
                            "hook runs with. A person confirms this.", level="ask")
    folder = _venv_folder(cmd)
    if folder:
        folders, _exe, _stdlib = _hook_python_places()
        for view in at_each_cwd(cmd):
            try:
                bin_dir = os.path.normpath(os.path.join(ctx.path(folder, view.cwd or ctx.cwd), "bin"))
            except (TypeError, ValueError):
                continue
            if bin_dir in folders or os.path.realpath(bin_dir) in folders:
                return Hit("SLF01", "Makes a virtual environment in %s, whose python the hook's PATH finds first. A "
                                    "person makes this change." % bin_dir)
    return None


# Options of venv, virtualenv and uv venv that take a value.
_VENV_VALUES = {"--prompt", "-p", "--python", "--index-url", "--extra-index-url", "--seed-packages", "--relocatable",
                "--activators", "--creator", "--discovery", "--app-data", "--extra-search-dir", "--cache-dir",
                "--upgrade-deps-packages", "--project", "--directory"}


# Interpreter options that may come before -m venv without changing what it makes.
_PYTHON_FLAGS = {"-I", "-S", "-B", "-E", "-s", "-u"}


def _venv_folder(cmd):
    """The folder a command makes a virtual environment in (python -m venv DIR, virtualenv DIR, uv venv [DIR]),
    or None."""
    args = list(cmd.args)
    while args and args[0] in _PYTHON_FLAGS:
        args = args[1:]
    if cmd.name.startswith("python") and _INTERPRETER.match(cmd.name) and args[:2] in _VENV_MODULES:
        words = _nonopt_words(args[2:])
        return words[-1] if words else None
    if cmd.name == "virtualenv":
        words = _nonopt_words(args)
        return words[-1] if words else None
    if cmd.name == "uv" and args[:1] == ["venv"]:
        words = _nonopt_words(args[1:])
        return words[0] if words else ".venv"
    return None


def _nonopt_words(args):
    words, skip = [], False
    for a in args:
        if skip:
            skip = False
        elif a in _VENV_VALUES:
            skip = True
        elif not a.startswith("-"):
            words.append(a)
    return words


def _startup_hit(path):
    if _hook_python(path) and not _site_startup(path):
        return Hit("SLF01", "Changes %s, the Python interpreter or standard library checkrein's hook runs with. A "
                            "person makes this change." % path)
    return Hit("SLF01", "Writes %s, which Python loads when it starts (a .pth file, sitecustomize or "
                        "usercustomize, or a site-packages folder). A person makes this change." % path)


# Settings keys that turn checkrein (a plugin) or hooks on and off.
_SWITCH_KEYS = ("enabledPlugins", "hooks", "disableAllHooks", "pluginConfigs")
_SWITCH_OFF = "Changes Claude Code settings in a way that affects checkrein or turns hooks off."


def _read_settings(path):
    """(text, problem): the file's text ("" when it doesn't exist), or a problem when it can't be read."""
    if not os.path.lexists(path):
        return "", None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(), None
    except OSError as exc:
        return None, "checkrein can't read %s (%s), so it can't tell what this change does." % (path, exc.strerror)


def _strict(name):
    raise ValueError("%s is not JSON" % name)


def _load(text):
    # NaN and Infinity are Python's extension: Claude Code can't read such a file, so it can't count as safe.
    try:
        return json.loads(text, parse_constant=_strict) if text.strip() else {}
    except ValueError:
        return None


def holds_switch(text):
    """True when settings text names checkrein or holds plugin switches or hooks."""
    if "checkrein" in text.lower():
        return True
    data = _load(text)
    if isinstance(data, dict):
        return any(k in data for k in _SWITCH_KEYS)
    return any('"%s"' % k in text for k in _SWITCH_KEYS)


def _checkrein_switches(data, key="enabledPlugins"):
    """checkrein's entries under key (enabledPlugins, pluginConfigs), whatever the case of the name."""
    entries = data.get(key)
    if entries is None:
        return {}
    if not isinstance(entries, dict):
        return {"": entries}  # Not a map: compared as a whole.
    return {k: v for k, v in entries.items() if isinstance(k, str) and is_checkrein(k)}


def keeps_switch(old_text, new_text):
    """True when the new settings provably keep checkrein enabled and hooks as they were."""
    old, new = _load(old_text), _load(new_text)
    if not isinstance(old, dict) or not isinstance(new, dict):
        return False
    if new.get("disableAllHooks", False) is not False or old.get("hooks") != new.get("hooks"):
        return False
    # checkrein's plugin options (preset, fail_mode, scanner) live in pluginConfigs; they change only by the menu.
    if _checkrein_switches(old, "pluginConfigs") != _checkrein_switches(new, "pluginConfigs"):
        return False
    before, after = _checkrein_switches(old), _checkrein_switches(new)
    if any(v is not True for v in after.values()):
        return False
    return all(after.get(k) is True for k, v in before.items() if v is True)


def _settings_tool_write(ctx, fp):
    old, problem = _read_settings(fp)
    if problem:
        return [Hit("SLF01", problem, level="ask")]
    new = _new_settings_text(ctx, old)
    if new is _UNMATCHED:
        # Claude Code matches old_string loosely (quotes, line endings), so an edit checkrein can't place may
        # still be applied.
        if holds_switch(old):
            return [Hit("SLF01", "Edits %s, which holds checkrein's switch or hooks, with text checkrein can't "
                                 "find in it exactly, so it can't tell what changes." % fp)]
        return [Hit("SLF01", "Edits %s with text checkrein can't find in it exactly, so it can't tell what "
                             "changes. A person confirms this." % fp, level="ask")]
    if (holds_switch(old) or holds_switch(new)) and not keeps_switch(old, new):
        return [Hit("SLF01", _SWITCH_OFF)]
    risky, level = _risky_env(old, new)
    if level == "deny":
        return [Hit("SLF01", "Sets %s in the env of %s, which changes the programs, hooks or Python files Claude "
                             "Code and its hooks run with." % (risky, fp))]
    hits = []
    if risky:
        hits.append(Hit("SLF01", "Sets %s in the env of %s, which changes how Claude Code runs. A person confirms "
                                 "this." % (risky, fp), level="ask"))
    helper = _changed_helper(old, new)
    if helper:
        hits.append(Hit("SLF01", "Changes %s in %s, a command Claude Code runs by itself, outside checkrein's "
                                 "hooks. A person confirms this." % (helper, fp), level="ask"))
    return hits + _plugin_changes(ctx, old, new)


# Variables in settings env that decide which programs, git hooks, shells and Python start-up files Claude Code
# and its hooks run with, or which settings and plugins it loads. Other CLAUDE_* names are asked about.
_RISKY_ENV = re.compile(r"^(?:GIT_.*|HUSKY.*|SKIP|LEFTHOOK.*|PRE_COMMIT.*|LD_.*|DYLD_.*|BASH_ENV|ENV|ZDOTDIR|SHELL|"
                        r"XDG_.*|PATH|HOME|PYTHON.*|CLAUDE_CONFIG_DIR|CLAUDE_CODE_SHELL_PREFIX|CLAUDE_CODE_SIMPLE|"
                        r"CLAUDE_PLUGIN_.*|BASH_FUNC_.*|__BASH_FUNC.*|SHELLOPTS|BASHOPTS|PS4|IFS|GCONV_PATH|"
                        r"PROMPT_COMMAND|LC_.*)$")
# Settings that name a command Claude Code runs by itself.
_HELPER_KEYS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "fileSuggestion", "gcpAuthRefresh",
                "otelHeadersHelper", "processWrapper", "policyHelpers", "proxyAuthHelper", "statusLine",
                "subagentStatusLine")


def _changed_helper(old_text, new_text):
    """The first helper-command setting (statusLine, apiKeyHelper...) the change sets, edits or removes, or None."""
    old, new = _load(old_text), _load(new_text)
    old = old if isinstance(old, dict) else {}
    if not isinstance(new, dict):
        return None
    for key in _HELPER_KEYS:
        if old.get(key) != new.get(key):
            return key
    return None


def _risky_env(old_text, new_text):
    """(name, level) for the env variable the change sets or removes that matters most: deny for one that steers
    hooks, git or Python (_RISKY_ENV), ask for another CLAUDE_* name; (None, None) when neither changes."""
    old, new = _load(old_text), _load(new_text)
    if not isinstance(new, dict):
        return None, None
    before = (old or {}).get("env") if isinstance(old, dict) else None
    after = new.get("env")
    if before == after:
        return None, None
    if not isinstance(before, dict) or not isinstance(after, dict):
        before = before if isinstance(before, dict) else {}
        after = after if isinstance(after, dict) else {"env": after}
    asked = None
    for key in sorted(set(before) | set(after), key=str):
        if before.get(key) == after.get(key):
            continue
        name = str(key).upper()
        if _RISKY_ENV.match(name):
            return str(key), "deny"
        if asked is None and name.startswith("CLAUDE_"):
            asked = str(key)
    return (asked, "ask") if asked else (None, None)


def _plugin_changes(ctx, old_text, new_text):
    """SKL02 for plugins turned on in settings that the install ledger hasn't approved, and for changes to the
    marketplaces settings add."""
    old, new = _load(old_text), _load(new_text)
    if not isinstance(new, dict):
        return []
    old = old if isinstance(old, dict) else {}
    if old.get("extraKnownMarketplaces") != new.get("extraKnownMarketplaces"):
        return [Hit("SKL02", "Changes extraKnownMarketplaces in settings, which adds plugin sources outside the "
                             "install gate. Vet the marketplace first: /checkrein:vet <repo>.")]
    before = old.get("enabledPlugins") if isinstance(old.get("enabledPlugins"), dict) else {}
    after = new.get("enabledPlugins") if isinstance(new.get("enabledPlugins"), dict) else {}
    added = [k for k, v in after.items() if v is True and before.get(k) is not True
             and not own_checkrein(k, ctx)]
    if not added:
        return []
    try:
        entries = (ledger.load(ctx.data_dir) or {}).get("entries", {})
    except ledger.LedgerError as exc:
        return [Hit("SKL02", "%s Installs are refused until it is fixed (/checkrein:status doctor)." % exc,
                    level="deny")]
    for key in added:
        name, _, market = str(key).partition("@")
        _ekey, entry = ledger.find_plugin_approval(entries, name, market or None)
        if entry is None:
            return [Hit("SKL02", "Turns on the plugin %s in settings, which the install ledger has not approved. "
                                 "Vet it first: /checkrein:vet <repo>." % key)]
    return []


# Quotes Claude Code treats as the plain ones when it looks for old_string.
_LOOSE = {ord("\u201c"): '"', ord("\u201d"): '"', ord("\u201e"): '"', ord("\u201f"): '"', ord("\u2018"): "'",
          ord("\u2019"): "'", ord("\u201a"): "'", ord("\u201b"): "'"}
_UNMATCHED = object()


def _loose(text):
    return text.replace("\r\n", "\n").translate(_LOOSE)


def _new_settings_text(ctx, old):
    """The file's text after this Write, Edit or MultiEdit; _UNMATCHED when an edit's old text can't be placed in
    the file, even as Claude Code matches it (plain quotes for curly ones, LF for CRLF)."""
    ti = ctx.tool_input
    if ctx.tool_name == "Write":
        content = ti.get("content")
        return content if isinstance(content, str) else ""
    if ctx.tool_name == "Edit":
        edits = [ti]
    elif ctx.tool_name == "MultiEdit":
        edits = [e for e in ti.get("edits") or [] if isinstance(e, dict)]
    else:
        return "\0"  # A notebook edit: not JSON, so it can't be shown to keep the switch.
    text = old
    for e in edits:
        before, after = e.get("old_string"), e.get("new_string")
        if not isinstance(before, str) or not isinstance(after, str):
            return _UNMATCHED
        if not before:
            # An empty old_string writes new_string as the whole file, when the file is missing or empty.
            if text.strip():
                return _UNMATCHED
            text = after
            continue
        if before not in text:
            text, before, after = _loose(text), _loose(before), _loose(after)
            if before not in text:
                return _UNMATCHED
        text = text.replace(before, after) if e.get("replace_all") else text.replace(before, after, 1)
    return text


def _bash(ctx):
    hits = []
    roots = protected_roots(ctx)
    settings = settings_files(ctx)
    names = {os.path.basename(p).lower() for s in settings for p in (s, real_path(s))}
    for cmd in ctx.parsed.cmds:
        own = is_own_tool(cmd, ctx)
        # checkrein's own script run with folders of the agent's choosing is asked about by SKL04; it still
        # names the plugin's files only to run them.
        shape = own or own_tool_shape(cmd, ctx)
        if own:
            script, sub = own_tool_subcommand(cmd)
            if script == "cfgtool.py" and (sub is None or sub in CFG_MUTATING):
                hits.append(Hit("SLF01", "Changes checkrein's settings (cfgtool %s). A person confirms this."
                                % (sub or "with options checkrein can't read"), level="ask"))
        # A package runner starting Claude Code (the Claude Code package) is read as claude itself.
        agent = runners.program(cmd)
        if agent is not None and agent.name == "claude":
            off = _turns_checkrein_off(agent, ctx)
            if off:
                hits.append(Hit("SLF01", off))
            nested = _nested_agent(agent, env_of(cmd))
            if nested:
                hits.append(Hit("SLF01", "Starts another Claude Code agent with %s, which can run it without "
                                         "checkrein's hooks. A person confirms this." % nested, level="ask"))
            if cmd.name == "claude":
                continue
        words = _script_words(cmd)
        read_only = _read_only(cmd)
        written = write_targets(cmd, ctx)
        startup = [p for p, _k in written if python_startup(p, ctx)]
        if startup:
            hits.append(_startup_hit(startup[0]))
            continue
        swap = _python_swap(cmd, ctx)
        if swap:
            hits.append(swap)
            continue
        loose = []
        if not read_only and not _reads_named_files(cmd):
            lowered = [w.lower() for w in words]
            # Most commands name no settings file and run no editor, so the per-file checks are skipped for them;
            # a long command line holds tens of thousands of commands.
            if _INTERPRETER.match(cmd.name) or cmd.name in _EDITORS or any(globs.has_magic(w) for w in words) \
                    or any(n in w for w in lowered for n in names):
                # An inline script, editor or other writer that names a settings file, or runs where one is, may
                # rewrite it.
                written = written + [(s, "modify") for s in settings if _reaches_settings(cmd, ctx, s, words)]
            scripts = [w for w in words if _is_script(w)]
            if any(".claude" in w.lower() for w in scripts):
                # A settings path written inside a script (another folder's Claude settings file in a string)
                # may not be this file, so only a change about checkrein counts there. A plain word is a path,
                # already read against the command's folder above.
                loose = [s for s in settings if any(_mentions_settings(w, s, ctx) for w in scripts)]
        # Removing, moving, replacing or unpacking over a folder that holds a protected file changes it too, and
        # so does a recursive or find-driven writer run on a folder above it (find -delete, chmod -R, gzip -r).
        written = written + [(s, "modify") for s in settings
                             if replaces(cmd, ctx, s, written) or recursive_touches(cmd, ctx, s)]
        touched = [p for p, _k in written if any(inside(p, r) for r in roots)
                   or ".checkrein" in [x.lower() for x in unknown_relative(p) or []]]
        touched += [r for r in roots if replaces(cmd, ctx, r, written)
                    or recursive_touches(cmd, ctx, r, OWN_NAMES, sure=True)]
        if touched or (not read_only and not shape and any(inside(c or ctx.cwd, r) for c in cwds(cmd)
                                                         for r in roots)):
            # Run inside a protected folder, a writer may change any file there by a relative name.
            hits.append(Hit("SLF01", "Changes checkrein's own files with %s. Use /checkrein:config or edit the file "
                                     "yourself." % cmd.name))
            continue
        if any(_unknown_settings(p) for p, _k in written):
            hits.append(Hit("SLF01", "Changes a Claude Code settings file in a folder checkrein can't tell, so it "
                                     "can't check what the change does."))
            continue
        hit = _settings_bash(ctx, cmd, [p for p, _k in written], settings, loose)
        if hit:
            hits.append(hit)
            continue
        if any(recursive_touches(cmd, ctx, r, OWN_NAMES) for r in roots):
            # The name tests reach only files checkrein may write there later, or the folder is too large to list.
            hits.append(Hit("SLF01", "Runs %s on files found in checkrein's own folders, which may reach its "
                                     "settings or records. A person confirms this." % cmd.name, level="ask"))
            continue
        # The tool's own arguments (--data naming the data dir) are expected; everything else is checked.
        mentions = [a for a in ([] if shape else words) if _mentions(ctx, a, cwds(cmd), roots)]
        if mentions and not read_only:
            hits.append(Hit("SLF01", "Runs %s on checkrein's own files. Only read-only commands may touch them; "
                                     "use /checkrein:config for changes." % cmd.name))
    return hits


def _is_script(word):
    """True for a word that is script text rather than one path: it holds spaces, quotes or statements."""
    return any(c in word for c in " \t\n;'\"()=,")


# git subcommands that read the files they name, or change only the index and history.
_GIT_READS_FILES = {"add", "commit", "diff", "show", "log", "blame", "status", "ls-files", "stage", "annotate"}


def _reads_named_files(cmd):
    """True when the files a command names are only read: the sources of cp, scp and rsync (the destination is a
    write target), tar creating an archive, and git add, commit, diff or restore --staged."""
    args = list(cmd.args)
    if cmd.name in ("cp", "gcp", "scp", "ditto"):
        return True
    if cmd.name == "rsync":
        return not any(a.startswith(("--remove-source-files", "--delete")) for a in args)
    if cmd.name in ("tar", "gtar", "bsdtar"):
        first = args[0] if args else ""
        modes = set(first.lstrip("-")) if first and not first.startswith("--") else set()
        modes |= {"c" for a in args if a in ("-c", "--create")}
        modes |= set(c for a in args if a.startswith("-") and not a.startswith("--") for c in a[1:])
        return "c" in modes and not modes & {"x", "u", "r", "A"} and "--remove-files" not in args
    if cmd.name == "git":
        sub, sub_args = git_subcommand(args)
        if sub in _GIT_READS_FILES:
            return True
        if sub == "restore":
            staged = any(a in ("--staged", "-S") for a in sub_args)
            return staged and not any(a in ("--worktree", "-W") for a in sub_args)
    return False


def _json_tool_read(args):
    """True for python -m json.tool with at most one file: it prints the file. A second file is where it writes."""
    args = list(args)
    if args[:2] != ["-m", "json.tool"]:
        return False
    files = [a for a in args[2:] if not a.startswith("-")]
    return len(files) <= 1 and not any(a.startswith("--") and "=" in a for a in args[2:])


def _unknown_settings(path):
    """True for .claude/settings*.json or .claude.json written by a relative name from an unknown folder (any case,
    since the folder's file system is unknown)."""
    parts = [p.lower() for p in unknown_relative(path) or []]
    if not parts:
        return False
    if parts[-1] == ".claude.json":
        return True
    return len(parts) >= 2 and parts[-2] == ".claude" and parts[-1] in ("settings.json", "settings.local.json")


def _settings_bash(ctx, cmd, written, settings, loose=()):
    """A command that changes a settings file. What it writes can't be known, so a file holding checkrein's
    switch or hooks is off limits, and so is a command naming checkrein or the switches; any other change to a
    settings file is confirmed by a person."""
    for s in settings:
        exact = any(same_path(p, s) for p in written)
        if not exact and s not in loose:
            continue
        text, problem = _read_settings(s)
        if problem:
            return Hit("SLF01", problem, level="ask")
        keywords = any(k in ctx.command.lower() for k in ("checkrein", "disableallhooks", "enabledplugins",
                                                          "pluginconfigs"))
        if holds_switch(text) or keywords:
            return Hit("SLF01", "Changes %s, which holds checkrein's switch or hooks. Edit it yourself, or use the "
                                "/plugin menu." % _home_short(ctx, s))
        if not exact:
            continue
        # What a shell command writes can't be read reliably (printf formats, variables, scripts), so a person
        # confirms; the Write and Edit tools show the exact change.
        return Hit("SLF01", "Changes %s with a shell command, so checkrein can't check what it writes. Use the "
                            "Write or Edit tool, or edit it yourself." % _home_short(ctx, s), level="ask")
    return None


# Options a nested `claude` may run with that keep its hooks and permission checks: the value-taking ones map to
# True. Any other option (--bare, --plugin-dir, --settings, the permission-skipping one...) is asked about.
_NESTED_SAFE = {"-p": False, "--print": False, "--model": True, "--output-format": True, "--input-format": True,
                "--max-turns": True, "--append-system-prompt": True, "--system-prompt": True,
                "--allowedTools": True, "--allowed-tools": True, "--disallowedTools": True,
                "--disallowed-tools": True, "--permission-mode": True, "-c": False, "--continue": False,
                "-r": False, "--resume": False, "--verbose": False, "--add-dir": True, "-v": False,
                "--version": False, "-h": False, "--help": False, "--json-schema": True, "--effort": True,
                "--fallback-model": True, "--session-id": True, "--include-partial-messages": False, "-d": False,
                "--debug": False, "--fork-session": False, "--no-session-persistence": False, "-n": True,
                "--ide": False, "--chrome": False, "--replay-user-messages": False}
# Subcommands that manage Claude Code rather than start an agent; `claude plugin ...` is read by SKL02 and above.
_CLAUDE_SUBCOMMANDS = {"plugin", "plugins", "mcp", "config", "doctor", "update", "install", "migrate-installer",
                       "setup-token"}
# Variables that decide which settings, plugins and hooks a nested claude loads.
_NESTED_ENV = re.compile(r"^(?:CLAUDE_.*|HOME|XDG_CONFIG_HOME)$")


def _nested_agent(cmd, env=None):
    """What lets a nested `claude` run without checkrein's hooks or permission checks: an option outside the
    known-safe list, a permission mode that skips prompts, or a variable such as CLAUDE_CONFIG_DIR or HOME set
    for it. None for a plain `claude -p ...` or a management subcommand."""
    names = sorted(k for k in (env or {}) if _NESTED_ENV.match(k))
    if names:
        return "%s set" % names[0]
    args = list(cmd.args)
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            break
        if not a.startswith("-") or a == "-":
            if i == 0 or not args[i - 1].startswith("-"):
                if a in _CLAUDE_SUBCOMMANDS and not any(w for w in args[:i] if not w.startswith("-")):
                    return None
            i += 1
            continue
        opt, eq, val = a.partition("=")
        if not opt.startswith("--") and len(opt) > 2:
            # A cluster of short flags (-pc): each must be safe and take no value.
            if all(_NESTED_SAFE.get("-" + c) is False for c in opt[1:]):
                i += 1
                continue
            return opt
        if opt not in _NESTED_SAFE:
            return opt
        if opt == "--permission-mode":
            mode = val if eq else (args[i + 1] if i + 1 < len(args) else "")
            if mode not in ("default", "plan", "acceptEdits"):
                return "--permission-mode %s" % mode
        i += 2 if _NESTED_SAFE[opt] and not eq else 1
    return None


def _home_short(ctx, path):
    home = os.path.join(ctx.home, "")
    return "~/" + path[len(home):] if path.startswith(home) else path


def _script_words(cmd):
    """The words to look through: the arguments, plus an interpreter's script when it comes from a heredoc or
    here-string."""
    words = list(cmd.args)
    stdin = getattr(cmd, "stdin_text", "")
    if stdin and _INTERPRETER.match(cmd.name):
        words.append(stdin)
    return words


def _turns_checkrein_off(cmd, ctx):
    """Why a `claude plugin` call turns checkrein off or changes its options, or None."""
    call = plugin_call(cmd)
    if call is None or not call.words:
        return None
    sub, target = call.words[0], call.word(1)
    off = "Turns checkrein off. Do this yourself from the /plugin menu if you mean it."
    if sub == "disable" and ("--all" in call.flags or not target or is_checkrein(target)):
        return off
    if sub == "uninstall" and (not target or is_checkrein(target)):
        return off
    if sub == "configure" and is_checkrein(target) and call.flags - {"--json", "--help"}:
        return ("Changes checkrein's plugin options. Change settings with /checkrein:config, or set the options "
                "yourself from the /plugin menu.")
    if sub == "marketplace" and target == "remove" and call.word(2) in own_marketplaces(ctx):
        return off
    return None


_CLAUDE_FOLDER = ".claude"
_VENV_MODULES = (["-m", "venv"], ["-m", "virtualenv"])
_SETTINGS_NAMES = tuple(os.path.join(_CLAUDE_FOLDER, n) for n in ("settings.json", "settings.local.json")) + (
    ".claude.json",)


def _contains(word, part, where):
    """Substring test that ignores case when the file system holding where does."""
    if part in word:
        return True
    return case_insensitive(where) and part.lower() in word.lower()


def _reaches_settings(cmd, ctx, settings_path, words):
    folders = [c or ctx.cwd for c in cwds(cmd)]
    folder = os.path.dirname(settings_path)
    claude_folder = os.path.basename(folder).lower() == ".claude" or same_path(folder, claude_dir(ctx.home))
    if (_INTERPRETER.match(cmd.name) or cmd.name in _EDITORS) and claude_folder \
            and any(same_path(c, folder) for c in folders):
        return True
    return any(_names_settings(w, settings_path, ctx, c) for w in words for c in folders)


def _names_settings(word, settings_path, ctx, cwd=None):
    """True when word (a path or an inline script) names this settings file, by any path that leads to it from
    the folder the command runs in (settings.json, a .claude folder's settings.json, ../.claude.json)."""
    name = os.path.basename(settings_path).lower()
    if name in word.lower():
        for piece in word.split("=") + [m.group(2) for m in _QUOTED.finditer(word)]:
            if name in piece.lower() and len(piece) < 4096:
                try:
                    if same_path(ctx.path(piece.strip(), cwd), settings_path):
                        return True
                except (TypeError, ValueError):
                    pass
    if globs.has_magic(word) and "/" in word and not any(c in word for c in " \t\n"):
        try:
            if same_path(ctx.path(word, cwd), settings_path):
                return True
        except (TypeError, ValueError):
            pass
    return False


def _built_mention(word, name, where):
    """True when word holds name after a folder the script builds (homedir() joined with the settings path). A name
    standing alone or after ./ is relative to the command's folder, already read exactly as a path."""
    text, part = (word, name) if not case_insensitive(where) else (word.lower(), name.lower())
    at = text.find(part)
    while at >= 0:
        if at > 0 and text[at - 1] == "/" and text[at - 2:at] != "./":
            return True
        at = text.find(part, at + 1)
    return False


def _mentions_settings(word, settings_path, ctx):
    """True when word holds a settings name (settings.json under .claude) that may point at this file."""
    for name in _SETTINGS_NAMES:
        if settings_path.endswith(os.sep + name.replace("/", os.sep)) and _built_mention(word, name, settings_path):
            # A home-relative name points at the user files; any other at the project's.
            user = settings_path.startswith(os.path.join(ctx.home, "")) \
                or settings_path.startswith(os.path.join(claude_dir(ctx.home), ""))
            in_project = bool(ctx.project_dir) and settings_path.startswith(os.path.join(ctx.project_dir, ""))
            return user or in_project
    return False


_QUOTED = re.compile(r"""(["'])([^"'\n]{1,4096}?)\1""")


def _mentions(ctx, word, cwd_list, roots):
    # A root written inside a larger word (an inline script, a quoted string) still counts.
    for root in roots:
        for form in {root, real_path(root)}:
            if form and _contains(word, form, root):
                return True
    if "CLAUDE_PLUGIN_DATA" in word or "CLAUDE_PLUGIN_ROOT" in word:
        return True
    # Path-like pieces: the word, its key=value halves, and strings quoted inside a script, each read against
    # every folder the command may run in.
    pieces = word.split("=") + [m.group(2) for m in _QUOTED.finditer(word)]
    for piece in pieces:
        if not piece or ("/" not in piece and not piece.startswith((".", "~", "$"))):
            continue
        for cwd in cwd_list:
            try:
                path = ctx.path(piece, cwd)
            except (TypeError, ValueError):
                continue
            if any(inside(path, r) for r in roots):
                return True
    return False


def _read_only(cmd):
    if _INTERPRETER.match(cmd.name) and _json_tool_read(cmd.args) and not any(k in _RUNNER_ENV for k in cmd.env or {}):
        return True
    if cmd.name not in READ_ONLY:
        return False
    args = cmd.args
    if any(k in _RUNNER_ENV for k in cmd.env or {}):
        return False
    if cmd.name == "find" and any(a in _FIND_ACTIONS for a in args):
        return False
    if cmd.name in ("sed", "gsed") and (sed_in_place(args) or sed_writes_or_runs(args)):
        return False
    if cmd.name == "git":
        return _git_read_only(cmd)
    if cmd.name == "rg" and any(a == "--pre" or a.startswith("--pre=") for a in args):
        return False  # --pre runs a command on every file searched.
    if cmd.name == "fd" and any(a in ("--exec", "--exec-batch") or a.startswith(("--exec=", "--exec-batch="))
                                or set("xX") & set(shell.short_flags(a, "cdeEjStT")) for a in args):
        return False
    if cmd.name == "bat" and any(a == "--pager" or a.startswith("--pager=") for a in args):
        return False
    if cmd.name == "awk" and awk_writes_or_runs(args):
        return False
    if cmd.name in ("sort", "tree") and any(a.startswith(("-o", "--o")) for a in args):
        return False
    if cmd.name == "sort" and any(long_option(a.split("=", 1)[0], "--compress-program", 3) for a in args):
        return False  # It runs the named program.
    if cmd.name == "uniq" and len([a for a in args if not a.startswith("-")]) >= 2:
        return False
    return True


_GIT_READ = ("diff", "log", "show", "status", "blame", "ls-files", "grep", "rev-parse", "describe")


def _git_read_only(cmd):
    configs, _cdir = git_globals(cmd.args)
    if configs:
        return False  # -c core.pager=..., diff.external=... can run anything.
    sub, sub_args = git_subcommand(cmd.args)
    if sub not in _GIT_READ:
        return False
    if sub == "grep":
        for a in sub_args:
            if a == "--":
                break
            if long_option(a.split("=", 1)[0], "--open-files-in-pager", 2):
                return False  # Opens the matching files in a pager it names, which can be any command.
            if a.startswith("-") and not a.startswith("--") and "O" in shell.short_flags(a, "efABCm"):
                return False
    return True
