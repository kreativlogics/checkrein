"""What every rule sees: the tool call, where it runs, the config, and helpers
that find which paths a shell command writes to."""

import fnmatch
import os
import re
import shlex
import sys

from . import globs
from . import shell

UNATTENDED_MODES = ("dontAsk", "bypassPermissions")
LEVELS = ("off", "ask", "deny")
FILE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")


def shell_text(tool_name, tool_input):
    """The shell command a tool call runs, or None. Bash, Monitor and any other tool with a command field run it in
    a shell; a list of words is read as those words."""
    if tool_name in FILE_TOOLS or not isinstance(tool_input, dict) or "command" not in tool_input:
        return None
    command = tool_input["command"]
    if isinstance(command, str):
        return command
    if isinstance(command, list) and all(isinstance(w, str) for w in command):
        return " ".join(shlex.quote(w) for w in command)
    return None


def claude_dir(home=None):
    """Claude Code's config folder: $CLAUDE_CONFIG_DIR when it is set to an absolute path, else ~/.claude."""
    env = os.environ.get("CLAUDE_CONFIG_DIR", "").strip()
    if env and os.path.isabs(env):
        return os.path.normpath(env)
    return os.path.join(home or os.path.expanduser("~"), ".claude")


def claude_json(home=None):
    """Claude Code's state file: .claude.json inside $CLAUDE_CONFIG_DIR when that is set, else ~/.claude.json."""
    env = os.environ.get("CLAUDE_CONFIG_DIR", "").strip()
    if env and os.path.isabs(env):
        return os.path.join(claude_dir(home), ".claude.json")
    return os.path.join(home or os.path.expanduser("~"), ".claude.json")


def default_data_dir(home):
    env = os.environ.get("CLAUDE_PLUGIN_DATA", "").strip()
    return env or os.path.join(claude_dir(home), "checkrein")


class Hit(object):
    """One rule match. level None means: use the rule's configured level."""

    __slots__ = ("rule", "reason", "level", "cap")

    def __init__(self, rule, reason, level=None, cap=None):
        self.rule = rule
        self.reason = reason
        self.level = level
        self.cap = cap  # Highest level this hit may reach (e.g. generic secret patterns: ask).


class Ctx(object):
    def __init__(self, payload, eff, home=None, data_dir=None, plugin_root=None):
        self.payload = payload
        self.tool_name = payload.get("tool_name") or ""
        self.tool_input = payload.get("tool_input") or {}
        self.shell_command = shell_text(self.tool_name, self.tool_input)
        # A tool that runs a shell command (Monitor, tools added later) is judged exactly as Bash. MCP tools keep
        # their name for the MCP checks; rules.evaluate also judges their command as Bash.
        self.called_as = self.tool_name
        if self.shell_command is not None and not self.tool_name.startswith("mcp__"):
            self.tool_name = "Bash"
        self.cwd = payload.get("cwd") or os.getcwd()
        self.permission_mode = payload.get("permission_mode") or "default"
        self.home = home or os.path.expanduser("~")
        self.project_dir = os.environ.get("CLAUDE_PROJECT_DIR") or self.cwd
        self.data_dir = data_dir or default_data_dir(self.home)
        self.plugin_root = plugin_root
        self.eff = eff
        self._parsed = None

    @property
    def unattended(self):
        return self.permission_mode in UNATTENDED_MODES

    @property
    def command(self):
        return (self.shell_command or "") if self.tool_name == "Bash" else ""

    def as_shell(self):
        """This call judged as a Bash command (an MCP tool with a command field)."""
        payload = dict(self.payload, tool_name="Bash", tool_input={"command": self.shell_command or ""})
        view = Ctx(payload, self.eff, home=self.home, data_dir=self.data_dir, plugin_root=self.plugin_root)
        view.cwd, view.project_dir = self.cwd, self.project_dir
        return view

    @property
    def parsed(self):
        if self._parsed is None:
            self._parsed = shell.parse(self.command, cwd=self.cwd, home=self.home)
        return self._parsed

    def path(self, word, cwd=None):
        return shell.expand_path(word, cwd or self.cwd, self.home)

    def file_path(self):
        """The target of Write, Edit, MultiEdit or NotebookEdit, absolute."""
        p = self.tool_input.get("file_path") or self.tool_input.get("notebook_path") or ""
        return self.path(p) if p else ""


_CASE_CACHE = {}
# Answers per path for this hook call: rules ask about the same paths many times.
_CASE_PATHS = {}
_REAL_PATHS = {}
# Rules ask the same path questions for every command of a long command line, so answers are kept per process.
_INSIDE = {}
_HOLDS = {}
_SAME = {}
_NORM_PATHS = {}


def _real(path):
    if path not in _REAL_PATHS:
        _REAL_PATHS[path] = os.path.realpath(path)
    return _REAL_PATHS[path]


def real_path(path):
    """os.path.realpath, answered once per path."""
    return _real(path)


def case_insensitive(path):
    """True when the file system holding path treats names differing only in case as one (macOS and Windows
    by default). Probed on the nearest existing folder with letters in its name; cached per folder."""
    if path not in _CASE_PATHS:
        _CASE_PATHS[path] = _case_insensitive(path)
    return _CASE_PATHS[path]


def _case_insensitive(path):
    probe = os.path.normpath(path)
    # Folders passed on the way up share the answer of the folder probed, so they are kept too: many paths in one
    # command line sit in the same folder.
    passed = []
    while True:
        if probe in _CASE_PATHS and passed:
            answer = _CASE_PATHS[probe]
            break
        base = os.path.basename(probe)
        if base.swapcase() != base and os.path.lexists(probe):
            answer = _CASE_PATHS[probe] = _probe_case(probe)
            break
        parent = os.path.dirname(probe)
        if parent == probe:
            answer = sys.platform in ("darwin", "win32")  # Nothing to probe: go by the platform's default.
            break
        passed.append(probe)
        probe = parent
    for folder in passed[1:]:
        _CASE_PATHS[folder] = answer
    return answer


def _probe_case(probe):
    key = os.path.dirname(probe)
    if key not in _CASE_CACHE:
        swapped = os.path.join(key, os.path.basename(probe).swapcase())
        try:
            _CASE_CACHE[key] = os.path.lexists(swapped) and os.path.samefile(probe, swapped)
        except OSError:
            _CASE_CACHE[key] = False
    return _CASE_CACHE[key]


def _under(path, root, fold):
    if fold:
        path, root = path.lower(), root.lower()
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _norm(path):
    if path not in _NORM_PATHS:
        _NORM_PATHS[path] = os.path.normpath(path)
    return _NORM_PATHS[path]


def inside(path, root):
    """True when path is root or inside it. A glob path counts when it could name root, something inside it, or
    a folder that holds it. Case is ignored where the root's file system ignores it. A path the system can't
    look up (a null byte, a name too long) counts, since checkrein can't tell where it leads."""
    if not path or not root:
        return False
    key = (path, root)
    if key not in _INSIDE:
        try:
            _INSIDE[key] = _inside(path, root)
        except (ValueError, OSError):
            _INSIDE[key] = True
    return _INSIDE[key]


def _inside(path, root):
    ci = case_insensitive(root)
    if globs.has_magic(path):
        return globs.path_may_reach(path, root, ci)
    if _under(_norm(path), _norm(root), ci):
        return True
    return _under(_real(path), _real(root), ci)


def holds(folder, path):
    """True when folder is path or a folder above it: moving, removing or replacing folder affects path."""
    key = (folder, path)
    found = _HOLDS.get(key)
    if found is None:
        found = _HOLDS[key] = inside(path, folder) or (globs.has_magic(folder) and inside(folder, path))
    return found


def reach(path, base):
    """The folders from path's parent up to base (both included), when path is inside base; none when path is
    base; else just the parent. Unpacking or pouring files into any of them can create path."""
    out = []
    current = os.path.dirname(os.path.normpath(path))
    if same_path(path, base):
        return []
    if not inside(path, base):
        return [current]
    while True:
        out.append(current)
        if same_path(current, base) or os.path.dirname(current) == current:
            return out
        current = os.path.dirname(current)


def same_path(path, target):
    """True when path is target, or a glob that could name it, ignoring case where the file system does."""
    key = (path, target)
    if key not in _SAME:
        _SAME[key] = _same_path(path, target)
    return _SAME[key]


def _same_path(path, target):
    ci = case_insensitive(target)
    if globs.has_magic(path):
        return globs.path_may_be(path, target, ci)
    fold = (lambda x: x.lower()) if ci else (lambda x: x)  # noqa: E731
    if fold(_norm(path)) == fold(_norm(target)):
        return True
    # A symlink and its target are one file (a settings file kept in a dotfiles folder).
    try:
        return fold(_real(path)) == fold(_real(target))
    except (ValueError, OSError):
        return True


def matches_globs(path, patterns, project_dir):
    rel = os.path.relpath(path, project_dir) if project_dir and inside(path, project_dir) else None
    for g in patterns:
        if fnmatch.fnmatch(path, g) or (rel and fnmatch.fnmatch(rel, g)) or fnmatch.fnmatch(os.path.basename(path), g):
            return True
    return False


def settings_files(ctx):
    """Claude Code settings files that can turn hooks or plugins off."""
    out = [os.path.join(claude_dir(ctx.home), "settings.json"),
           os.path.join(claude_dir(ctx.home), "settings.local.json"),
           claude_json(ctx.home)]
    if ctx.project_dir:
        out.append(os.path.join(ctx.project_dir, ".claude", "settings.json"))
        out.append(os.path.join(ctx.project_dir, ".claude", "settings.local.json"))
    return [os.path.normpath(p) for p in out]


# Commands that copy, download or unpack content into a destination.
_DEST_LAST = {"cp", "mv", "rsync", "install", "ln", "ditto", "scp", "gcp", "gmv"}
_DELETE = {"rm", "rmdir", "unlink", "shred", "trash"}
_MODIFY_ARGS = {"touch", "chmod", "chown", "chflags", "chgrp", "truncate", "xattr", "setfacl"}


def _nonopts(args, takes_value=()):
    out = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in takes_value:
            skip = True
            continue
        if a.startswith("-") and a != "-":
            continue
        out.append(a)
    return out


class _AtCwd(object):
    """A command read as if run in another of the folders it may run in."""

    def __init__(self, cmd, cwd):
        self._cmd = cmd
        self.cwd = cwd

    def __getattr__(self, name):
        return getattr(self._cmd, name)


def cwds(cmd):
    """Folders cmd may run in. The shell reader lists several when it can't tell whether a cd ran first."""
    found = getattr(cmd, "cwds", None) or (cmd.cwd,)
    out = []
    for cwd in found:
        if cwd not in out:
            out.append(cwd)
    return out or [cmd.cwd]


# Stands for the folder a command runs in when the shell reader can't know it (cd "$DIR", cd "$(...)").
UNKNOWN_CWD = os.path.join(os.sep, "checkrein-unknown-folder")


def at_each_cwd(cmd):
    """cmd as run in each folder it may run in, plus UNKNOWN_CWD when the folder may be one the reader can't know."""
    out = [cmd if cwd == cmd.cwd else _AtCwd(cmd, cwd) for cwd in cwds(cmd)]
    if getattr(cmd, "cwd_unknown", False):
        out.append(_AtCwd(cmd, UNKNOWN_CWD))
    return out


def unknown_relative(path):
    """The parts of a relative name a command wrote from an unknown folder (a path under UNKNOWN_CWD), or None.

    Any folder could hold .checkrein, .claude or .git/hooks, so rules treat those names as protected here.
    """
    prefix = UNKNOWN_CWD + os.sep
    if not path or not path.startswith(prefix):
        return None
    return [p for p in path[len(prefix):].split(os.sep) if p]


def write_targets(cmd, ctx):
    """Paths a simple command writes, copies into, unpacks into or deletes.

    Returns a list of (absolute_path, kind) with kind one of: bring, modify, delete.
    "bring" means new content arrives from somewhere else (copy, download, clone, unpack).
    Relative words are read in every folder the command may run in (see at_each_cwd).
    """
    # Several rules ask for the same command's targets; a long command line has tens of thousands of commands.
    cache = ctx.__dict__.setdefault("_write_targets", {})
    hit = cache.get(id(cmd))
    if hit is not None and hit[0] is cmd:
        return list(hit[1])
    out, seen = [], set()
    for at in at_each_cwd(cmd):
        for target in _write_targets(at, ctx):
            if target not in seen:
                seen.add(target)
                out.append(target)
    cache[id(cmd)] = (cmd, tuple(out))
    return out


# Programs whose "bring" targets are folders that receive whatever an archive, download or checkout holds.
UNPACKERS = {"tar", "gtar", "bsdtar", "unzip", "bsdunzip", "7z", "7za", "cpio", "git", "gh", "svn", "hg", "aria2c",
             "sftp", "http", "https", "pip", "pip3", "wget", "curl"}


def unpack_folders(cmd, ctx):
    """Folders a command fills with content it does not name: archives unpacked, checkouts, downloads into the
    current folder, and folders poured into another (rsync -a src/ dest/)."""
    if cmd.name not in UNPACKERS and cmd.name not in _DEST_LAST:
        return []
    # Asked once per protected file for the same command; a long command line has tens of thousands of commands.
    cache = ctx.__dict__.setdefault("_unpack_folders", {})
    hit = cache.get(id(cmd))
    if hit is not None and hit[0] is cmd:
        return list(hit[1])
    out = [p for p, kind in write_targets(cmd, ctx) if kind == "bring"] if cmd.name in UNPACKERS else []
    for view in at_each_cwd(cmd):
        out.extend(copy_landings(view, ctx)[1])
    cache[id(cmd)] = (cmd, tuple(out))
    return out


def base_of(ctx, path):
    """How far up from path an unpacked archive or poured folder can still create it: to the project's top-level
    folder holding it (.claude, .checkrein) for project files, to home for the user's files."""
    if ctx.project_dir and inside(path, ctx.project_dir) and not same_path(path, ctx.project_dir):
        rel = os.path.relpath(os.path.normpath(path), os.path.normpath(ctx.project_dir))
        return os.path.join(ctx.project_dir, rel.split(os.sep)[0])
    if inside(path, ctx.home):
        return ctx.home
    config = claude_dir(ctx.home)
    if inside(path, config):
        # A CLAUDE_CONFIG_DIR outside home: files poured into the folder above it can create it.
        return os.path.dirname(os.path.normpath(config))
    return os.path.dirname(os.path.normpath(path))


def _all_landings(cmd, ctx):
    """Where copies land in every folder cmd may run in, worked out once per command for all protected files."""
    cache = ctx.__dict__.setdefault("_all_landings", {})
    hit = cache.get(id(cmd))
    if hit is None or hit[0] is not cmd:
        hit = (cmd, Landings([landing for view in at_each_cwd(cmd) for landing in copy_landings(view, ctx)[0]]))
        cache[id(cmd)] = hit
    return hit[1]


class Landings(object):
    """Paths copies land at, grouped by the folder they land in: cp s0 ... s9999 ~/.claude/ lands ten thousand
    names in one folder, and a protected path is compared with that folder once, not once per name. A landing
    that is a glob or an existing symlink (which may lead anywhere) is compared on its own."""

    def __init__(self, paths):
        self.paths = list(paths)
        self.groups = {}
        self.odd = []
        for path in self.paths:
            if globs.has_magic(path) or os.path.islink(path):
                self.odd.append(path)
            else:
                norm = _norm(path)
                self.groups.setdefault(os.path.dirname(norm), set()).add(os.path.basename(norm))

    def __iter__(self):
        return iter(self.paths)

    def __bool__(self):
        return bool(self.paths)

    __nonzero__ = __bool__

    def any_inside(self, root):
        """True when a landing is root or inside it."""
        if any(inside(p, root) for p in self.odd):
            return True
        for parent, names in self.groups.items():
            if inside(parent, root) or _named_child(parent, names, root, whole=True):
                return True
        return False

    def any_holds(self, path):
        """True when a landing is path or a folder above it."""
        if any(holds(p, path) for p in self.odd):
            return True
        return any(_named_child(parent, names, path) for parent, names in self.groups.items())


def _named_child(parent, names, path, whole=False):
    """True when one of names, in parent, is path (whole) or is path or a folder above it."""
    ci = case_insensitive(parent)
    for folder, target in ((_norm(parent), _norm(path)), (_real(parent), _real(path))):
        if not _under(target, folder, ci) or _under(folder, target, ci):
            continue
        rest = target[len(folder.rstrip(os.sep)) + 1:]
        child = rest.split(os.sep, 1)[0]
        if whole and child != rest:
            continue
        if child in names or (ci and child.lower() in {n.lower() for n in names}):
            return True
    return False


def replaces(cmd, ctx, path, written):
    """True when the command removes or moves a folder holding path, copies a folder over it, or unpacks or pours
    files into a folder from which they can create it."""
    for p, kind in written:
        if kind == "delete" and holds(p, path):
            return True
    if cmd.name not in _DEST_LAST and cmd.name not in UNPACKERS:
        return False  # Only copies and unpackers land or pour files; skip the per-folder work for the rest.
    if _all_landings(cmd, ctx).any_holds(path):
        return True
    filled = unpack_folders(cmd, ctx)
    if not filled:
        return False
    # The folders that can create path are worked out once, not once per source.
    above = reach(path, base_of(ctx, path))
    return any(same_path(f, a) for f in filled for a in above)


# Variables a command inherits from earlier in the command line (export, declare -x, set -a); set by shell.py.
INHERITED_ENV = "inherited_env"


def env_of(cmd):
    """The variables a command runs with that the command line set: inherited ones, then its own prefix."""
    out = dict(getattr(cmd, INHERITED_ENV, None) or {})
    out.update(cmd.env or {})
    return out


def _write_targets(cmd, ctx):
    out = []
    p = lambda w: ctx.path(w, cmd.cwd)  # noqa: E731
    for op, target in cmd.redirects:
        if op in shell.REDIRECT_WRITE and target and not target.startswith("&") and target != "/dev/null":
            out.append((p(target), "bring"))
    name, args = cmd.name, cmd.args
    if name in _DEST_LAST:
        takes = {"-t", "--target-directory", "-S", "--suffix", "-e", "--rsh", "-m", "--mode", "-o", "-g"}
        target_dir = None
        for i, a in enumerate(args):
            if a in ("-t", "--target-directory") and i + 1 < len(args):
                target_dir = args[i + 1]
            elif a.startswith("--target-directory="):
                target_dir = a.split("=", 1)[1]
        words = _nonopts(args, takes)
        if target_dir:
            out.append((p(target_dir), "bring"))
        elif len(words) >= 2:
            dest = words[-1]
            if ":" in dest and name in ("scp", "rsync") and not dest.startswith(("/", ".", "~")):
                pass  # Remote destination.
            else:
                out.append((p(dest), "bring"))
        if name in ("mv", "gmv"):
            for w in words[:-1]:
                out.append((p(w), "delete"))
    elif name == "tee":
        for w in _nonopts(args):
            out.append((p(w), "bring"))
    elif name in ("sort", "gsort"):
        out.extend((p(w), "bring") for w in _option_values(args, ("-o",), ("--output",), "ktTS"))
    elif name in ("uniq", "guniq"):
        words = _nonopts(args, {"-f", "-s", "-w", "--skip-fields", "--skip-chars", "--check-chars"})
        if len(words) >= 2:
            out.append((p(words[1]), "bring"))
    elif name == "tree":
        out.extend((p(w), "bring") for w in _option_values(args, ("-o",), (), "LPIHT"))
    elif name in ("awk", "gawk", "mawk", "nawk"):
        for script in _awk_programs(args):
            out.extend((p(w), "bring") for w in _awk_outputs(script))
    elif name in ("patch", "gpatch"):
        out.extend(_patch_targets(cmd, ctx))
    elif name in _DELETE:
        for w in _nonopts(args):
            out.append((p(w), "delete"))
    elif name in _MODIFY_ARGS:
        words = chmod_files(args) if name == "chmod" else _nonopts(args)
        if name in ("chown", "chgrp", "chflags") and words and not any(a.startswith("--reference") for a in args):
            words = words[1:]
        for w in words:
            out.append((p(w), "modify"))
    elif (name in ("sed", "gsed") and sed_in_place(args)) or (name == "perl" and perl_in_place(args)):
        words = _nonopts(args, {"-e", "-f", "--expression", "--file"})
        script_given = any(a in ("-e", "-f", "--expression", "--file") for a in args)
        for w in (words if script_given else words[1:]):
            out.append((p(w), "modify"))
        if name != "perl":
            out.extend((p(w), "bring") for w in _sed_outputs(args))
    elif name in ("sed", "gsed"):
        out.extend((p(w), "bring") for w in _sed_outputs(args))
    elif name == "dd":
        for a in args:
            if a.startswith("of="):
                out.append((p(a[3:]), "bring"))
    elif name in ("curl", "wget"):
        out.extend(_download_targets(cmd, ctx))
    elif name == "gh" and args[:2] == ["repo", "clone"]:
        rest = args[2:]
        if "--" in rest:
            rest = rest[:rest.index("--")]
        words = _nonopts(rest, {"-u", "--upstream-remote-name"})
        if len(words) >= 2:
            out.append((p(words[1]), "bring"))
        elif words:
            out.append((p(words[0].rstrip("/").rsplit("/", 1)[-1]), "bring"))
    elif name == "git" and args:
        sub, sub_args = git_subcommand(args)
        _configs, cdir = git_globals(args)
        gcwd = p(cdir) if cdir else cmd.cwd or ctx.cwd
        work_tree = git_work_tree(cmd)
        if work_tree:
            # The work tree, not the current folder, is what checkout, reset and friends rewrite.
            gcwd = ctx.path(work_tree, gcwd)
        out.extend((ctx.path(w, gcwd), "bring") for w in _option_values(sub_args, (), ("--output",)))
        if sub == "format-patch":
            out.extend((ctx.path(w, gcwd), "bring")
                       for w in _option_values(sub_args, ("-o",), ("--output-directory",)))
        if sub in _GIT_UPDATES_TREE:
            out.append((gcwd, "bring"))
        elif sub == "apply" and not any(a in _GIT_APPLY_READ for a in sub_args):
            dirs = _option_values(sub_args, (), ("--directory",))
            out.append((ctx.path(dirs[0], gcwd) if dirs else gcwd, "modify"))
        elif sub == "worktree" and sub_args[:1] == ["add"]:
            words = _nonopts(sub_args[1:], {"-b", "-B", "--reason"})
            if words:
                out.append((ctx.path(words[0], gcwd), "bring"))
        elif sub == "submodule" and sub_args[:1] == ["add"]:
            words = _nonopts(sub_args[1:], {"-b", "--branch", "--name", "--reference", "--depth"})
            if len(words) >= 2:
                out.append((ctx.path(words[1], gcwd), "bring"))
        if sub == "clone":
            words = _nonopts(sub_args, {"-b", "--branch", "-o", "--origin", "--depth", "-c", "--config",
                                         "--reference", "--separate-git-dir", "-u", "--upload-pack", "--filter",
                                         "-j", "--jobs", "--template", "--shallow-since", "--shallow-exclude"})
            if len(words) >= 2:
                out.append((ctx.path(words[1], gcwd), "bring"))
            elif words:
                base = words[0].rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
                out.append((ctx.path(base[:-4] if base.endswith(".git") else base, gcwd), "bring"))
    elif name in ("tar", "gtar", "bsdtar"):
        extract = any(a.startswith("-") and "x" in a and not a.startswith("--") or a in ("--extract", "--get")
                      for a in args) or (args and not args[0].startswith("-") and "x" in args[0])
        if extract:
            dest = None
            for i, a in enumerate(args):
                if a in ("-C", "--directory") and i + 1 < len(args):
                    dest = args[i + 1]
                elif a.startswith("--directory="):
                    dest = a.split("=", 1)[1]
            out.append((p(dest) if dest else cmd.cwd or ctx.cwd, "bring"))
    elif name == "cpio":
        letters = "".join(a[1:] for a in args if a[:1] == "-" and a[:2] != "--")
        through = "p" in letters or "--pass-through" in args
        if through or "i" in letters or "--extract" in args:
            # -i unpacks into the current folder (or -D); -p copies into the folder named last.
            dirs = _option_values(args, ("-D",), ("--directory",))
            words = _nonopts(args, {"-D", "--directory", "-E", "-F", "-H", "-I", "-O", "-R", "-M", "-C"})
            dest = dirs[0] if dirs else words[-1] if through and words else None
            out.append((p(dest) if dest else cmd.cwd or ctx.cwd, "bring"))
    elif name in ("svn", "hg"):
        out.extend(_vcs_targets(cmd, ctx))
    elif name == "aria2c":
        dirs = _option_values(args, ("-d",), ("--dir",))
        out.append((p(dirs[0]) if dirs else cmd.cwd or ctx.cwd, "bring"))
    elif name == "sftp":
        out.append((cmd.cwd or ctx.cwd, "bring"))  # get without a local name saves into the current folder.
    elif name in ("http", "https") and any(a in ("-d", "--download") or (a[:1] == "-" != a[:2] and "d" in a)
                                           for a in args):
        files = _option_values(args, ("-o",), ("--output",))
        out.append((p(files[0]) if files else cmd.cwd or ctx.cwd, "bring"))
    elif name in ("pip", "pip3") and args[:1] == ["download"]:
        dirs = _option_values(args, ("-d",), ("--dest",))
        out.append((p(dirs[0]) if dirs else cmd.cwd or ctx.cwd, "bring"))
    elif name in ("unzip", "7z", "7za", "bsdunzip"):
        dest = None
        for i, a in enumerate(args):
            if a == "-d" and i + 1 < len(args):
                dest = args[i + 1]
            elif a.startswith("-o") and name.startswith("7z") and len(a) > 2:
                dest = a[2:]
        out.append((p(dest) if dest else cmd.cwd or ctx.cwd, "bring"))
    return out


# git subcommands that put new content into the working tree they run in.
_GIT_UPDATES_TREE = {"pull", "fetch", "checkout", "switch", "reset", "merge", "rebase", "am", "cherry-pick",
                     "restore", "submodule", "read-tree", "checkout-index"}
_GIT_APPLY_READ = {"--check", "--stat", "--numstat", "--summary", "--cached"}


def _option_values(args, short, long, stop=""):
    """Values of options like -o X, -oX, -no X, --output X, --output=X (long names may be abbreviated).

    short holds options like "-o"; stop holds other short letters that take a value (they end a cluster).
    """
    out = []
    letters = "".join(s[1:] for s in short)
    for i, a in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else None
        if letters and a.startswith("-") and not a.startswith("--") and len(a) > 1:
            for k, ch in enumerate(a[1:], 1):
                if ch in letters:
                    if k + 1 < len(a):
                        out.append(a[k + 1:])
                    elif nxt is not None:
                        out.append(nxt)
                    break
                if ch in stop:
                    break
        for lg in long:
            opt, eq, val = a.partition("=")
            if long_option(opt, lg, 1):
                if eq:
                    out.append(val)
                elif nxt is not None:
                    out.append(nxt)
    return out


def long_option(arg, full, min_len=2):
    """True when arg is full or a prefix of it that git/getopt accept (at least min_len letters after --)."""
    if not arg.startswith("--") or not full.startswith("--"):
        return False
    body = arg[2:]
    return body == full[2:] or (len(body) >= min_len and full[2:].startswith(body))


def _sed_scripts(args):
    scripts = []
    given = False
    for i, a in enumerate(args):
        if a in ("-e", "--expression") and i + 1 < len(args):
            scripts.append(args[i + 1])
            given = True
        elif a.startswith("--expression="):
            scripts.append(a.split("=", 1)[1])
            given = True
        elif a.startswith("-e") and len(a) > 2 and not a.startswith("--"):
            scripts.append(a[2:])
            given = True
        elif a in ("-f", "--file"):
            given = True
    if not given:
        words = _nonopts(args, {"-l", "--line-length", "-s"})
        if words:
            scripts.append(words[0])
    return scripts


def _sed_skip_regex(s, i):
    """Index just past a delimited regex/text whose delimiter is s[i]."""
    delim = s[i]
    i += 1
    while i < len(s) and s[i] != delim:
        i += 2 if s[i] == "\\" else 1
    return i + 1


def _sed_actions(script):
    """Yield (command letter, argument) for each sed command; s commands yield ("s", flags)."""
    s = script
    n = len(s)
    i = 0
    while i < n:
        while i < n and s[i] in " \t\n;{}":
            i += 1
        # Addresses: numbers, $, /re/, \cREc, ranges and steps.
        while i < n:
            c = s[i]
            if c.isdigit() or c in "$,~+":
                i += 1
            elif c == "/":
                i = _sed_skip_regex(s, i)
                while i < n and s[i] in "IM":
                    i += 1
            elif c == "\\" and i + 1 < n:
                i = _sed_skip_regex(s, i + 1)
            else:
                break
        while i < n and s[i] in " \t!":
            i += 1
        if i >= n:
            return
        c = s[i]
        i += 1
        if c in "sy" and i < n:
            i = _sed_skip_regex(s, i) - 1  # Pattern and replacement share the middle delimiter.
            i = _sed_skip_regex(s, i)
            j = i
            while i < n and s[i] not in ";}\n":
                if s[i] in "wW":
                    i = n if s.find("\n", i) == -1 else s.find("\n", i)
                    break
                i += 1
            yield c, s[j:i]
        elif c in "wWrRaic:btTev":
            j = s.find("\n", i)
            j = n if j == -1 else j
            if c in ":btTv":
                k = min([x for x in (s.find(";", i), s.find("}", i), j) if x != -1])
                j = k
            yield c, s[i:j].strip()
            i = j
        else:
            yield c, ""


def _sed_outputs(args):
    out = []
    for script in _sed_scripts(args):
        for c, arg in _sed_actions(script):
            if c in "wW" and arg:
                out.append(arg)
            elif c == "s":
                m = re.search(r"[wW]\s*(.+)$", arg)
                if m:
                    out.append(m.group(1).strip())
    return [t for t in out if t not in ("/dev/stdout", "/dev/stderr")]


def _awk_programs(args):
    progs = []
    skip = False
    for i, a in enumerate(args):
        if skip:
            skip = False
            continue
        if a in ("-v", "-F", "-f", "--assign", "--field-separator", "--file"):
            skip = True
            continue
        if a.startswith("-"):
            continue
        progs.append(a)
        break
    return progs


# print/printf output redirection: > "file", >> "file", | "command".
_AWK_REDIRECT = re.compile(r"\bprintf?\b[^;{}\n]*?(>>|>|\|)\s*\"([^\"]*)\"")
_AWK_ANY_REDIRECT = re.compile(r"\bprintf?\b[^;{}\n]*?(>>?|\|)")


def _awk_outputs(script):
    out = []
    for m in _AWK_REDIRECT.finditer(script):
        if m.group(1) == "|":
            # A pipe runs a shell command; look for its redirects.
            out.extend(t for op, t in _inner_redirects(m.group(2)))
        else:
            out.append(m.group(2))
    return out


def _inner_redirects(command):
    try:
        parsed = shell.parse(command)
    except Exception:  # noqa: BLE001 - best effort on a nested string
        return []
    return [(op, t) for c in parsed.cmds for op, t in c.redirects if op in shell.REDIRECT_WRITE]


def awk_writes_or_runs(args):
    """True when an awk program redirects output, pipes it, or runs commands."""
    for script in _awk_programs(args):
        if "system(" in script or "getline" in script and "|" in script or _AWK_ANY_REDIRECT.search(script):
            return True
    return any(a in ("-f", "--file") or a.startswith("--file=") for a in args)


def sed_writes_or_runs(args):
    """True when a sed program writes files (w, W, s///w) or runs commands (e, s///e)."""
    if _sed_outputs(args):
        return True
    for script in _sed_scripts(args):
        for c, arg in _sed_actions(script):
            if c == "e" or (c == "s" and "e" in re.split(r"[wW]", arg, 1)[0]):
                return True
    return any(a in ("-f", "--file") or a.startswith("--file=") for a in args)


def _patch_targets(cmd, ctx):
    args = cmd.args
    if any(a in ("--dry-run", "-C", "--check") for a in args):
        return []
    p = lambda w: ctx.path(w, cmd.cwd)  # noqa: E731
    dirs = _option_values(args, ("-d",), ("--directory",), "BDFiopreVYz")
    base = p(dirs[0]) if dirs else cmd.cwd or ctx.cwd
    out = [(base, "modify")]
    out.extend((p(w), "modify") for w in _option_values(args, ("-o",), ("--output",), "BDFdipreVYz"))
    words = _nonopts(args, {"-d", "--directory", "-p", "-i", "--input", "-o", "--output", "-r", "--reject-file",
                            "-B", "--prefix", "-D", "--ifdef", "-F", "--fuzz", "-V", "--version-control",
                            "-z", "--suffix", "-Y", "--basename-prefix"})
    if words:
        out.append((ctx.path(words[0], base), "modify"))
    return out


# Short options that take a value; they end a cluster like -sSLo.
_CURL_VALUE_LETTERS = "AbcCdDeEFHKmoPQrtTuUwxXyYz"
_WGET_VALUE_LETTERS = "aAbBDeIilLoOPQRtTUwWX"


def _download_targets(cmd, ctx):
    out = []
    args = cmd.args
    p = lambda w: ctx.path(w, cmd.cwd)  # noqa: E731
    if cmd.name == "curl":
        out.extend((p(w), "bring") for w in _option_values(args, ("-o",), ("--output",), _CURL_VALUE_LETTERS))
        out.extend((p(w), "bring") for w in _option_values(args, (), ("--output-dir",)))
        for a in args:
            if a in ("--remote-name", "--remote-name-all") or (
                    a.startswith("-") and not a.startswith("--") and "O" in shell.short_flags(a, _CURL_VALUE_LETTERS)):
                out.append((cmd.cwd or ctx.cwd, "bring"))
                break
    else:
        # -O saves the download, -P picks its folder (else it lands in the current one); -o and -a write the log.
        saved = _option_values(args, ("-O", "-P"), ("--output-document", "--directory-prefix"), _WGET_VALUE_LETTERS)
        logs = _option_values(args, ("-o", "-a"), ("--output-file", "--append-output"), _WGET_VALUE_LETTERS)
        out.extend((p(w), "bring") for w in saved + logs)
        if not saved:
            out.append((cmd.cwd or ctx.cwd, "bring"))
    return out


# git options that come before the subcommand and take a value.
_GIT_GLOBAL_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix",
                     "--config-env", "--list-cmds", "--attr-source", "--shallow-file"}


def git_subcommand(args):
    """Return (subcommand, its args) from git's argv[1:], skipping global options."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in _GIT_GLOBAL_VALUE:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return a, args[i + 1:]
    return "", []


def git_work_tree(cmd):
    """The --work-tree or GIT_WORK_TREE a git command runs with, or None."""
    tree = cmd.env.get("GIT_WORK_TREE") if cmd.env else None
    args = cmd.args
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--work-tree" and i + 1 < len(args):
            tree = args[i + 1]
            i += 2
            continue
        if a.startswith("--work-tree="):
            tree = a.split("=", 1)[1]
        elif a in _GIT_GLOBAL_VALUE:
            i += 2
            continue
        elif not a.startswith("-"):
            break
        i += 1
    return tree


def sed_in_place(args):
    """True when sed edits files in place: -i, -i.bak, -ni, -I (BSD), --in-place[=SUF] or a prefix of it."""
    for a in args:
        if a == "--":
            break
        if a.startswith("--"):
            if long_option(a.split("=", 1)[0], "--in-place", 1):
                return True
            continue
        if a.startswith("-") and len(a) > 1:
            for ch in a[1:]:
                if ch in "iI":
                    return True
                if ch in "efl":
                    break  # The rest of the word, or the next word, is this option's value.
    return False


def perl_in_place(args):
    """True when perl edits files in place: -i, -pi, -0pi.bak, -ni and the like."""
    skip = False
    for a in args:
        if skip or a == "--":
            skip = False
            continue
        if a in ("-e", "-E", "-M", "-m", "-I"):
            skip = True  # Its value is the next word.
            continue
        if not a.startswith("-") or a.startswith("--"):
            continue
        for ch in a[1:]:
            if ch == "i":
                return True
            if ch not in "0123456789aclnpsStTuUwWX":
                break
    return False


def copy_landings(cmd, ctx):
    """Where cp, mv, rsync, ditto and scp put each source: (paths an item lands at, folders filled with contents).

    A source ending in / or /. (rsync, BSD cp), and every ditto source, pours its contents into the destination.
    """
    if cmd.name not in _DEST_LAST or cmd.name in ("ln", "install"):
        return [], []
    # Asked once per protected file for the same command and folder. A view in another folder is keyed by the
    # command it reads and that folder; the cache holds the command, so its id is not reused during the run.
    base = cmd._cmd if isinstance(cmd, _AtCwd) else cmd
    cache = ctx.__dict__.setdefault("_copy_landings", {})
    key = (id(base), cmd.cwd)
    hit = cache.get(key)
    if hit is None or hit[0] is not base:
        hit = (base,) + _copy_landings(cmd, ctx)
        cache[key] = hit
    return list(hit[1]), list(hit[2])


def _copy_landings(cmd, ctx):
    args = cmd.args
    takes = {"-t", "--target-directory", "-S", "--suffix", "-e", "--rsh", "-m", "--mode", "-o", "-g"}
    target_dir = None
    for i, a in enumerate(args):
        if a in ("-t", "--target-directory") and i + 1 < len(args):
            target_dir = args[i + 1]
        elif a.startswith("--target-directory="):
            target_dir = a.split("=", 1)[1]
    words = _nonopts(args, takes)
    if target_dir:
        dest, sources = target_dir, words
    elif len(words) >= 2:
        dest, sources = words[-1], words[:-1]
    else:
        return [], []
    if ":" in dest and cmd.name in ("scp", "rsync") and not dest.startswith(("/", ".", "~")):
        return [], []  # Remote destination.
    dest_abs = ctx.path(dest, cmd.cwd)
    into_dir = bool(target_dir) or dest.endswith("/") or len(sources) > 1 or _is_dir(ctx, dest_abs)
    landings = []
    poured = []
    for src in sources:
        if cmd.name == "ditto" or (cmd.name in ("rsync", "cp", "gcp", "scp") and src.endswith(("/", "/."))):
            poured.append(dest_abs)
            continue
        base = os.path.basename(src.rstrip("/"))
        landings.append(os.path.join(dest_abs, base) if into_dir and base else dest_abs)
    return landings, poured


def _is_dir(ctx, path):
    """os.path.isdir, asked once per path in a guard run: a long line copies into the same folder many times."""
    cache = ctx.__dict__.setdefault("_is_dir", {})
    if path not in cache:
        cache[path] = os.path.isdir(path)
    return cache[path]


_HG_GLOBAL_VALUE = {"--cwd", "-R", "--repository", "--repo", "--config", "--encoding", "--encodingmode", "--color",
                    "--pager", "--config-file"}
_HG_BRINGS = {"update", "up", "checkout", "co", "unbundle", "revert", "merge", "rebase", "graft", "import",
              "backout", "unshelve"}


def _vcs_targets(cmd, ctx):
    """Folders svn and hg checkouts and updates fill. hg's --cwd moves the command; -R names the repository
    updated."""
    args = list(cmd.args)
    hg = cmd.name == "hg"
    base = cmd.cwd or ctx.cwd
    repo = None
    i = 0
    while i < len(args) and args[i].startswith("-"):
        a = args[i]
        value = args[i + 1] if i + 1 < len(args) else ""
        if a in _HG_GLOBAL_VALUE:
            if hg and a == "--cwd":
                base = ctx.path(value, base)
            elif hg and a in ("-R", "--repository", "--repo"):
                repo = value
            i += 2
            continue
        if hg and a.startswith("--cwd="):
            base = ctx.path(a.split("=", 1)[1], base)
        elif hg and a.startswith(("--repository=", "--repo=")):
            repo = a.split("=", 1)[1]
        elif hg and a.startswith("-R") and len(a) > 2:
            repo = a[2:]
        i += 1
    sub, rest = (args[i], args[i + 1:]) if i < len(args) else ("", [])
    out = []
    if sub in ("checkout", "co", "export", "clone") and not (hg and sub in ("checkout", "co")):
        words = _nonopts(rest, {"-r", "--revision", "-u", "--updaterev", "-b", "--branch", "--depth", "--username",
                                "--password", "-e", "--ssh", "--remotecmd"})
        if len(words) >= 2:
            out.append((ctx.path(words[1], base), "bring"))
        elif words:
            out.append((ctx.path(words[0].rstrip("/").rsplit("/", 1)[-1], base), "bring"))
    elif hg and (sub in _HG_BRINGS or (sub == "pull" and any(a in ("-u", "--update") for a in rest))):
        out.append((ctx.path(repo, base) if repo else base, "bring"))
    return out


def git_globals(args):
    """Global -c key=value pairs and the -C folder before the subcommand: every -C, each read from the one
    before it (git -C a -C b runs in a/b), or None."""
    configs = []
    cdirs = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-c", "--config-env") and i + 1 < len(args):
            configs.append(args[i + 1])
            i += 2
            continue
        if a.startswith("--config-env="):
            configs.append(a.split("=", 1)[1])
            i += 1
            continue
        if a == "-C" and i + 1 < len(args):
            # Each -C is read from the folder the one before it moved to; an empty one moves nowhere.
            if args[i + 1]:
                cdirs.append(args[i + 1])
            i += 2
            continue
        if a in _GIT_GLOBAL_VALUE:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        break
    return configs, _join_dirs(cdirs)


def _join_dirs(dirs):
    """os.path.join(*dirs) in one pass: the last absolute folder and those after it, or None."""
    if not dirs:
        return None
    start = max((i for i, d in enumerate(dirs) if d.startswith(os.sep)), default=0)
    return os.sep.join(d.rstrip(os.sep) or os.sep for d in dirs[start:]).replace(os.sep * 2, os.sep)


# Programs that change every file below a folder when given -r, -R or --recursive.
_RECURSIVE_WRITERS = {"rm", "chmod", "chown", "chgrp", "chflags", "gzip", "gunzip", "bzip2", "bunzip2", "xz",
                      "unxz", "zstd", "unzstd", "lz4", "setfacl", "pigz", "trash"}
# find actions that delete or run something on each path found.
_FIND_WRITE_ACTIONS = {"-delete", "-exec", "-execdir", "-ok", "-okdir"}
_FIND_GLOBAL = {"-H", "-L", "-P", "-E", "-X", "-d", "-s", "-x", "-O0", "-O1", "-O2", "-O3"}
_FIND_NAME_TESTS = {"-name": False, "-iname": True}
# find tests that let through names a -name test alone would not, so the name tests narrow nothing.
_FIND_WIDENING = {"!", "-not", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-lname",
                  "-ilname", "-samefile", "-inum", "-links"}
# Programs run by find -exec that only read what they are given.
_EXEC_READERS = {"cat", "grep", "egrep", "fgrep", "rg", "head", "tail", "wc", "ls", "file", "stat", "md5", "md5sum",
                 "shasum", "sha1sum", "sha256sum", "du", "echo", "printf", "test", "[", "basename", "dirname",
                 "realpath", "readlink", "diff", "cmp", "jq", "less", "more", "true", "od", "xxd", "hexdump",
                 "strings", "otool", "nm", "objdump"}
# A mode word chmod takes first: octal, or symbolic, dash forms included (-x, u-w,go+r).
_CHMOD_MODE = re.compile(r"^(?:[0-7]{1,5}|[ugoa]*(?:[-+=][rwxXstugo]*)+(?:,[ugoa]*(?:[-+=][rwxXstugo]*)+)*)$")
_NAMES_UNDER_LIMIT = 2000
_NAMES_UNDER = {}


def chmod_files(args):
    """The files chmod changes: the words after its mode, which may start with a dash (-x)."""
    files = []
    mode_seen = any(a.startswith("--reference") for a in args)
    only_files = False
    for a in args:
        if only_files:
            files.append(a)
        elif a == "--":
            only_files = True
        elif not mode_seen and _CHMOD_MODE.match(a):
            mode_seen = True
        elif a.startswith("-") and a != "-":
            continue
        elif not mode_seen:
            mode_seen = True
        else:
            files.append(a)
    return files


_PERM_LETTERS = frozenset("rwxst")


def chmod_removes(args):
    """The permission letters (r, w, x, s, t) chmod's argv may take away from some file, or None when it can't
    tell (--reference, no mode, or a clause copying another class's bits such as g=u). A numeric mode is set
    whole, so every bit it leaves out is removed; an = clause removes what it does not list."""
    if any(a.startswith("--reference") for a in args):
        return None
    mode = None
    for a in args:
        if a == "--":
            break
        if _CHMOD_MODE.match(a):
            mode = a
            break
        if not a.startswith("-"):
            break
    if mode is None:
        return None
    if mode[0].isdigit():
        return _numeric_removes(int(mode, 8))
    removed = set()
    for clause in mode.split(","):
        for op, perms in re.findall(r"([-+=])([rwxXstugo]*)", clause):
            if set(perms) & set("ugo"):
                return None
            # X sets x only on folders and files that already have it, so it does not keep x on every file.
            listed = set(perms) - {"X"}
            if op == "-":
                removed |= listed | ({"x"} if "X" in perms else set())
            elif op == "=":
                removed |= _PERM_LETTERS - listed
    return removed


def _numeric_removes(bits):
    removed = set()
    for shift in (6, 3, 0):
        for letter, bit in (("r", 4), ("w", 2), ("x", 1)):
            if not (bits >> shift) & bit:
                removed.add(letter)
    if not bits & 0o6000:
        removed.add("s")
    if not bits & 0o1000:
        removed.add("t")
    return removed


def find_spares_files(args):
    """True when find -delete can only remove empty folders: -type d with no -exec and nothing that widens the
    match (find . -type d -empty -delete)."""
    typed_dirs = any(a == "-type" and b == "d" for a, b in zip(args, args[1:]))
    widened = any(a in ("-o", "-or", "!", "-not", ",") for a in args)
    runs = any(a in ("-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls") for a in args)
    return typed_dirs and not widened and not runs


def _found_patterns(predicates):
    """find's name tests from Cmd.found_predicates as (pattern, ignore_case), or None when any name may be found
    (no name test, or a path, regex, negation or ls listing)."""
    names = []
    for test, value in predicates:
        if test in _FIND_NAME_TESTS:
            names.append((value, _FIND_NAME_TESTS[test]))
        elif test not in ("-type", "-o", "-or"):
            return None
    return tuple(names) or None


def _recursive_flag(name, args):
    # The ch* programs take only -R; to chmod, -r is a mode (take read away).
    letters = set("R") if name in ("chmod", "chown", "chgrp", "chflags", "setfacl") else set("rR")
    for a in args:
        if a == "--":
            break
        if a == "--recursive":
            return True
        if not a.startswith("-") or a.startswith("--") or (name == "chmod" and _CHMOD_MODE.match(a)):
            continue
        if letters & set(a[1:]):
            return True
    return False


def _find_exec_writes(expr):
    """True when a find -exec, -execdir, -ok or -okdir runs a program that may write."""
    j = 0
    while j < len(expr):
        if expr[j] in ("-exec", "-execdir", "-ok", "-okdir") and j + 1 < len(expr):
            prog = os.path.basename(expr[j + 1])
            rest = expr[j + 2:]
            end = next((k for k, w in enumerate(rest) if w in (";", "+")), len(rest))
            if prog not in _EXEC_READERS and not (prog == "chmod" and chmod_removes(rest[:end]) == set()):
                return True
            j += 2 + end
        j += 1
    return False


def _find_parts(args):
    """(roots, name patterns or None, whether it writes) for find's argv[1:]."""
    i = 0
    while i < len(args) and args[i] in _FIND_GLOBAL:
        i += 1
    roots = []
    while i < len(args):
        a = args[i]
        if a == "-f" and i + 1 < len(args):
            roots.append(args[i + 1])
            i += 2
            continue
        if a.startswith("-") or a in ("(", "!", ")"):
            break
        roots.append(a)
        i += 1
    expr = args[i:]
    writes = "-delete" in expr or _find_exec_writes(expr)
    patterns = []
    for j, a in enumerate(expr):
        if a in _FIND_WIDENING:
            patterns = None
            break
        if a in _FIND_NAME_TESTS and j + 1 < len(expr):
            patterns.append((expr[j + 1], _FIND_NAME_TESTS[a]))
    return roots or ["."], (tuple(patterns) if patterns else None), writes


def _archive_sources(name, args):
    """Files an archiver removes once archived (tar --remove-files, zip -m, 7z -sdel), and the folder they are
    read in (tar -C), or ([], None)."""
    if name in ("tar", "gtar", "bsdtar"):
        if "--remove-files" not in args:
            return [], None
        words, cdir, skip = [], None, 0
        for i, a in enumerate(args):
            if skip:
                skip -= 1
                continue
            if a in ("-C", "--directory") and i + 1 < len(args):
                cdir, skip = args[i + 1], 1
            elif a in ("-f", "--file", "-T", "--files-from", "-X", "--exclude-from", "-b", "-H", "--format",
                       "-I", "--use-compress-program", "--exclude"):
                skip = 1
            elif a.startswith("-") and not a.startswith("--") and "f" in a[1:]:
                skip = 1
            elif i == 0 and not a.startswith("-") and "f" in a:
                skip = 1  # Old-style bundled letters: cf archive.
            elif not a.startswith("-") and i > 0:
                words.append(a)
        return words, cdir
    if name == "zip":
        if not any((a.startswith("-") and not a.startswith("--") and "m" in a[1:]) or a == "--move" for a in args):
            return [], None
        words = _nonopts(args, {"-b", "-n", "-t", "-tt", "-x", "-i", "-P", "-Z", "-O", "--out"})
        return words[1:], None
    if name in ("7z", "7za") and "-sdel" in args:
        return _nonopts(args)[2:], None
    return [], None


_FD_VALUES = {"-e", "--extension", "-t", "--type", "-E", "--exclude", "-d", "--max-depth", "-j", "--threads", "-S",
              "--size", "--changed-within", "--changed-before"}


def _recursive_words(cmd):
    """(words, patterns, folder they are read in or None) for one command, or None."""
    name, args = cmd.name, list(cmd.args)
    if name == "chmod" and chmod_removes(args) == set():
        return None
    roots = getattr(cmd, "found_roots", ())
    if roots and os.path.basename(name) not in _EXEC_READERS:
        # A writer run on paths find or ls produces (find -exec, or find piped into xargs and a remover) reaches what they may find.
        return (list(roots), _found_patterns(getattr(cmd, "found_predicates", ())), None)
    if name in ("find", "gfind"):
        roots, patterns, writes = _find_parts(args)
        if "-delete" in args and not _find_exec_writes(args) and find_spares_files(args):
            return None
        return (roots, patterns, None) if writes else None
    if name in ("fd", "fdfind"):
        cut = next((i for i, a in enumerate(args) if a in ("-x", "--exec", "-X", "--exec-batch")), None)
        if cut is None or os.path.basename(args[cut + 1] if cut + 1 < len(args) else "") in _EXEC_READERS:
            return None
        return (_nonopts(args[:cut], _FD_VALUES)[1:] or ["."], None, None)
    if name in _RECURSIVE_WRITERS and _recursive_flag(name, args):
        if name == "chmod":
            words = chmod_files(args)
        else:
            words = _nonopts(args, {"-S", "--suffix", "-b", "-B", "-m", "-M", "-x", "-X"})
            if name in ("chown", "chgrp", "chflags", "setfacl") and not any(a.startswith("--reference")
                                                                           for a in args):
                words = words[1:]
        return (words, None, None)
    words, cdir = _archive_sources(name, args)
    return (words, None, cdir) if words else None


def recursive_targets(cmd, ctx):
    """Folders a command acts on recursively or through paths it finds, as [(folder, patterns)]: find with
    -delete or a writing -exec (its roots), fd -x, a -r/-R writer (rm, chmod, chown, gzip...), and an archiver
    that removes what it archives. patterns is None when any name below the folder is reached, else the
    (pattern, ignore_case) name tests a found name must pass. Words are read in each folder the command may run
    in."""
    cache = ctx.__dict__.setdefault("_recursive_targets", {})
    hit = cache.get(id(cmd))
    if hit is not None and hit[0] is cmd:
        return list(hit[1])
    out = []
    found = _recursive_words(cmd)
    if found:
        words, patterns, cdir = found
        for view in at_each_cwd(cmd):
            base = view.cwd or ctx.cwd
            try:
                base = ctx.path(cdir, base) if cdir else base
            except (TypeError, ValueError):
                pass
            for w in words:
                try:
                    out.append((ctx.path(w, base), patterns))
                except (TypeError, ValueError):
                    continue
    cache[id(cmd)] = (cmd, tuple(out))
    return out


def recursive_touches(cmd, ctx, path, names=(), sure=False):
    """True when a folder the command acts on recursively is path or holds it, and its name tests can let path
    (or, for a folder, a name inside it or one of names, files it may hold later) through. A path that does
    not exist can't be reached this way. With sure, only names there now count, and a folder too large to list
    does not."""
    targets = recursive_targets(cmd, ctx)
    if not targets or not os.path.lexists(path):
        return False
    for folder, patterns in targets:
        if holds(folder, path) and _names_may_match(patterns, folder, path, () if sure else names, sure):
            return True
    return False


def _names_may_match(patterns, folder, path, extra=(), sure=False):
    if patterns is None or globs.has_magic(folder):
        return True
    rel = os.path.relpath(os.path.normpath(path), os.path.normpath(folder))
    names = [os.path.basename(os.path.normpath(folder))] + [p for p in rel.split(os.sep) if p not in ("", ".")]
    under = _names_under(path)
    if under is None:
        return not sure
    names.extend(under)
    names.extend(extra)
    for pattern, fold in patterns:
        want = pattern.lower() if fold else pattern
        for n in names:
            if fnmatch.fnmatchcase(n.lower() if fold else n, want):
                return True
    return False


def _names_under(path):
    """Names of the entries below a folder (a bounded walk), [] for a file, None when there are too many."""
    if path not in _NAMES_UNDER:
        names = []
        if os.path.isdir(path) and not os.path.islink(path):
            for _top, dirs, files in os.walk(path):
                names.extend(dirs)
                names.extend(files)
                if len(names) > _NAMES_UNDER_LIMIT:
                    names = None
                    break
        _NAMES_UNDER[path] = names
    return _NAMES_UNDER[path]
