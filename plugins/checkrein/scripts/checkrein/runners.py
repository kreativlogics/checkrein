"""What a package runner runs: npx, npm exec, pnpm dlx, yarn dlx, bunx, corepack, deno run npm:, pipx run, uvx.

These fetch a package and run one of its programs, so the program is only known from the package spec. Rules that
care about a program (the skill installers of SKL03, a nested `claude`) read it from here, so every runner form is
read the same way for all of them.
"""

import re

# Packages whose program name differs from the package's own name.
KNOWN_BINS = {"@anthropic-ai/claude-code": "claude"}

# Runner forms: program -> the subcommand that runs a package (None: the program itself does).
_FORMS = {
    "npx": None, "pnpx": None, "bunx": None, "uvx": None,
    "npm": ("exec", "x"), "pnpm": ("dlx",), "yarn": ("dlx",), "yarnpkg": ("dlx",), "bun": ("x",),
    "pipx": ("run",), "uv": ("tool run",), "deno": ("run",),
}
_PYTHON = {"pipx", "uvx", "uv"}
# Package managers corepack runs by name (corepack pnpm dlx ...).
_COREPACK = {"npm", "npx", "pnpm", "pnpx", "yarn", "yarnpkg"}

# Options naming the package to fetch; the program run is then the first word after the options.
_PACKAGE_OPTS = {"-p", "--package", "--from", "--spec", "--with"}
# Options that run a shell string instead of a named program (npx -c, pnpm dlx -c).
_SHELL_OPTS = {"-c", "--call", "--shell-mode"}
# Other options that take a value, so the value isn't read as the package.
_VALUE_OPTS = {
    "--registry", "--cache", "--userconfig", "--prefix", "-w", "--workspace", "--node-options", "--script-shell",
    "--loglevel", "--allow-build", "--reporter", "--python", "--pip-args", "--index-url", "-i", "--index",
    "--extra-index-url", "--with-requirements", "--with-editable", "--constraints", "--overrides", "--directory",
    "--config", "--import-map", "--lock", "--cert", "--location", "--seed", "-L", "--log-level", "--ext",
}
# Options that take a value only for some runners: uvx -p is the Python version, the npm runner's -p the package.
_PYTHON_VALUE = {"-p"}


class Run(object):
    """A runner call: the program it runs (lower case, or None when the spec can't be named), that program's
    arguments, the package names it names, and the spec checkrein can't name (or None)."""

    __slots__ = ("bin", "args", "packages", "unreadable")

    def __init__(self, bin_name, args, packages, unreadable):
        self.bin = bin_name
        self.args = args
        self.packages = packages
        self.unreadable = unreadable


def resolve(cmd):
    """The Run for a package runner command, or None for any other command."""
    return _resolve(cmd.name, list(cmd.args))


def _resolve(name, args):
    if name == "corepack":
        if not args:
            return None
        manager = args[0].split("@", 1)[0].lower()
        return _resolve(manager, args[1:]) if manager in _COREPACK else None
    if name not in _FORMS:
        return None
    subs = _FORMS[name]
    if subs is not None:
        if name == "uv":
            if args[:2] != ["tool", "run"]:
                return None
            args = args[2:]
        elif not args or args[0] not in subs:
            return None
        else:
            args = args[1:]
    if name == "deno":
        return _deno(args)
    return _read(args, python=name in _PYTHON)


def _read(args, python):
    packages = []
    i = 0
    while i < len(args):
        a = args[i]
        opt, eq, val = a.partition("=")
        if a == "--":
            i += 1
            break
        if not a.startswith("-") or a == "-":
            break
        if opt in _SHELL_OPTS:
            # The program is inside a shell string: checkrein can't name it here.
            return Run(None, args[i + 1:], packages, val if eq else (args[i + 1] if i + 1 < len(args) else a))
        if opt in _PACKAGE_OPTS or (python and opt in _PYTHON_VALUE):
            value = val if eq else (args[i + 1] if i + 1 < len(args) else "")
            if opt in _PACKAGE_OPTS:
                packages.append(value)
            i += 1 if eq else 2
            continue
        if opt in _VALUE_OPTS and not eq:
            i += 2
            continue
        i += 1
    if i >= len(args):
        return Run(None, [], packages, _first_unreadable(packages))
    spec, rest = args[i], args[i + 1:]
    if rest[:1] == ["--"]:
        rest = rest[1:]  # npm exec <pkg> -- <args>: the arguments after -- go to the program.
    named = packages + ([] if packages else [spec])
    unreadable = _first_unreadable(named)
    if packages:
        # With --package the word after the options is the program itself (the npm runner's -p, then the package, then claude).
        program = None if _dynamic(spec) else spec.lower()
        if program is None:
            unreadable = unreadable or spec
    else:
        program = bin_of(spec, python)
    return Run(program, rest, [p for p in (package_of(n, python) for n in named) if p], unreadable)


def _deno(args):
    i = 0
    while i < len(args):
        a = args[i]
        if not a.startswith("-") or a == "-":
            break
        opt, eq, _val = a.partition("=")
        i += 2 if opt in _VALUE_OPTS and not eq else 1
    if i >= len(args):
        return None
    spec, rest = args[i], args[i + 1:]
    if _dynamic(spec):
        return Run(None, rest, [], spec)
    low = spec.lower()
    if low.startswith(("npm:", "jsr:")):
        return Run(bin_of(spec, False), rest, [package_of(spec, False)], None)
    if "://" in low or low.startswith(("data:", "blob:")):
        return Run(None, rest, [], spec)
    return None  # A local script: an interpreter run, not a package.


def _dynamic(word):
    """True for a word built at run time (a variable or substitution)."""
    return type(word).__name__ == "_Dyn" or any(c in word for c in "$`") or "__SUBST__" in word


def _unreadable_spec(spec):
    """True when spec can't be turned into a name: a run-time word, a URL, a git or file source, or a tarball. A
    local folder is not: it holds code the agent could run directly anyway."""
    if _dynamic(spec):
        return True
    low = spec.lower()
    if low.startswith(("npm:", "jsr:")):
        low = low[4:]
    if "://" in low or low.startswith(("git+", "git@", "file:", "link:", "http:", "https:", "data:")):
        return True
    return low.endswith((".tgz", ".tar.gz", ".tar", ".zip", ".whl", ".tar.bz2", ".tar.xz"))


def _local(spec):
    return spec.startswith(("/", ".", "~"))


def _first_unreadable(specs):
    for spec in specs:
        if spec and _unreadable_spec(spec):
            return spec
    return None


def package_of(spec, python=False):
    """The package name a spec names, in lower case: no version, no npm:/jsr:/github: prefix; None when it can't be
    named."""
    if not spec or _unreadable_spec(spec) or _local(spec):
        return None
    s = spec.strip().lower()
    if s.startswith(("npm:", "jsr:")):
        s = s[4:]
    if s.startswith(("github:", "gitlab:", "bitbucket:", "gist:")):
        s = s.split(":", 1)[1].split("#", 1)[0]
        return s.rstrip("/").rsplit("/", 1)[-1] or None
    s = s.split("#", 1)[0]
    if python:
        return re.split(r"[=<>~!\[@;\s]", s, 1)[0] or None
    if s.startswith("@"):
        scope, _, rest = s.partition("/")
        return "%s/%s" % (scope, rest.split("@", 1)[0]) if rest else None
    name = s.split("@", 1)[0]
    # owner/repo is a GitHub shorthand: the package is the repository.
    return name.rstrip("/").rsplit("/", 1)[-1] or None


def bin_of(spec, python=False):
    """The program a package spec runs: the known name for packages that differ, else the name without its scope."""
    if spec and _local(spec) and not _unreadable_spec(spec):
        # A local folder or program runs under its own name (npx ./node_modules/.bin/skills).
        return spec.rstrip("/").rsplit("/", 1)[-1].lower() or None
    package = package_of(spec, python)
    if not package:
        return None
    return KNOWN_BINS.get(package, package.rsplit("/", 1)[-1])


class _Program(object):
    """A runner command seen as the program it runs: its name and arguments, the rest from the runner command."""

    def __init__(self, cmd, run):
        self._cmd = cmd
        self.name = run.bin
        self.args = list(run.args)
        self.argv = [run.bin] + self.args

    def __getattr__(self, name):
        return getattr(self._cmd, name)


# Claude Code run by its installed file rather than by name: the native build's versions folder, and the npm
# package's cli.js run by node.
_CLAUDE_VERSIONS = "/.local/share/claude/versions/"
_CLAUDE_CLI = "@anthropic-ai/claude-code/cli.js"
_JS_RUNNERS = {"node", "nodejs", "bun", "deno"}


def program(cmd):
    """cmd itself, or for a package runner a view of the program it runs (the Claude Code package run by a runner is
    claude ...); None when the runner's program can't be named. Claude Code's installed files count as claude."""
    run = resolve(cmd)
    if run is None:
        return _installed_claude(cmd) or cmd
    return _Program(cmd, run) if run.bin else None


def _installed_claude(cmd):
    """A view of cmd as `claude` when it runs Claude Code's installed file, or None."""
    argv = list(getattr(cmd, "argv", None) or [cmd.name] + list(cmd.args))
    first = str(argv[0]).replace("\\", "/") if argv else ""
    if _CLAUDE_VERSIONS in first:
        return _Program(cmd, Run("claude", argv[1:], [], None))
    if cmd.name in _JS_RUNNERS:
        for i, a in enumerate(argv[1:], 1):
            if str(a).startswith("-"):
                continue
            if str(a).replace("\\", "/").endswith(_CLAUDE_CLI):
                return _Program(cmd, Run("claude", argv[i + 1:], [], None))
            break
    return None
