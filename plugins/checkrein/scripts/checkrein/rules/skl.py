"""SKL01-SKL04: the install gate's side doors."""

import os
import re

from ..context import UNPACKERS, Hit, Landings, at_each_cwd, base_of, claude_dir, copy_landings, cwds, inside, \
    reach, recursive_targets, recursive_touches, same_path, unknown_relative, write_targets
from .. import globs
from .. import ledger
from .. import runners
from .. import shell

_GATE = "/checkrein:vet"
GATE_MUTATING = {"approve", "adopt", "forget"}


def check(ctx):
    hits = []
    hits.extend(_side_door_writes(ctx))
    if ctx.tool_name != "Bash":
        return hits
    for cmd in ctx.parsed.cmds:
        agent = runners.program(cmd)
        if agent is not None and agent.name == "claude":
            hits.extend(_plugin_cli(agent, ctx))
        hits.extend(_runners(cmd, ctx))
        hits.extend(_gate_decision(cmd, ctx))
    return hits


# Folders in a .claude folder whose files Claude Code loads as skills, slash commands or subagents.
_LOADED = ("skills", "commands", "agents")


def roots(ctx):
    extra = ctx.eff.get("extra_skill_roots") or []
    out = [path for _scope, path in ledger.skill_roots(ctx.home, ctx.project_dir, extra)]
    user = claude_dir(ctx.home)
    out.extend(os.path.join(user, name) for name in ("commands", "agents", "plugins"))
    if ctx.project_dir:
        out.extend(os.path.join(ctx.project_dir, ".claude", name) for name in ("commands", "agents"))
    return out


def _nested_root(path, ctx):
    """The .claude folder, or the .claude/skills, commands or agents folder, that a path in the project lies in or
    is: Claude Code loads those at any depth of the project (packages/app/.claude/skills)."""
    if not ctx.project_dir or ".claude" not in path or not inside(path, ctx.project_dir):
        return None
    parts = os.path.normpath(path).split(os.sep)
    for i, part in enumerate(parts):
        if part.lower() != ".claude":
            continue
        rest = parts[i + 1:]
        if not rest:
            return path
        if rest[0].lower() in _LOADED:
            return os.sep.join(parts[:i + 2])
    return None


def _side_door_writes(ctx):
    hits = []
    plugins = os.path.join(claude_dir(ctx.home), "plugins")
    if ctx.tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        fp = ctx.file_path()
        if inside(fp, plugins):
            hits.append(Hit("SKL01", "Writes into Claude Code's plugin folder, which only plugin installs should "
                                     "change. Install plugins through %s." % _GATE))
        return hits
    if ctx.tool_name != "Bash":
        return hits
    all_roots = roots(ctx)
    for cmd in ctx.parsed.cmds:
        if _brings_into_unknown(cmd, ctx):
            hits.append(Hit("SKL01", "Puts files into a .claude folder from a folder checkrein can't tell (%s). Vet "
                                     "and install with %s instead." % (cmd.name, _GATE)))
            return hits
        changed = _root_changed_by_exec(cmd, ctx, all_roots)
        if changed:
            hits.append(Hit("SKL01", "Runs %s on the files in %s, changing what a vetted skill or plugin holds. "
                                     "Change your own skills with the Edit tool; vet and install others with %s."
                            % (cmd.name, _short(changed, ctx), _GATE)))
            return hits
        for root in _roots_brought_into(cmd, ctx, all_roots):
            if not _local_copy(cmd, ctx, root):
                where = _short(root, ctx)
                hits.append(Hit("SKL01", "Puts files into %s outside the install gate (%s). Vet and install with "
                                "%s instead; for a skill you wrote yourself, run /checkrein:status adopt "
                                "afterwards." % (where, cmd.name, _GATE)))
                return hits
    return hits


# Programs that only remove what they are given; removing files from a vetted folder is not a way in.
_REMOVERS = {"rm", "rmdir", "unlink", "trash", "shred"}
_EXEC_OPTIONS = {"-exec", "-execdir", "-ok", "-okdir", "-x", "--exec", "-X", "--exec-batch"}


def _root_changed_by_exec(cmd, ctx, all_roots):
    """The skill or plugin folder a find or fd run changes files in through a program it runs on each path
    found (find over a skills folder with -exec sed -i, or find piped into xargs sed -i), or None. Removing files there is
    not a way in, and the project's own folders are edited like any of its files."""
    fed = bool(getattr(cmd, "found_roots", ())) and cmd.name not in _REMOVERS
    runs_each = any(a in _EXEC_OPTIONS for a in cmd.args)
    if not fed and (cmd.name not in ("find", "gfind", "fd", "fdfind") or not runs_each):
        return None
    targets = recursive_targets(cmd, ctx)
    for root in all_roots:
        if ctx.project_dir and inside(root, ctx.project_dir):
            continue  # The project's own skills and commands are its files, edited like any other.
        for folder, _patterns in targets:
            if inside(folder, root):
                return root
        if recursive_touches(cmd, ctx, root, ("SKILL.md", "plugin.json")):
            return root
    return None


def _brings_into_unknown(cmd, ctx):
    """A copy into .claude, .claude/skills or .claude/plugins by a relative name from an unknown folder."""
    if not getattr(cmd, "cwd_unknown", False):
        return False
    paths = [p for p, kind in write_targets(cmd, ctx) if kind == "bring"]
    for view in at_each_cwd(cmd):
        landings, poured = copy_landings(view, ctx)
        paths.extend(landings)
        paths.extend(poured)
    for path in paths:
        parts = unknown_relative(path) or []
        if ".claude" in parts:
            rest = parts[parts.index(".claude") + 1:]
            if not rest or rest[0] in ("plugins",) + _LOADED:
                return True
    return False


# Copy programs whose sources are all words but the last.
_COPIES = {"cp", "gcp", "mv", "gmv"}
_PLAIN_COPY_FLAGS = {"-r", "-R", "-p", "-f", "-v", "-a", "-n", "-i", "-rf", "-fr", "-rp", "-pr", "-av", "-va"}


def _local_copy(cmd, ctx, root):
    """A plain copy of files already in the project into a commands or agents folder (cp tpl.md
    .claude/commands/review.md). The Write tool can put the same text there, so only files brought in from
    outside the project, clones and downloads count for those folders."""
    if os.path.basename(root).lower() not in ("commands", "agents") or cmd.name not in _COPIES:
        return False
    if getattr(cmd, "cwd_unknown", False) or not ctx.project_dir:
        return False
    if any(a.startswith("-") and a not in _PLAIN_COPY_FLAGS for a in cmd.args):
        return False
    words = [a for a in cmd.args if not a.startswith("-")]
    if len(words) < 2:
        return False
    return all(not isinstance(w, shell._Dyn) and "$" not in w and not globs.has_magic(w)
               and inside(ctx.path(w, c), ctx.project_dir) for w in words[:-1] for c in cwds(cmd))


def _roots_brought_into(cmd, ctx, all_roots):
    """The skill, command, agent and plugin folders a command brings files into, nested project ones first.

    Landings and write targets are worked out once per command; a long command line holds tens of thousands."""
    written = write_targets(cmd, ctx)
    landings, poured = [], []
    for view in at_each_cwd(cmd):
        got = copy_landings(view, ctx)
        landings.extend(got[0])
        poured.extend(got[1])
    brought = [path for path, kind in written if kind == "bring"]
    out = []
    # A copy names where each item lands; a clone, download or unpack names the folder it fills.
    for path in (landings + poured) or brought:
        root = _nested_root(path, ctx)
        if root and root not in out:
            out.append(root)
    filled = (brought if cmd.name in UNPACKERS else []) + poured
    grouped = Landings(landings)
    for root in all_roots:
        if root in out:
            continue
        if any(inside(path, root) for path in brought) or grouped.any_inside(root):
            out.append(root)
        # A copied folder that lands as the root or a folder holding it (cp -r stage/skills ~/.claude/), and an
        # archive, checkout or folder poured into a folder above the root, up to home or the project's .claude
        # (tar -xf x.tar -C ~, rsync -a stage/ ~/), can create skills.
        elif grouped.any_holds(root):
            out.append(root)
        elif filled and _fills_above(ctx, filled, root):
            out.append(root)
    return out


def _fills_above(ctx, filled, root):
    # The folders above root are worked out once per root, not once per source poured.
    above = reach(root, base_of(ctx, root))
    return any(same_path(f, a) for f in filled for a in above)


def _short(path, ctx):
    return "~" + path[len(ctx.home):] if path.startswith(ctx.home) else path


def is_checkrein(spec):
    return bool(spec) and spec.split("@", 1)[0].lower() == "checkrein"


def own_checkrein(spec, ctx):
    """True for checkrein itself: its name, from its own marketplace or with none named. A plugin called
    checkrein from another marketplace is someone else's code and goes through the install gate."""
    market = spec.partition("@")[2] if isinstance(spec, str) else ""
    return is_checkrein(spec) and (not market or market in own_marketplaces(ctx))


def own_marketplaces(ctx):
    """Names checkrein's marketplace may have: its own, and the one in the install and data paths."""
    names = {"checkrein"}
    root = (ctx.plugin_root or "").replace(os.sep, "/")
    for marker in ("/plugins/cache/", "/plugins/marketplaces/"):
        if marker in root:
            names.add(root.split(marker, 1)[1].split("/", 1)[0])
    base = os.path.basename(os.path.normpath(ctx.data_dir or ""))
    if base.startswith("checkrein-"):
        names.add(base[len("checkrein-"):])
    return names


# Options of `claude plugin ...` that take a value, from each subcommand's --help. Short forms map to long ones.
_PLUGIN_VALUE = {"--scope", "--accept-command", "--config", "--marketplace", "--author", "--author-email",
                 "--description", "--profile"}
_PLUGIN_VARIADIC = {"--sparse", "--with"}
_PLUGIN_SHORT = {"-s": "--scope", "-a": "--all", "-y": "--yes", "-h": "--help", "-f": "--force"}
_PLUGIN_ALIASES = {"i": "install", "remove": "uninstall", "rm": "uninstall", "new": "init", "autoremove": "prune"}
_MARKETPLACE_ALIASES = {"rm": "remove"}


class PluginCall(object):
    """A parsed `claude plugin|plugins ...` call: positional words (subcommand first), option values, flags."""

    def __init__(self, words, opts, flags):
        self.words = words
        self.opts = opts
        self.flags = flags

    def word(self, index):
        return self.words[index] if len(self.words) > index else None


def plugin_call(cmd):
    """Parse `claude [options] plugin|plugins ...`, or None for any other claude command."""
    if cmd.name != "claude":
        return None
    args = list(cmd.args)
    start = None
    for i, a in enumerate(args):
        if a.startswith("-"):
            continue
        if a in ("plugin", "plugins"):
            start = i + 1
            break
        if i > 0 and args[i - 1].startswith("-") and "=" not in args[i - 1]:
            continue  # Maybe the value of a top-level option; keep looking.
        return None
    if start is None:
        return None
    words, opts, flags = [], {}, set()
    rest = args[start:]
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--":
            words.extend(rest[i + 1:])
            break
        if a.startswith("--"):
            name, eq, val = a.partition("=")
            if name in _PLUGIN_VALUE:
                if not eq:
                    i += 1
                    val = rest[i] if i < len(rest) else ""
                opts.setdefault(name, []).append(val)
            elif name in _PLUGIN_VARIADIC:
                # Commander's variadic options take every following word up to the next option.
                vals = [val] if eq else []
                while i + 1 < len(rest) and not rest[i + 1].startswith("-"):
                    i += 1
                    vals.append(rest[i])
                opts.setdefault(name, []).extend(vals)
            else:
                flags.add(name)
        elif a.startswith("-") and len(a) > 1:
            for k, ch in enumerate(a[1:], 1):
                name = _PLUGIN_SHORT.get("-" + ch, "-" + ch)
                if name in _PLUGIN_VALUE:
                    val = a[k + 1:]
                    if not val:
                        i += 1
                        val = rest[i] if i < len(rest) else ""
                    opts.setdefault(name, []).append(val)
                    break
                flags.add(name)
        else:
            words.append(a)
        i += 1
    if words:
        words[0] = _PLUGIN_ALIASES.get(words[0], words[0])
        if words[0] == "marketplace" and len(words) > 1:
            words[1] = _MARKETPLACE_ALIASES.get(words[1], words[1])
    return PluginCall(words, opts, flags)


def _plugin_cli(cmd, ctx):
    call = plugin_call(cmd)
    if call is None or not call.words:
        return []
    sub = call.words[0]
    # A relative local source is read where the command runs; when that folder is uncertain, every candidate
    # must lead to the approved source.
    cwd = [c or ctx.cwd for c in cwds(cmd)]
    if sub == "install" and call.word(1):
        spec = call.word(1)
        name, _, market = spec.partition("@")
        sources = call.opts.get("--marketplace")
        if sources:
            # The marketplace at this source is added (if new) and the plugin comes from it.
            source = sources[-1]
            return _approved(ctx, "plugin", "%s from %s" % (name, source),
                             lambda entries: _plugin_from_source(entries, name, source, cwd))
        if not market:
            # Approvals are per marketplace, so a spec without one can't be matched to any approval.
            return [Hit("SKL02", "Installs the plugin %s without naming its marketplace. Approvals are per "
                                 "marketplace: vet it with %s <repo>, then install it as %s@<marketplace>."
                        % (name, _GATE, name))]
        return _approved(ctx, "plugin", spec, lambda entries: ledger.find_plugin_approval(entries, name, market or None))
    if sub == "enable":
        return _enable(ctx, call)
    if sub == "update":
        return [Hit("SKL02", "Updates the plugin %s, which brings in a new version the install gate has not vetted. "
                             "Run the update yourself from /plugin, then check it with /checkrein:status."
                    % (call.word(1) or "(name unclear)"))]
    if sub == "marketplace" and call.word(1) == "add":
        source = call.word(2)
        if not source:
            return [Hit("SKL02", "Adds a marketplace whose source checkrein can't read. Vet it first: %s <source>."
                        % _GATE)]
        return _approved(ctx, "marketplace", source, lambda entries: _marketplace_from_source(entries, source, cwd))
    if sub == "marketplace" and call.word(1) == "update":
        return [Hit("SKL02", "Updates marketplace %s from its source, which can bring in plugin versions the install "
                             "gate has not vetted. Run it yourself from /plugin, then check with /checkrein:status."
                    % (call.word(2) or "listings"))]
    return []


def _enable(ctx, call):
    """`claude plugin enable` turns a plugin on, like an enabledPlugins entry in settings, so the install ledger
    must have approved it. Turning checkrein itself back on passes."""
    spec = call.word(1)
    if "--help" in call.flags:
        return []
    if "--all" in call.flags or not spec:
        return [Hit("SKL02", "Turns on plugins checkrein can't name, which the install ledger may not have approved. "
                             "Turn them on yourself from /plugin.")]
    if own_checkrein(spec, ctx):
        return []
    name, _, market = spec.partition("@")
    return _approved(ctx, "enable", spec, lambda entries: ledger.find_plugin_approval(entries, name, market or None))


def _marketplace_from_source(entries, source, cwd_list):
    found = [ledger.find_marketplace_approval(entries, source, c) for c in cwd_list]
    if any(entry is None for _key, entry in found) or len(set(key for key, _entry in found)) != 1:
        return None, None
    return found[0]


def _plugin_from_source(entries, name, source, cwd_list):
    key, entry = _marketplace_from_source(entries, source, cwd_list)
    if entry is None:
        return None, None
    if entry.get("kind") == "plugin" and entry.get("name") == name:
        return key, entry
    if entry.get("kind") == "marketplace" and name in (entry.get("plugins") or []):
        return key, entry
    return None, None


def _approved(ctx, what, spec, finder):
    try:
        data = ledger.load(ctx.data_dir)
    except ledger.LedgerError as exc:
        return [Hit("SKL02", "%s Installs are refused until it is fixed (/checkrein:status doctor)." % exc,
                    level="deny")]
    entries = (data or {}).get("entries", {})
    _key, entry = finder(entries)
    if entry is not None:
        return []
    if what == "enable":
        msg = ("Turns on the plugin %s, which the install ledger has not approved. Vet it first: %s <repo>."
               % (spec, _GATE))
    elif what == "plugin":
        msg = "Installs the plugin %s, which the install ledger has not approved. Vet it first: %s <repo>." % (spec, _GATE)
    else:
        msg = "Adds the marketplace %s, which the install ledger has not approved. Vet it first: %s %s." % (spec, _GATE, spec)
    return [Hit("SKL02", msg)]


def _runners(cmd, ctx):
    installers = {i.lower() for i in ctx.eff.get("extra_installers") or []}
    run = runners.resolve(cmd)
    if run is None:
        args = list(cmd.args)
        if cmd.name in installers and args and args[0] in ("add", "install", "i", "get", "sync", "update"):
            return [_installer_hit(cmd.name)]
        return []
    if run.unreadable:
        return [Hit("SKL03", "Runs a package from %s, which checkrein can't name, so it can't tell whether it installs "
                             "skills or starts another agent. A person confirms this." % _clip(run.unreadable),
                    level="ask")]
    names = set(run.packages) | {p.rsplit("/", 1)[-1] for p in run.packages}
    if run.bin:
        names.add(run.bin)
    found = sorted(names & installers)
    return [_installer_hit(found[0])] if found else []


def _installer_hit(name):
    return Hit("SKL03", "Runs the skill installer %s, which writes skills without the install gate. Use %s "
                        "instead." % (name, _GATE))


def _clip(word, limit=80):
    return word if len(word) <= limit else word[:limit] + "..."


def is_own_tool(cmd, ctx):
    """True for python3 <plugin root>/scripts/skillgate.py|cfgtool.py ... written plainly.

    Interpreter options (-c, -m, -i, -W ...) and variables set before the command (PYTHONPATH, PYTHONSTARTUP,
    PATH) can run other code first or instead, so any of them makes it an ordinary command.
    """
    if not own_tool_shape(cmd, ctx):
        return False
    return not foreign_folders(cmd, ctx)


def own_tool_shape(cmd, ctx):
    argv = getattr(cmd, "argv", None) or [cmd.name] + list(cmd.args)
    if argv[0] not in ("python3", "python") or not cmd.args or cmd.env or ctx.plugin_root is None:
        return False
    script = cmd.args[0]
    if os.path.basename(script) not in OWN_TOOLS or not script.startswith(("/", "$")):
        return False
    path = ctx.path(script, cmd.cwd)
    if not os.path.isabs(path) or globs.has_magic(path):
        return False
    return same_path(os.path.dirname(os.path.normpath(path)), os.path.join(ctx.plugin_root, "scripts"))


# Per own tool: options before the subcommand that take a value, flags, and the known subcommands.
OWN_TOOLS = {
    "cfgtool.py": ({"--data", "--project-dir"}, {"-h", "--help"},
                   {"show", "explain", "set", "unset", "approve", "detect", "init", "doctor"}),
    "skillgate.py": ({"--data", "--project"}, {"-h", "--help"},
                     {"vet", "approve", "audit", "adopt", "list", "forget"}),
}


def foreign_folders(cmd, ctx):
    """--data, --project and --project-dir values that are not checkrein's own data folder and project: the tool
    would read a config (and run a scanner) the agent chose."""
    takes_value = OWN_TOOLS.get(os.path.basename(cmd.args[0]), (set(),))[0]
    rest = cmd.args[1:]
    out = []
    for i, a in enumerate(rest):
        opt, eq, value = a.partition("=")
        if opt not in takes_value:
            continue
        if not eq:
            value = rest[i + 1] if i + 1 < len(rest) else ""
        expected = ctx.data_dir if opt == "--data" else ctx.project_dir
        if not value or not expected or not same_path(ctx.path(value, cmd.cwd), expected):
            out.append(opt)
    return out


def own_tool_subcommand(cmd):
    """Return (script name, subcommand) for one of checkrein's own tools.

    The subcommand is None when it can't be read with certainty (an unknown or abbreviated option, an
    --opt=value form, an unknown word). Callers treat None as a changing command.
    """
    script = cmd.args[0] if cmd.args else ""
    name = os.path.basename(script)
    if name not in OWN_TOOLS:
        return name, None
    takes_value, flags, subs = OWN_TOOLS[name]
    rest = cmd.args[1:]
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in takes_value:
            i += 2
            continue
        if a in flags:
            return name, ""  # Help: prints and exits.
        if a.startswith("-"):
            return name, None
        return name, (a if a in subs else None)
    return name, ""


def _gate_decision(cmd, ctx):
    if own_tool_shape(cmd, ctx) and foreign_folders(cmd, ctx):
        script = os.path.basename(cmd.args[0])
        return [Hit("SKL04" if script == "skillgate.py" else "SLF01",
                    "Runs checkrein's %s with %s naming a folder other than its own, whose config can name any "
                    "scanner. A person confirms this." % (script, " and ".join(foreign_folders(cmd, ctx))),
                    level="ask")]
    if not is_own_tool(cmd, ctx):
        return []
    script, sub = own_tool_subcommand(cmd)
    if script == "skillgate.py" and (sub is None or sub in GATE_MUTATING):
        detail = " with --override" if "--override" in cmd.args else ""
        return [Hit("SKL04", "Install gate decision: skillgate %s%s. This changes what the gate trusts, so a "
                             "person confirms it." % (sub or "(subcommand unclear)", detail))]
    return []
