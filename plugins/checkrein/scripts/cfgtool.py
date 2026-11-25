#!/usr/bin/env python3
"""checkrein settings.

  cfgtool.py show [--json]              Effective settings and where each came from.
  cfgtool.py explain <RULE|key>         What a rule or key does, its level and source.
  cfgtool.py set <key> <value> [--project] [--add|--remove]
                                        Change your config (or the project's with --project).
                                        Rules: set rules.GIT06 ask. Lists: --add / --remove one item.
  cfgtool.py unset <key> [--project]    Remove a key from a layer.
  cfgtool.py approve <key>              Approve the project config's value for a key that loosens
                                        or runs something (secret_ignore_paths, scanner).
  cfgtool.py detect [--json]            Look at this machine and project; suggest settings.
  cfgtool.py init [--preset P] [--yes]  Write a starting user config from detect's suggestions.
  cfgtool.py doctor                     Check the install, config, ledger and timing.

Common: --data DIR, --project-dir DIR.
set, unset, approve and init are confirmed by a person (rule SLF01 asks).
"""

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time

DOCS_URL = "https://github.com/kreativlogics/checkrein/blob/master"
HERE = os.path.dirname(os.path.abspath(__file__))
# Keep the installed plugin folder free of .pyc files, so it still hashes and scans as published.
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)

from checkrein import approve, cfg, context, ledger  # noqa: E402

PLUGIN_ROOT = os.path.dirname(HERE)


def _paths(args):
    home = os.path.expanduser("~")
    data = args.data or context.default_data_dir(home)
    project = args.project_dir or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    return home, data, project


def _resolve(data, project):
    try:
        return cfg.resolve(data, project)
    except cfg.ConfigError as exc:
        sys.exit("Config error: %s" % exc)


def cmd_show(args):
    _home, data, project = _paths(args)
    eff = _resolve(data, project)
    registry = cfg.load_registry()
    if args.json:
        print(json.dumps({"values": eff.values, "sources": eff.sources, "notes": eff.notes,
                          "pending_approval": eff.pending_approval}, indent=2, sort_keys=True))
        return
    print("Files: user %s | project %s" % (cfg.user_config_path(data), cfg.project_config_path(project)))
    print("Preset: %s (%s)   fail_mode: %s (%s)" % (eff.get("preset"), eff.sources["preset"],
                                                    eff.get("fail_mode"), eff.sources["fail_mode"]))
    print("Rules:")
    for rid, spec in registry["rules"].items():
        print("  %-6s %-6s %-28s %s" % (rid, eff.level(rid), eff.sources["rules"][rid], spec["title"]))
    for key in ("protected_branches", "extra_skill_roots", "extra_installers", "mcp_write_tools",
                "secret_ignore_paths", "mcp_routine"):
        print("%s: %s (%s)" % (key, ", ".join(eff.get(key) or []) or "-", eff.sources[key]))
    scanner = eff.get("scanner")
    print("scanner: %s (%s)" % (" ".join(scanner["command"]) if scanner else "-", eff.sources["scanner"]))
    print("secret_scanner: %s (%s)" % (eff.get("secret_scanner"), eff.sources["secret_scanner"]))
    for note in eff.notes:
        print("Note: %s" % note)


def cmd_explain(args):
    _home, data, project = _paths(args)
    eff = _resolve(data, project)
    registry = cfg.load_registry()
    what = args.name
    rules = registry["rules"]
    if what.upper() in rules:
        rid = what.upper()
        spec = rules[rid]
        print("%s: %s" % (rid, spec["title"]))
        print("Group: %s" % spec["group"])
        print("Level now: %s (from %s)" % (eff.level(rid), eff.sources["rules"][rid]))
        print("Presets: " + ", ".join("%s=%s" % kv for kv in spec["presets"].items()))
        if spec.get("notes"):
            print("Notes: %s" % spec["notes"])
        print("Change it: /checkrein:config set rules.%s <%s>" % (rid, "|".join(spec["levels"])))
        print("Details: %s/docs/rules.md#%s" % (DOCS_URL, rid.lower()))
        return
    if what in cfg.SCHEMA:
        print("%s: %s" % (what, cfg.DESCRIPTIONS[what]))
        print("Now: %s (from %s)" % (json.dumps(eff.get(what)), eff.sources.get(what)))
        return
    sys.exit("Unknown rule or key %r.%s" % (what, cfg._hint(what, list(rules) + list(cfg.SCHEMA))))


def _parse_value(text):
    try:
        return json.loads(text)
    except ValueError:
        return text


def _layer_path(args, data, project):
    return cfg.project_config_path(project) if args.project else cfg.user_config_path(data)


def cmd_set(args):
    _home, data, project = _paths(args)
    path = _layer_path(args, data, project)
    layer = cfg.read_json(path) or {}
    key = args.key
    value = _parse_value(args.value)
    if key.startswith("rules."):
        layer.setdefault("rules", {})[key.split(".", 1)[1].upper()] = value
    elif key == "scanner" and isinstance(value, str):
        layer["scanner"] = {"command": shlex.split(value)}
    elif key in cfg.SCHEMA and cfg.SCHEMA[key][0] == "list" and (args.add or args.remove):
        items = list(layer.get(key) or [])
        if args.add and value not in items:
            items.append(value)
        if args.remove and value in items:
            items.remove(value)
        layer[key] = items
    else:
        layer[key] = value
    try:
        cfg.write_layer(path, layer)
    except cfg.ConfigError as exc:
        sys.exit("Not saved: %s" % exc)
    print("Saved %s in %s." % (key, path))
    eff = _resolve(data, project)
    for note in eff.notes:
        print("Note: %s" % note)


def cmd_unset(args):
    _home, data, project = _paths(args)
    path = _layer_path(args, data, project)
    layer = cfg.read_json(path) or {}
    if args.key.startswith("rules."):
        (layer.get("rules") or {}).pop(args.key.split(".", 1)[1].upper(), None)
    else:
        layer.pop(args.key, None)
    cfg.write_layer(path, layer)
    print("Removed %s from %s." % (args.key, path))


def cmd_approve(args):
    _home, data, project = _paths(args)
    path = cfg.project_config_path(project)
    layer = cfg.read_json(path)
    if not layer or args.key not in layer:
        sys.exit("The project config (%s) does not set %s." % (path, args.key))
    if cfg.SCHEMA.get(args.key, ("", ""))[1] not in ("loosen-approved", "exec"):
        sys.exit("%s does not need approval." % args.key)
    value = layer[args.key]
    approve.grant(data, project, args.key, value)
    print("Approved %s = %s for %s. A changed value needs a new approval."
          % (args.key, json.dumps(value), os.path.realpath(project)))


def _run(cmd, cwd=None):
    try:
        res = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
                             universal_newlines=True)
        return res.stdout.strip() if res.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def detect(home, data, project):
    """Facts about this machine and project, and suggested settings."""
    facts = {"python": sys.version.split()[0], "git": bool(shutil.which("git")),
             "gitleaks": bool(shutil.which("gitleaks")), "skillspector": bool(shutil.which("skillspector"))}
    default_branch = _run(["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"], cwd=project)
    facts["default_branch"] = default_branch.split("/", 1)[1] if "/" in default_branch else None
    facts["hook_managers"] = [name for name, marker in (("husky", ".husky"), ("pre-commit", ".pre-commit-config.yaml"),
                                                        ("lefthook", "lefthook.yml"))
                              if os.path.exists(os.path.join(project, marker))]
    items = ledger.inventory(home, project)
    facts["installed_skills"] = len([k for k in items if k.startswith("skill:")])
    facts["installed_plugins"] = len([k for k in items if k.startswith("plugin:")])
    try:
        facts["ledger"] = "present" if ledger.load(data) is not None else "missing"
    except ledger.LedgerError:
        facts["ledger"] = "unreadable"
    facts["mcp_servers"] = sorted(_mcp_servers(home, project))
    suggestions = []
    registry = cfg.load_registry()
    if facts["default_branch"] and facts["default_branch"] not in registry["defaults"]["protected_branches"]:
        suggestions.append({"key": "protected_branches", "add": facts["default_branch"],
                            "why": "the repository's default branch is %s" % facts["default_branch"]})
    if facts["skillspector"]:
        command = ["skillspector", "scan", "{path}", "--no-llm", "--format", "json", "--output", "{report}"]
        suggestions.append({"key": "scanner", "value": {"command": command},
                            "why": "SkillSpector is installed; vet verdicts can reach PASS"})
    else:
        suggestions.append({"key": "scanner", "value": None,
                            "why": "no scanner found; vet verdicts stop at REVIEW. A scanner such as SkillSpector "
                                   "can be added later"})
    if facts["gitleaks"]:
        suggestions.append({"key": "rules.SEC03", "value": "deny",
                            "why": "gitleaks is installed, so the staged-commit scan is fast and thorough"})
    if facts["mcp_servers"]:
        suggestions.append({"key": "rules.MCP01", "value": "ask",
                            "why": "MCP servers are configured (%s); ask before tools that write to them"
                                   % ", ".join(facts["mcp_servers"][:5])})
    if facts["ledger"] == "missing" and (facts["installed_skills"] or facts["installed_plugins"]):
        suggestions.append({"key": "ledger", "value": "adopt",
                            "why": "%d skill(s) and %d plugin(s) are installed but not recorded; review and "
                                   "adopt them" % (facts["installed_skills"], facts["installed_plugins"])})
    return {"facts": facts, "suggestions": suggestions}


def _mcp_servers(home, project):
    names = set()
    for path in (context.claude_json(home), os.path.join(project, ".mcp.json")):
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        servers = data.get("mcpServers") if isinstance(data, dict) else None
        if isinstance(servers, dict):
            names.update(servers)
        projects = data.get("projects") if isinstance(data, dict) else None
        if isinstance(projects, dict):
            entry = projects.get(project) or projects.get(os.path.realpath(project)) or {}
            if isinstance(entry.get("mcpServers"), dict):
                names.update(entry["mcpServers"])
    return names


def cmd_detect(args):
    home, data, project = _paths(args)
    result = detect(home, data, project)
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print("Found:")
    for k, v in result["facts"].items():
        print("  %s: %s" % (k, v if not isinstance(v, list) else (", ".join(v) or "-")))
    print("Suggestions:")
    for s in result["suggestions"]:
        print("  %s: %s" % (s["key"], s["why"]))


def cmd_init(args):
    home, data, project = _paths(args)
    path = cfg.user_config_path(data)
    if os.path.exists(path) and not args.force:
        sys.exit("%s already exists. Use set to change it, or --force to start over." % path)
    result = detect(home, data, project)
    layer = {"version": cfg.SUPPORTED_VERSION, "preset": args.preset}
    for s in result["suggestions"]:
        if s["key"] == "protected_branches":
            layer.setdefault("protected_branches", []).append(s["add"])
        elif s["key"] == "scanner" and s["value"]:
            layer["scanner"] = s["value"]
        elif s["key"].startswith("rules.") and args.preset != "relaxed":
            layer.setdefault("rules", {})[s["key"].split(".", 1)[1]] = s["value"]
    if not args.yes:
        print(json.dumps(layer, indent=2))
        print("This is what init would write to %s. Run again with --yes to save it." % path)
        return
    cfg.write_layer(path, layer)
    print("Saved %s." % path)
    if any(s["key"] == "ledger" for s in result["suggestions"]):
        print("Next: /checkrein:status to review installed skills and plugins.")


def cmd_doctor(args):
    home, data, project = _paths(args)
    problems = 0

    def line(ok, text):
        nonlocal problems
        if not ok:
            problems += 1
        print("%s %s" % ("ok  " if ok else "FAIL", text))

    line(sys.version_info >= (3, 9), "Python %s (3.9 or newer needed)" % sys.version.split()[0])
    line(os.path.exists(os.path.join(PLUGIN_ROOT, "hooks", "hooks.json")), "hooks/hooks.json present")
    try:
        os.makedirs(data, exist_ok=True)
        probe = os.path.join(data, ".probe")
        with open(probe, "w") as fh:
            fh.write("x")
        os.unlink(probe)
        line(True, "data folder writable: %s" % data)
    except OSError as exc:
        line(False, "data folder not writable: %s (%s)" % (data, exc))
    try:
        eff = cfg.resolve(data, project)
        line(True, "config valid (preset %s, fail_mode %s)" % (eff.get("preset"), eff.get("fail_mode")))
        for note in eff.notes:
            print("     note: %s" % note)
        if eff.project_error:
            line(False, "project config skipped, fix it so its rules apply: %s" % eff.project_error)
    except cfg.ConfigError as exc:
        eff = None
        line(False, "config: %s" % exc)
    try:
        led = ledger.load(data)
        line(True, "ledger %s" % ("readable, %d entries" % len(led["entries"]) if led else "not created yet"))
    except ledger.LedgerError as exc:
        line(False, "ledger: %s Move it aside and run skillgate adopt --all." % exc)
    if eff and eff.level("SEC03") != "off":
        choice = eff.get("secret_scanner")
        line(choice != "gitleaks" or bool(shutil.which("gitleaks")), "staged-commit scanner: %s%s" % (
            choice, " (gitleaks found)" if shutil.which("gitleaks") else ""))
    if eff and eff.get("scanner"):
        tool = eff.get("scanner")["command"][0]
        line(bool(shutil.which(tool)), "install-gate scanner %s on PATH" % tool)
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}, "cwd": project,
                          "permission_mode": "default"})
    start = time.time()
    res = subprocess.run([sys.executable, os.path.join(HERE, "guard.py"), "pre"], input=payload,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=20)
    ms = (time.time() - start) * 1000
    line(res.returncode == 0 and not res.stderr, "hook runs (%.0f ms for a sample call)" % ms)
    print("%d problem(s)." % problems)
    return 1 if problems else 0


def build_parser():
    # No abbreviations: the hook reads these options exactly (SLF01), so --proj must not mean --project-dir.
    p = argparse.ArgumentParser(prog="cfgtool", description="checkrein settings", allow_abbrev=False)
    p.add_argument("--data")
    p.add_argument("--project-dir")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("show", allow_abbrev=False)
    s.add_argument("--json", action="store_true")
    e = sub.add_parser("explain", allow_abbrev=False)
    e.add_argument("name")
    st = sub.add_parser("set", allow_abbrev=False)
    st.add_argument("key")
    st.add_argument("value")
    st.add_argument("--project", action="store_true")
    st.add_argument("--add", action="store_true")
    st.add_argument("--remove", action="store_true")
    un = sub.add_parser("unset", allow_abbrev=False)
    un.add_argument("key")
    un.add_argument("--project", action="store_true")
    ap = sub.add_parser("approve", allow_abbrev=False)
    ap.add_argument("key")
    d = sub.add_parser("detect", allow_abbrev=False)
    d.add_argument("--json", action="store_true")
    i = sub.add_parser("init", allow_abbrev=False)
    i.add_argument("--preset", choices=cfg.PRESETS, default="standard")
    i.add_argument("--yes", action="store_true")
    i.add_argument("--force", action="store_true")
    doc = sub.add_parser("doctor", allow_abbrev=False)
    for sp in (s, e, st, un, ap, d, i, doc):
        sp.add_argument("--data", default=argparse.SUPPRESS)
        sp.add_argument("--project-dir", default=argparse.SUPPRESS)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {"show": cmd_show, "explain": cmd_explain, "set": cmd_set, "unset": cmd_unset,
                "approve": cmd_approve, "detect": cmd_detect, "init": cmd_init, "doctor": cmd_doctor}
    if args.cmd not in handlers:
        parser.print_help()
        return 2
    return handlers[args.cmd](args) or 0


if __name__ == "__main__":
    sys.exit(main())
