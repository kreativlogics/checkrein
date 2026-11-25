#!/usr/bin/env python3
"""checkrein install gate.

  skillgate.py vet <source> [--name SKILL] [--no-scanner] [--json]
  skillgate.py approve <quarantine-id> [--scope user|project] [--replace] [--override]
                      [--marketplace NAME]
  skillgate.py audit [--json]
  skillgate.py adopt (<key> ... | --all) [--override]
  skillgate.py list [--json]
  skillgate.py forget <key>

Common: --data DIR (default $CLAUDE_PLUGIN_DATA), --project DIR (default
$CLAUDE_PROJECT_DIR or the current folder).

approve, adopt and forget change what the gate trusts. The PreToolUse hook
asks a person before they run (rule SKL04).
"""

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
# Keep the installed plugin folder free of .pyc files, so it still hashes and scans as published.
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)

from checkrein import cfg, context, gate, ledger  # noqa: E402

QUARANTINE_DAYS = 7
# A marketplace name as it appears in "plugin@marketplace" and as a plugin cache folder name.
_MARKET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _paths(args):
    home = os.path.expanduser("~")
    data = args.data or context.default_data_dir(home)
    project = args.project or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    return home, data, project


def _ledger(data):
    try:
        led = ledger.load(data)
    except ledger.LedgerError as exc:
        sys.exit("Error: %s Move the file aside and run 'adopt --all' to rebuild it." % exc)
    return led or ledger.empty()


def _clean_quarantine(data):
    qdir = gate.quarantine_dir(data)
    if not os.path.isdir(qdir):
        return
    cutoff = time.time() - QUARANTINE_DAYS * 86400
    for name in os.listdir(qdir):
        path = os.path.join(qdir, name)
        try:
            if os.path.getmtime(path) < cutoff:
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.unlink(path)
        except OSError:
            continue


def cmd_vet(args):
    home, data, project = _paths(args)
    os.makedirs(gate.quarantine_dir(data), exist_ok=True)
    _clean_quarantine(data)
    eff = cfg.resolve(data, project)
    scanner = None if args.no_scanner else (eff.get("scanner") or {})
    try:
        report = gate.vet(args.source, data, scanner_command=scanner.get("command") if scanner else None,
                          name=args.name, scanner_env=(scanner or {}).get("env") or ())
    except (ValueError, RuntimeError, OSError) as exc:
        sys.exit("Error: %s" % exc)
    if args.json:
        print(json.dumps(report, indent=2))
        return
    if report.get("choices"):
        print(report["message"])
        print("Skills: " + ", ".join(report["choices"]))
        return
    _print_report(report, eff)


def _print_report(r, eff):
    print("Verdict: %s" % r["verdict"])
    print("Name: %s (%s), %d files" % (r["name"], r["kind"], r["files"]))
    origin = r["origin"]
    print("Source: %s%s" % (origin["source"], " @ %s" % origin["commit"][:12] if origin.get("commit") else ""))
    if r.get("scanned") and r["scanned"] != ["."]:
        print("Scanned: %s (what Claude Code installs; other files in the repository are not vetted)"
              % ", ".join(r["scanned"]))
    sc = r["scanner"]
    labels = {"none": "no scanner configured (verdict can be at best REVIEW)",
              "unavailable": "configured scanner not found: %s" % sc.get("detail"),
              "error": "scanner failed: %s" % sc.get("detail"),
              "clean": "scanner reported nothing",
              "findings": "scanner reported findings (%s); see %s" % (
                  sc.get("findings") or "count unknown", sc.get("report") or sc.get("log"))}
    print("Scanner: %s" % labels.get(sc.get("status"), sc.get("status")))
    findings = r["findings"]
    if findings:
        print("Static findings:")
        for f in findings[:40]:
            loc = "%s:%d" % (f["path"], f["line"]) if f["line"] else f["path"]
            print("  [%s] %s %s: %s" % (f["severity"], f["rule"], loc, f["message"]))
        if len(findings) > 40:
            print("  ... and %d more (use --json)" % (len(findings) - 40))
    else:
        print("Static findings: none")
    if r["kind"] in ("plugin", "marketplace"):
        print("Plugins covered: %s" % (", ".join(p for p in r.get("marketplace_plugins") or [] if p) or r["name"]))
        if r.get("external_plugins"):
            print("Not covered (their code lives elsewhere): %s" % ", ".join(r["external_plugins"]))
    print("Quarantine id: %s" % r["id"])
    if r["verdict"] == "PASS":
        print("Next: skillgate approve %s" % r["id"])
    elif r["kind"] != "unknown":
        print("Next: read the findings. To install anyway: skillgate approve %s --override" % r["id"])
    else:
        print("This is not a skill, plugin or marketplace; nothing to install.")


def _entry_from_report(r, approved_override):
    return {
        "name": r["name"],
        "kind": r["kind"],
        "origin": r["origin"],
        "tree_hash": r["tree_hash"],
        "verdict": r["verdict"],
        "override": approved_override,
        "findings": len(r["findings"]),
        "scanner": r["scanner"].get("status"),
        "vetted_at": r["vetted_at"],
        "approved_at": ledger.now(),
    }


def _recorded_source(origin):
    """The source as the ledger keeps it. A local folder is kept as its real absolute path (taken when it was
    vetted), so adding the marketplace matches it from any folder; other sources are kept as typed, and
    ledger.normalize_source compares their spellings."""
    if origin.get("kind") == "local" and origin.get("location"):
        return os.path.realpath(origin["location"])
    return origin["source"]


def cmd_approve(args):
    home, data, project = _paths(args)
    try:
        r = gate.load_report(data, args.id)
    except (ValueError, OSError) as exc:
        sys.exit("Error: no vet report for %r (%s)." % (args.id, exc))
    if r.get("verdict") is None or r.get("kind") in (None, "unknown"):
        sys.exit("Error: nothing to approve in %s." % args.id)
    if r["verdict"] != "PASS" and not args.override:
        sys.exit("Error: verdict is %s. Read the findings; approve with --override to accept them." % r["verdict"])
    qroot = os.path.join(gate.quarantine_dir(data), args.id)
    subject = os.path.join(qroot, r["subject"])
    if not os.path.isdir(subject):
        sys.exit("Error: the quarantined copy is gone; vet it again.")
    if ledger.tree_hash(subject) != r["tree_hash"]:
        sys.exit("Error: the quarantined copy changed after vetting; vet it again.")
    led = _ledger(data)
    entry = _entry_from_report(r, bool(args.override and r["verdict"] != "PASS"))
    if r["kind"] == "skill":
        return _install_skill(args, home, data, project, r, subject, led, entry)
    entry["kind"] = "marketplace" if r.get("marketplace") else "plugin"
    entry["sources"] = [_recorded_source(r["origin"])]
    if entry["kind"] == "marketplace":
        entry["name"] = r["marketplace"]
        entry["plugins"] = [p for p in r.get("marketplace_plugins") or [] if p]
        entry["plugin_hashes"] = r.get("plugin_hashes") or {}
        key = "marketplace:%s" % r["marketplace"]
    else:
        # A plugin approval covers installs from one named marketplace only, so the same name offered by another
        # marketplace is not trusted by accident.
        market = args.marketplace
        if not market:
            sys.exit("Error: name the marketplace you will install %s from: approve %s --marketplace <name> "
                     "(the part after @ in %s@<name>)." % (r["name"], args.id, r["name"]))
        if not _MARKET_NAME.match(market):
            sys.exit("Error: %r is not a marketplace name." % market)
        entry["marketplace"] = market
        key = "plugin:%s@%s" % (r["name"], market)
    entry["caches"] = (led["entries"].get(key) or {}).get("caches", {})
    led["entries"][key] = entry
    ledger.save(data, led)
    print("Approved %s." % key)
    if entry["kind"] == "marketplace":
        print("Now run:\n  claude plugin marketplace add %s" % entry["sources"][0])
        for p in entry["plugins"]:
            print("  claude plugin install %s@%s" % (p, entry["name"]))
    else:
        print("Now run:\n  claude plugin install %s@%s" % (r["name"], entry["marketplace"]))
    print("Claude Code downloads the plugin again when installing. The next session start compares that copy "
          "with what was vetted and reports a difference.")


def _install_skill(args, home, data, project, r, subject, led, entry):
    name = r["name"]
    if not name or "/" in name or name.startswith("."):
        sys.exit("Error: unusable skill name %r." % name)
    base = os.path.join(context.claude_dir(home), "skills") if args.scope == "user" else \
        os.path.join(project, ".claude", "skills")
    dest = os.path.join(base, name)
    if os.path.exists(dest) and not args.replace:
        sys.exit("Error: %s already exists. Use --replace to swap it (the old copy goes to the data folder's "
                 "trash)." % dest)
    os.makedirs(base, exist_ok=True)
    # Copy and check beside the destination first, so a copy that does not match never lands in the skill folder.
    stage = tempfile.mkdtemp(prefix=".%s.checkrein-" % name, dir=base)
    try:
        staged = os.path.join(stage, name)
        shutil.copytree(subject, staged, symlinks=True)
        if ledger.tree_hash(staged) != r["tree_hash"]:
            sys.exit("Error: the copy does not match the vetted copy; nothing was installed. Vet it again.")
        if os.path.exists(dest):
            trash = os.path.join(data, "trash", "%s-%s" % (name, time.strftime("%Y%m%d-%H%M%S")))
            os.makedirs(os.path.dirname(trash), exist_ok=True)
            shutil.move(dest, trash)
            print("Old copy moved to %s" % trash)
        os.replace(staged, dest)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    key = "skill:%s:%s" % (args.scope, name)
    entry.update({"kind": "skill", "scope": args.scope, "path": dest,
                  "tree_hash": ledger.tree_hash(dest), "fingerprint": ledger.fingerprint(dest)})
    if entry["tree_hash"] != r["tree_hash"]:
        shutil.rmtree(dest, ignore_errors=True)
        sys.exit("Error: the installed copy does not match the vetted copy; it was removed. Vet it again.")
    led["entries"][key] = entry
    ledger.save(data, led)
    print("Installed %s to %s and recorded it as %s." % (name, dest, key))


def cmd_audit(args):
    home, data, project = _paths(args)
    eff = cfg.resolve(data, project)
    try:
        report = ledger.drift(data, home, project, eff.get("extra_skill_roots") or [])
    except ledger.LedgerError as exc:
        sys.exit("Error: %s" % exc)
    if report is None:
        items = ledger.inventory(home, project, eff.get("extra_skill_roots") or [])
        report = {"ledger": False, "unvetted": sorted(items), "changed": [], "missing": [], "bound": [], "ok": 0}
    else:
        report["ledger"] = True
    if args.json:
        print(json.dumps(report, indent=2))
        return
    if not report["ledger"]:
        print("No ledger yet.")
    for label, key in (("Changed since approval", "changed"), ("Never vetted", "unvetted"),
                       ("Newly installed plugin code (first look)", "bound"),
                       ("Approved but not installed", "missing")):
        if report[key]:
            print("%s:" % label)
            for item in report[key]:
                print("  %s" % item)
    print("Unchanged: %d" % report["ok"])
    if report["changed"] or report["unvetted"]:
        print("Review an item: skillgate vet <its folder>. Record it as trusted: skillgate adopt <key>.")


def cmd_adopt(args):
    home, data, project = _paths(args)
    eff = cfg.resolve(data, project)
    items = ledger.inventory(home, project, eff.get("extra_skill_roots") or [])
    led = _ledger(data)
    if args.all:
        keys = sorted(items)
    else:
        keys = args.keys
    if not keys:
        sys.exit("Error: name keys to adopt (see 'audit') or pass --all.")
    blocked = []
    for key in keys:
        path = items.get(key)
        if path is None:
            print("Skip %s: not installed." % key)
            continue
        findings = gate.static_scan(path)
        verdict = gate.verdict(findings, {"status": "none"})
        high = [f for f in findings if f.severity == "high"]
        if verdict == "BLOCK" and not args.override:
            blocked.append(key)
            print("Not adopted %s: %d high finding(s):" % (key, len(high)))
            for f in high[:10]:
                print("  %s %s:%d %s" % (f.rule, f.path, f.line, f.message))
            continue
        th = ledger.tree_hash(path)
        entry = {"name": os.path.basename(path), "path": path, "tree_hash": th, "fingerprint": ledger.fingerprint(path),
                 "verdict": verdict, "override": verdict == "BLOCK", "findings": len(findings),
                 "origin": {"source": "adopted", "kind": "local", "location": path},
                 "approved_at": ledger.now(), "adopted": True}
        if key.startswith("plugin:"):
            name, _, rest = key[len("plugin:"):].partition("@")
            market = rest.split("#", 1)[0]
            ekey = "plugin:%s@%s" % (name, market)
            existing = led["entries"].get(ekey) or {}
            entry.update({"kind": "plugin", "name": name, "marketplace": market, "sources": existing.get("sources", []),
                          "caches": existing.get("caches", {})})
            entry["caches"][key] = {"tree_hash": th, "fingerprint": entry["fingerprint"], "first_seen": ledger.now(),
                                    "matches_vetted": True}
            led["entries"][ekey] = entry
        else:
            entry["kind"] = "skill"
            led["entries"][key] = entry
        print("Adopted %s (%s, %d finding(s))." % (key, verdict, len(findings)))
    ledger.save(data, led)
    if blocked:
        print("Use --override to adopt the blocked items anyway.")


def cmd_list(args):
    _home, data, _project = _paths(args)
    led = _ledger(data)
    if args.json:
        print(json.dumps(led, indent=2))
        return
    if not led["entries"]:
        print("The ledger is empty.")
    for key, e in sorted(led["entries"].items()):
        extra = " override" if e.get("override") else ""
        print("%s  %s%s  %s" % (key, e.get("verdict"), extra, e.get("approved_at")))


def cmd_forget(args):
    _home, data, _project = _paths(args)
    led = _ledger(data)
    if args.key not in led["entries"]:
        sys.exit("Error: %r is not in the ledger." % args.key)
    del led["entries"][args.key]
    ledger.save(data, led)
    print("Forgot %s. Files on disk are unchanged." % args.key)


def build_parser():
    # allow_abbrev=False everywhere: an abbreviated option (--proj) would read differently here than in the hook's
    # parsing of this command line.
    p = argparse.ArgumentParser(prog="skillgate", description="checkrein install gate", allow_abbrev=False)
    p.add_argument("--data")
    p.add_argument("--project")
    sub = p.add_subparsers(dest="cmd")
    v = sub.add_parser("vet", allow_abbrev=False)
    v.add_argument("source")
    v.add_argument("--name")
    v.add_argument("--no-scanner", action="store_true")
    v.add_argument("--json", action="store_true")
    a = sub.add_parser("approve", allow_abbrev=False)
    a.add_argument("id")
    a.add_argument("--scope", choices=("user", "project"), default="user")
    a.add_argument("--replace", action="store_true")
    a.add_argument("--override", action="store_true")
    a.add_argument("--marketplace")
    au = sub.add_parser("audit", allow_abbrev=False)
    au.add_argument("--json", action="store_true")
    ad = sub.add_parser("adopt", allow_abbrev=False)
    ad.add_argument("keys", nargs="*")
    ad.add_argument("--all", action="store_true")
    ad.add_argument("--override", action="store_true")
    li = sub.add_parser("list", allow_abbrev=False)
    li.add_argument("--json", action="store_true")
    f = sub.add_parser("forget", allow_abbrev=False)
    f.add_argument("key")
    for sp in (v, a, au, ad, li, f):
        sp.add_argument("--data", default=argparse.SUPPRESS)
        sp.add_argument("--project", default=argparse.SUPPRESS)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {"vet": cmd_vet, "approve": cmd_approve, "audit": cmd_audit, "adopt": cmd_adopt,
                "list": cmd_list, "forget": cmd_forget}
    if args.cmd not in handlers:
        parser.print_help()
        return 2
    if args.cmd in ("approve", "adopt", "forget"):
        # These load, change and save the ledger: one at a time, also against a session start's drift check.
        with ledger.locked(_paths(args)[1]):
            handlers[args.cmd](args)
    else:
        handlers[args.cmd](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
