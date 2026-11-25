---
name: config
description: Set up or change checkrein - detect the tools and repo, suggest a preset, show or explain rules, and change levels or lists in the user's or the project's config. Use when the user asks to configure, tune, loosen or tighten checkrein, explain a rule (GIT01, SEC01...), or after checkrein blocked something the user wants allowed.
argument-hint: "[show | explain <RULE|key> | set <key> <value> | init | detect]"
allowed-tools: Bash(python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cfgtool.py" --data "${CLAUDE_PLUGIN_DATA}" show*), Bash(python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cfgtool.py" --data "${CLAUDE_PLUGIN_DATA}" explain *), Bash(python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cfgtool.py" --data "${CLAUDE_PLUGIN_DATA}" detect*)
---

# checkrein config

`CFG` means `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/cfgtool.py" --data "${CLAUDE_PLUGIN_DATA}"`. For what a rule or key does, run
`CFG explain <RULE or key>`; the full reference is https://github.com/kreativlogics/checkrein/blob/master/docs/rules.md.

Request: $ARGUMENTS

**First setup** (no user config yet, or the user says "set up"):
1. Run `CFG detect` and `CFG show`. Tell the user what was found (gitleaks, a skill scanner, hook managers, the
   default branch, MCP servers) and what each suggestion would change.
2. Recommend a preset: `standard` for most people; `strict` for shared checkouts, unattended runs or teams;
   `relaxed` for solo experiments. Ask the user to pick.
3. Run `CFG init --preset <choice>` to preview, then `CFG init --preset <choice> --yes`. Apply the suggestions the user
   accepted with `CFG set`.

**Explain:** `CFG explain <RULE|key>`, then the matching section of the rule reference in plain words.

**Change a setting:** `CFG set <key> <value>`; lists take `--add` / `--remove`; `--project` writes the project's
`.checkrein/config.json` (shared with the team, and it can only tighten). Examples:
- `CFG set rules.GIT06 ask`
- `CFG set protected_branches --add staging`
- `CFG set secret_ignore_paths --add "tests/fixtures/*"`
- `CFG set scanner "skillspector scan {path} --no-llm --format json --output {report}"`
- `CFG unset rules.GIT06`

checkrein asks the user to confirm every `set`, `unset`, `approve` and `init` (SLF01). Never edit the config files
directly; that is denied.

**After a block the user disagrees with:** explain the rule, then offer the narrowest change: a single rule's level, a
path in `secret_ignore_paths`, or a tool pattern in `mcp_routine` (your own config only). Say what the change would
let through. Do not suggest `off` for a whole group when one rule will do.

**Project settings that loosen** (`secret_ignore_paths`, `scanner` in `.checkrein/config.json`) apply only after the user
runs `CFG approve <key>`; show them what they are approving first.
