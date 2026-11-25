# Threat model

## What checkrein protects

- **Your machine and accounts** from a skill or plugin that reads credentials, sets up persistence or runs remote
  code, by making new ones pass through quarantine and a verdict before they land.
- **Secrets** from being written into files, typed into commands, committed, or sent to MCP tools by the agent.
- **Work in git** from force pushes, remote deletes, hard resets and skipped hooks.
- **checkrein itself** from being turned off or reconfigured by the agent.

## Who it defends against

| Actor | Can | checkrein's answer |
|---|---|---|
| The agent, steered by untrusted content (a web page, an issue, a README, a skill's text) | Make any tool call the session allows | Every Bash, Write, Edit and MCP call passes the PreToolUse hook first; rules deny or ask |
| A malicious or careless skill or plugin author | Ship code, hooks and instructions | Quarantine, static checks, optional scanner, a person approves; drift is reported at session start |
| A repository you open | Commit a `.checkrein/config.json`, or a `.claude/settings.json` that disables checkrein or all hooks | A `.checkrein/config.json` can only tighten; entries that run a program or skip secret checks wait for your approval. A committed `.claude/settings.json` can switch checkrein off, because project settings take precedence, and one brought in mid-session by a checkout, pull or merge is not checked. Look at `.claude/settings*.json` in repositories you don't trust before opening them |
| The agent trying to loosen the guard | Edit config, ledger, settings, disable the plugin, approve its own install | SLF01 and SKL04; config changes go through `cfgtool`, which asks you |

## Trust boundaries

- **Trusted:** you, your own config file, the plugin folder as installed, Python's standard library.
- **Untrusted:** everything inside quarantine, project config files until approved, tool inputs, MCP payloads,
  third-party scanner output (it is read as JSON and masked before it is logged).
- **Child processes** (the `git clone` of a source, a third-party scanner) get a minimal environment: PATH, HOME,
  locale, temp and proxy settings, plus any variable you name in `scanner.env`. Tokens in your shell do not reach them.

## Out of scope

- A person who edits checkrein's files or disables the plugin themselves.
- Code that runs outside the agent's tool calls: build tools, package scripts, MCP servers' own actions, your own
  terminal.
- Hiding the real action from a pattern reader (aliases, encoded or generated commands, scripts written then run).
  These are listed in [docs/limits.md](docs/limits.md) and tested as expected failures.
- A model set on getting around the guard. checkrein stops the common routes; others (tools outside its lists that
  write into a skill folder, hard links, git config includes, git folders in non-standard places) are listed in
  [docs/limits.md](docs/limits.md).
- A compromised Python interpreter or operating system.

## Failure behaviour

If checkrein crashes or its config is unreadable, `fail_mode` decides (`ask` by default). In `dontAsk` and
`bypassPermissions` modes every `ask` becomes `deny`.
