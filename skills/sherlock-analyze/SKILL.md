---
name: sherlock-analyze
description: Use when the user asks to analyze token spend, find wasteful workflows, compare agent sessions, or diagnose a cost spike across Claude Code / Codex / Cursor / Antigravity / Copilot logs. Runs `sherlock ingest` + `sherlock report` and interprets the output.
---

# Sherlock Analyze

You have access to the `sherlock` CLI — a token-usage forensic tool that ingests agent-CLI logs into a Dolt database and produces structured reports. Your job when this skill fires is to run Sherlock, then interpret its deterministic output with qualitative reasoning.

## Step 1 — pick the provider

Ask the user which agent CLI they want analyzed (or infer from context). Supported providers and default log paths:

| Provider id     | Default log location                                                    |
|-----------------|-------------------------------------------------------------------------|
| `claude-code`   | `~/.claude/projects/**/*.jsonl`                                         |
| `codex`         | `~/.codex/sessions/**/rollout-*.jsonl`                                  |
| `copilot-cli`   | `gh copilot` CLI event logs (path varies; ask if unsure)                |
| `copilot-vscode`| `~/.config/Code/User/globalStorage/github.copilot-chat/` (stub)         |
| `antigravity`   | Antigravity session dir (path TBD; ask the user)                        |
| `cursor`        | Cursor export JSON (experimental — prefer export over live DB scrape)   |

If the provider's adapter is marked experimental or stubbed, warn the user that totals may be zero or incomplete and offer to proceed anyway.

## Step 2 — ingest

```
sherlock --repo ~/.local/share/sherlock ingest --provider <id> --history <path>
```

Omit `--provider` to let Sherlock auto-detect from the path. The command prints a JSON summary containing the `session_id` you'll need next.

## Step 3 — pull the structured report

```
sherlock --repo ~/.local/share/sherlock report --session-id <id> --format json
```

For comparison requests, run this once per session id and collect all reports.

## Step 4 — analyze

Read the JSON. The important fields:
- `session_totals` — input/output/cache_read/cache_write tokens and percentages
- `top_sources` — tools and plugins ranked by estimated token spend
- `spikes` — turn-level token jumps with nearby tool/event context
- `findings` — deterministic rules that fired (cache-read-dominated, workflow-heavy-session, etc.)
- `recommendations` — deterministic 1:1 responses to findings
- `comparisons` — same-project session history

Your contribution is **qualitative**:
1. Identify the top 3 cost drivers by name — specific prompts, tools, plugins, workflow patterns.
2. Separate the deterministic `findings` (which Sherlock already produced) from your own synthesis.
3. Produce 2–5 concrete, actionable changes the user can make.
4. For multi-session comparisons, call out what changed, whether interventions worked, and which session was more efficient per prompt.
5. Be blunt about uncertainty — if token attribution is missing for half the sources, say so and suggest re-ingesting from richer logs.

Keep the analysis under 600 words. No preamble.

## Step 5 — offer follow-up

After the analysis, offer:
- Re-running against a second session id for before/after comparison (`sherlock analyze --session-id A --session-id B`).
- Opening the TUI (`sherlock tui --session-id <id>`) for interactive exploration.
- Re-ingesting with a different provider if the first attempt produced zero tokens.

## Shortcut — the built-in analyze subcommand

If the user just wants the LLM narrative directly without running Sherlock's output through you, point them at:

```
sherlock analyze --session-id <id> [--session-id <other>...] [--backend anthropic|openai|gemini|openai-compatible|prompt-only] [--model <id>]
```

The subcommand auto-detects which backend to use based on whichever `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY` is set. Use `--backend prompt-only` to print the assembled prompt without making an API call.
