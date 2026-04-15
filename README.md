# Sherlock

**Agent-CLI token-usage forensics for understanding what's driving your spend.**

Have you ever asked Claude Code to "write a plan for this" and watched your usage melt down?  
That happened to me one too many times, so I built Sherlock to investigate what was really driving token spikes (spoiler: agents).

Use Sherlock to analyze your token usage across Claude Code, Codex, Copilot, Antigravity, and Cursor — see which prompts are actually effective, and spot plugins or workflows that burn money without adding value.

## Supported providers

| Provider id       | Default log location                                                 | Notes |
|-------------------|----------------------------------------------------------------------|-------|
| `claude-code`     | `~/.claude/projects/**/*.jsonl`                                      | First-class |
| `codex`           | `~/.codex/sessions/**/rollout-*.jsonl`                               | First-class |
| `copilot-cli`     | `gh copilot` CLI event logs                                          | Tier 1 |
| `copilot-vscode`  | `~/.config/Code/User/globalStorage/github.copilot-chat/`             | Tier 2 (stubbed) |
| `antigravity`     | Antigravity session directory (exact path probed at ingest time)     | Gemini-shape usage |
| `cursor`          | Cursor export JSON                                                   | Experimental — gated behind `--experimental-cursor` |

Run `sherlock ingest --provider <id>` to force a specific adapter, or omit it for auto-detection.

## Important Note on Dolt Interference

**Sherlock uses Dolt CLI commands which may interfere with running `dolt sql-server` processes** (like those used by beads). When Sherlock detects running Dolt servers, it will display a warning.

**Recommendation:** If you use beads or other Dolt-based tools:
- Complete your Sherlock operations quickly, or
- Temporarily stop Dolt servers while using Sherlock
- This interference is temporary and only occurs while Sherlock is actively running commands

## Repository Scope

**In scope:**
- Sherlock CLI runtime (ingest, report, TUI)
- Token attribution and forensics for Claude usage
- Session analysis and comparison features
- Documentation and issue tracking for Sherlock roadmap
- Visualizations for token usage patterns

**Out of scope:**
- Forge/daemon runtime concerns from legacy monorepo
- Unrelated plugin orchestration features
- Non-Sherlock tooling and experiments

This repository is dedicated to Sherlock's core mission: helping you understand and optimize your Claude token usage.

## Requirements

- Rust (`cargo`)
- Dolt (`dolt`) on `PATH`

## Usage

Initialize a Sherlock data repo:

```bash
cargo run -- --repo ~/.local/share/sherlock init
```

Ingest agent-CLI history (auto-detects provider from the path):

```bash
cargo run -- --repo ~/.local/share/sherlock ingest --history ~/.claude/history.jsonl
cargo run -- --repo ~/.local/share/sherlock ingest --provider codex --history ~/.codex/sessions/2026-04-15/rollout-abc.jsonl
cargo run -- --repo ~/.local/share/sherlock ingest --provider cursor --experimental-cursor --history ./cursor-export.json
```

Generate a JSON report:

```bash
cargo run -- --repo ~/.local/share/sherlock report --session-id <session-id>
```

Open the TUI dashboard:

```bash
cargo run -- --repo ~/.local/share/sherlock tui --session-id <session-id>
```

## LLM-narrated analysis

`sherlock analyze` feeds one or more session reports to an LLM and asks it to name the top cost drivers and suggest concrete fixes. Backend auto-selects from whichever of `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GEMINI_API_KEY` is set; otherwise prints the assembled prompt for you to paste elsewhere.

```bash
# Single-session analysis with whatever API key is in the environment
sherlock analyze --session-id <id>

# Before/after comparison between two sessions
sherlock analyze --session-id <id-a> --session-id <id-b>

# Force a specific backend and model
sherlock analyze --backend openai --model gpt-5 --session-id <id>

# Route to a local OpenAI-compatible server (Ollama, LM Studio, Together, Groq, DeepSeek)
sherlock analyze --backend openai-compatible \
  --base-url http://localhost:11434/v1 --model llama3.1 --session-id <id>

# No API call — print the assembled prompt for manual use
sherlock analyze --backend prompt-only --session-id <id>
```

## Claude Code skill

Sherlock ships a bundled Claude Code skill (`sherlock-analyze`). Install it once and Claude Code will fire Sherlock automatically when you ask it to diagnose token spend, compare sessions, or analyze a cost spike:

```bash
sherlock install-skill          # writes to ~/.claude/skills/sherlock-analyze/
sherlock install-skill --force  # overwrite an existing install
```
