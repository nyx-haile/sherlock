# Sherlock

**Claude token-usage forensics for understanding what's driving your spend.**

Have you ever asked Claude Code to "write a plan for this" and watched your usage melt down?  
That happened to me one too many times, so I built Sherlock to investigate what was really driving token spikes (spoiler: agents).

Use Sherlock to analyze your token usage, see which prompts are actually effective, and spot plugins or workflows that burn money without adding value.

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

Ingest Claude history:

```bash
cargo run -- --repo ~/.local/share/sherlock ingest --history ~/.claude/history.jsonl
```

Generate a JSON report:

```bash
cargo run -- --repo ~/.local/share/sherlock report --session-id <session-id>
```

Open the TUI dashboard:

```bash
cargo run -- --repo ~/.local/share/sherlock tui --session-id <session-id>
```
