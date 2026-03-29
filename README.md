# Sherlock

Have you ever asked Claude Code to “write a plan for this” and watched your usage melt down?  
That happened to me one too many times, so I built Sherlock to investigate what was really driving token spikes (spoiler: agents).

Use Sherlock to analyze your token usage, see which prompts are actually effective, and spot plugins or workflows that burn money without adding value.

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
