# Sherlock

Sherlock is a Rust CLI for token-usage forensics on Claude session logs.

It ingests local JSONL history into a Dolt-backed relational store, then helps you
identify where token usage (especially cache usage) spikes.

## Requirements

- Rust toolchain (`cargo`)
- Dolt CLI (`dolt`) on PATH

## Build

```bash
cargo build
```

## Usage

Initialize a Sherlock evidence repo:

```bash
cargo run -- --repo ~/.local/share/sherlock init
```

Ingest history:

```bash
cargo run -- --repo ~/.local/share/sherlock ingest --history ~/.claude/history.jsonl
```

Generate JSON report:

```bash
cargo run -- --repo ~/.local/share/sherlock report --session-id <session-id>
```

Open terminal dashboard:

```bash
cargo run -- --repo ~/.local/share/sherlock tui --session-id <session-id>
```

Press `q` or `Esc` to quit the TUI.
