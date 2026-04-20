//! Live, on-demand data sources — not JSONL transcripts.
//!
//! Providers under `src/providers/` replay recorded history files.
//! Modules here poll authenticated endpoints and never persist tokens.

pub mod claude_code_oauth;
