// EXPERIMENTAL: Cursor stores conversations in state.vscdb (SQLite) under
// ~/.config/Cursor/User/globalStorage/. The schema is undocumented and has
// historically shifted between minor releases. This adapter accepts a JSON
// export as the primary ingest path; a direct SQLite read mode may be added
// later once the cursorDiskKV shape is re-confirmed.

use super::{read_jsonl_file, safe_i64, Provider, RawEvent, Source, UsageSample};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

pub struct CursorProvider;

const CONTINUATION_MARKERS: &[&str] = &[];

const WORKFLOW_TOOLS: &[&str] = &["edit_file", "read_file", "run_terminal_cmd", "codebase_search"];

impl Provider for CursorProvider {
    fn id(&self) -> &'static str {
        "cursor"
    }

    fn detect(&self, path: &Path) -> u8 {
        let s = path.to_string_lossy();
        if s.contains("Cursor/User") || s.contains("cursor-export") || s.contains("cursorDiskKV") {
            return 85;
        }
        0
    }

    fn iter_events<'a>(&self, source: &'a Source<'a>) -> Result<Vec<RawEvent>> {
        match source {
            Source::JsonlFile(p) => read_jsonl_file(p),
        }
    }

    fn extract_session_id(&self, ev: &RawEvent) -> Option<String> {
        ev.as_json()
            .and_then(|o| {
                o.get("conversationId")
                    .or_else(|| o.get("session_id"))
                    .or_else(|| o.get("composerId"))
            })
            .and_then(Value::as_str)
            .map(|s| s.to_string())
    }

    fn extract_usage(&self, ev: &RawEvent) -> UsageSample {
        let Some(obj) = ev.as_json() else {
            return UsageSample::default();
        };
        let usage = obj.get("usage").or_else(|| obj.get("tokenUsage"));
        UsageSample {
            input_tokens: safe_i64(usage.and_then(|u| u.get("inputTokens")).or_else(|| usage.and_then(|u| u.get("input_tokens")))),
            output_tokens: safe_i64(usage.and_then(|u| u.get("outputTokens")).or_else(|| usage.and_then(|u| u.get("output_tokens")))),
            cache_read_tokens: None,
            cache_write_tokens: None,
        }
    }

    fn extract_tool_name(&self, ev: &RawEvent) -> String {
        ev.as_json()
            .and_then(|o| o.get("toolName").or_else(|| o.get("tool_name")))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    fn extract_plugin_id(&self, _ev: &RawEvent, _tool: &str) -> Option<String> {
        None
    }

    fn extract_mcp_server_name(&self, _tool: &str) -> Option<String> {
        None
    }

    fn extract_hook_name(&self, _ev: &RawEvent) -> String {
        String::new()
    }

    fn infer_event_type(&self, ev: &RawEvent) -> String {
        if !self.extract_tool_name(ev).is_empty() {
            return "tool_call".to_string();
        }
        let role = ev.as_json().and_then(|o| o.get("role").and_then(Value::as_str));
        match role {
            Some("user") => "prompt_submit".to_string(),
            _ => "assistant_turn".to_string(),
        }
    }

    fn extract_prompt_text(&self, ev: &RawEvent) -> Option<String> {
        let obj = ev.as_json()?;
        if obj.get("role").and_then(Value::as_str) != Some("user") {
            return None;
        }
        obj.get("text")
            .or_else(|| obj.get("content"))
            .and_then(Value::as_str)
            .map(|s| s.to_string())
    }

    fn event_time_value(&self, ev: &RawEvent) -> Option<String> {
        ev.as_json()
            .and_then(|o| o.get("timestamp").or_else(|| o.get("createdAt")))
            .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|i| i.to_string())))
    }

    fn event_time_epoch(&self, ev: &RawEvent) -> Option<i64> {
        ev.as_json()
            .and_then(|o| o.get("timestamp").or_else(|| o.get("createdAt")))
            .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
    }

    fn is_compact_summary(&self, _ev: &RawEvent) -> bool {
        false
    }

    fn continuation_markers(&self) -> &'static [&'static str] {
        CONTINUATION_MARKERS
    }

    fn workflow_tools(&self) -> &'static [&'static str] {
        WORKFLOW_TOOLS
    }

    fn has_cache_tokens(&self) -> bool {
        false
    }

    fn has_continuation_summaries(&self) -> bool {
        false
    }

    fn instability_warning(&self) -> Option<&'static str> {
        Some("cursor adapter is EXPERIMENTAL — Cursor's internal storage shape is undocumented and may drift between releases; prefer exporting conversations to JSON before ingest")
    }
}
