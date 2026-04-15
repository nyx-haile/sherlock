// Google Antigravity agent IDE. Expected log shape is Gemini-style with
// `usageMetadata.{promptTokenCount,candidatesTokenCount,cachedContentTokenCount}`.
// Exact log path is confirmed at runtime by the user, not hardcoded here.

use super::{read_jsonl_file, safe_i64, Provider, RawEvent, Source, UsageSample};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

pub struct AntigravityProvider;

const CONTINUATION_MARKERS: &[&str] = &["continuing previous antigravity session"];

const WORKFLOW_TOOLS: &[&str] = &["runShellCommand", "readFile", "writeFile", "editFile", "listFiles"];

impl Provider for AntigravityProvider {
    fn id(&self) -> &'static str {
        "antigravity"
    }

    fn detect(&self, path: &Path) -> u8 {
        let s = path.to_string_lossy();
        if s.contains("antigravity") {
            return 90;
        }
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        for line in raw.lines().take(4) {
            if line.contains("usageMetadata") && line.contains("promptTokenCount") {
                return 70;
            }
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
                o.get("sessionId")
                    .or_else(|| o.get("session_id"))
                    .or_else(|| o.get("conversationId"))
            })
            .and_then(Value::as_str)
            .map(|s| s.to_string())
    }

    fn extract_usage(&self, ev: &RawEvent) -> UsageSample {
        let Some(obj) = ev.as_json() else {
            return UsageSample::default();
        };
        let meta = obj.get("usageMetadata").or_else(|| obj.get("usage_metadata"));
        UsageSample {
            input_tokens: safe_i64(meta.and_then(|m| m.get("promptTokenCount"))),
            output_tokens: safe_i64(meta.and_then(|m| m.get("candidatesTokenCount"))),
            cache_read_tokens: safe_i64(meta.and_then(|m| m.get("cachedContentTokenCount"))),
            cache_write_tokens: None,
        }
    }

    fn extract_tool_name(&self, ev: &RawEvent) -> String {
        let Some(obj) = ev.as_json() else {
            return String::new();
        };
        obj.get("functionCall")
            .and_then(|fc| fc.get("name"))
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
        let role = ev
            .as_json()
            .and_then(|o| o.get("role").and_then(Value::as_str));
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
        obj.get("parts")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("\n\n")
            })
            .filter(|s| !s.is_empty())
            .or_else(|| obj.get("text").and_then(Value::as_str).map(|s| s.to_string()))
    }

    fn event_time_value(&self, ev: &RawEvent) -> Option<String> {
        ev.as_json()
            .and_then(|o| o.get("timestamp"))
            .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|i| i.to_string())))
    }

    fn event_time_epoch(&self, ev: &RawEvent) -> Option<i64> {
        ev.as_json()
            .and_then(|o| o.get("timestamp"))
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

    fn instability_warning(&self) -> Option<&'static str> {
        Some("antigravity adapter uses expected Gemini-style fields — confirm against a real fixture; totals may be zero until shape is verified")
    }
}
