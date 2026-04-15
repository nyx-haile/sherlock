use super::{read_jsonl_file, safe_i64, Provider, RawEvent, Source, UsageSample};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

pub struct CodexProvider;

const CONTINUATION_MARKERS: &[&str] = &[
    "resuming previous session",
    "continuing from previous conversation",
    "previous session summary",
];

const WORKFLOW_TOOLS: &[&str] = &[
    "shell",
    "exec",
    "apply_patch",
    "read_file",
    "write_file",
    "list_files",
    "edit",
];

impl Provider for CodexProvider {
    fn id(&self) -> &'static str {
        "codex"
    }

    fn detect(&self, path: &Path) -> u8 {
        let s = path.to_string_lossy();
        if s.contains(".codex/sessions") || s.contains("rollout-") {
            return 90;
        }
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        for line in raw.lines().take(6) {
            if line.contains("\"response.output\"") || line.contains("\"function_call\"") {
                return 70;
            }
            if line.contains("\"type\":\"session_meta\"")
                || line.contains("\"type\": \"session_meta\"")
            {
                return 80;
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
        let obj = ev.as_json()?;
        obj.get("session_id")
            .or_else(|| obj.get("sessionId"))
            .or_else(|| obj.get("id"))
            .and_then(Value::as_str)
            .map(|s| s.to_string())
    }

    fn extract_usage(&self, ev: &RawEvent) -> UsageSample {
        let Some(obj) = ev.as_json() else {
            return UsageSample::default();
        };
        // Codex rollouts carry usage on response.completed events under response.usage
        let usage = obj
            .get("response")
            .and_then(|r| r.get("usage"))
            .or_else(|| obj.get("usage"));
        let input_tokens = safe_i64(usage.and_then(|u| u.get("input_tokens")));
        let output_tokens = safe_i64(usage.and_then(|u| u.get("output_tokens")));
        let cache_read_tokens = safe_i64(
            usage
                .and_then(|u| u.get("input_tokens_details"))
                .and_then(|d| d.get("cached_tokens"))
                .or_else(|| usage.and_then(|u| u.get("cache_read_input_tokens"))),
        );
        UsageSample {
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cache_write_tokens: None,
        }
    }

    fn extract_tool_name(&self, ev: &RawEvent) -> String {
        let Some(obj) = ev.as_json() else {
            return String::new();
        };
        // Codex response events nest function/tool calls as items within response.output[]
        if let Some(items) = obj
            .get("item")
            .into_iter()
            .chain(
                obj.get("response")
                    .and_then(|r| r.get("output"))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flat_map(|a| a.iter()),
            )
            .next()
        {
            if items.get("type").and_then(Value::as_str) == Some("function_call") {
                if let Some(name) = items.get("name").and_then(Value::as_str) {
                    return name.to_string();
                }
            }
            if items.get("type").and_then(Value::as_str) == Some("custom_tool_call") {
                if let Some(name) = items.get("name").and_then(Value::as_str) {
                    return name.to_string();
                }
            }
        }
        if let Some(v) = obj.get("tool_name").and_then(Value::as_str) {
            return v.to_string();
        }
        String::new()
    }

    fn extract_plugin_id(&self, _ev: &RawEvent, tool_name: &str) -> Option<String> {
        // Codex CLI does not yet have a plugin ecosystem. Any MCP-style prefix is mapped through.
        if tool_name.starts_with("mcp__") {
            let parts: Vec<&str> = tool_name.split("__").collect();
            if parts.len() >= 2 {
                return Some(format!("mcp:{}", parts[1]));
            }
        }
        None
    }

    fn extract_mcp_server_name(&self, tool_name: &str) -> Option<String> {
        if !tool_name.starts_with("mcp__") {
            return None;
        }
        let parts: Vec<&str> = tool_name.split("__").collect();
        if parts.len() >= 2 {
            return Some(parts[1].to_string());
        }
        None
    }

    fn extract_hook_name(&self, _ev: &RawEvent) -> String {
        String::new()
    }

    fn infer_event_type(&self, ev: &RawEvent) -> String {
        let Some(obj) = ev.as_json() else {
            return "assistant_turn".to_string();
        };
        if !self.extract_tool_name(ev).is_empty() {
            return "tool_call".to_string();
        }
        let ty = obj.get("type").and_then(Value::as_str).unwrap_or("");
        match ty {
            "user_message" | "user_input" => "prompt_submit".to_string(),
            "session_meta" => "session_meta".to_string(),
            _ => {
                // role-based fallback
                let role = obj
                    .get("role")
                    .or_else(|| obj.get("message").and_then(|m| m.get("role")))
                    .and_then(Value::as_str);
                match role {
                    Some("user") => "prompt_submit".to_string(),
                    _ => "assistant_turn".to_string(),
                }
            }
        }
    }

    fn extract_prompt_text(&self, ev: &RawEvent) -> Option<String> {
        let obj = ev.as_json()?;
        let ty = obj.get("type").and_then(Value::as_str).unwrap_or("");
        let is_user = matches!(ty, "user_message" | "user_input")
            || obj.get("role").and_then(Value::as_str) == Some("user")
            || obj
                .get("message")
                .and_then(|m| m.get("role"))
                .and_then(Value::as_str)
                == Some("user");
        if !is_user {
            return None;
        }
        // Prompt text can live under text, content, or message.content[]
        if let Some(text) = obj.get("text").and_then(Value::as_str) {
            return Some(text.to_string());
        }
        if let Some(content) = obj.get("content") {
            return flatten_content(content);
        }
        if let Some(content) = obj.get("message").and_then(|m| m.get("content")) {
            return flatten_content(content);
        }
        None
    }

    fn event_time_value(&self, ev: &RawEvent) -> Option<String> {
        let obj = ev.as_json()?;
        obj.get("timestamp")
            .or_else(|| obj.get("created_at"))
            .and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|i| i.to_string())))
    }

    fn event_time_epoch(&self, ev: &RawEvent) -> Option<i64> {
        let obj = ev.as_json()?;
        obj.get("timestamp")
            .or_else(|| obj.get("created_at"))
            .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok())))
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
        true
    }
}

fn flatten_content(content: &Value) -> Option<String> {
    match content {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => {
            let mut parts = Vec::new();
            for item in items {
                if let Some(text) = item.get("text").and_then(Value::as_str) {
                    parts.push(text.to_string());
                } else if let Some(text) = item.as_str() {
                    parts.push(text.to_string());
                }
            }
            if parts.is_empty() {
                None
            } else {
                Some(parts.join("\n\n"))
            }
        }
        _ => None,
    }
}
