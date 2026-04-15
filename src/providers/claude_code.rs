use super::{read_jsonl_file, safe_i64, Provider, RawEvent, Source, UsageSample};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

pub struct ClaudeCodeProvider;

const CONTINUATION_MARKERS: &[&str] = &[
    "this session is being continued from a previous conversation",
    "ran out of context",
    "continue the conversation from where it left off",
    "summary below covers the earlier portion of the conversation",
];

const WORKFLOW_TOOLS: &[&str] = &[
    "Read",
    "TaskUpdate",
    "Task",
    "Agent",
    "Bash",
    "exec_command",
    "write_stdin",
    "spawn_agent",
    "send_input",
];

impl Provider for ClaudeCodeProvider {
    fn id(&self) -> &'static str {
        "claude-code"
    }

    fn detect(&self, path: &Path) -> u8 {
        let s = path.to_string_lossy();
        if s.contains(".claude/projects") || s.contains(".claude/history") {
            return 90;
        }
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        for line in raw.lines().take(4) {
            if line.contains("\"sessionId\"") && line.contains("\"message\"") {
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
        let obj = ev.as_json()?;
        obj.get("sessionId")
            .or_else(|| obj.get("session_id"))
            .and_then(Value::as_str)
            .map(|s| s.to_string())
    }

    fn extract_usage(&self, ev: &RawEvent) -> UsageSample {
        let Some(obj) = ev.as_json() else {
            return UsageSample::default();
        };
        let usage = obj
            .get("message")
            .and_then(|m| m.get("usage"))
            .or_else(|| obj.get("usage"));
        let cache_creation_sum = usage.and_then(|u| u.get("cache_creation")).map(|c| {
            let a = safe_i64(c.get("ephemeral_1h_input_tokens")).unwrap_or(0);
            let b = safe_i64(c.get("ephemeral_5m_input_tokens")).unwrap_or(0);
            a + b
        });
        let input_tokens = safe_i64(
            usage
                .and_then(|u| u.get("input_tokens"))
                .or_else(|| obj.get("input_tokens_cum"))
                .or_else(|| obj.get("input_tokens")),
        );
        let output_tokens = safe_i64(
            usage
                .and_then(|u| u.get("output_tokens"))
                .or_else(|| obj.get("output_tokens_cum"))
                .or_else(|| obj.get("output_tokens")),
        );
        let cache_read_tokens = safe_i64(
            usage
                .and_then(|u| u.get("cache_read_input_tokens"))
                .or_else(|| usage.and_then(|u| u.get("cache_read_tokens")))
                .or_else(|| obj.get("cache_read_tokens_cum"))
                .or_else(|| obj.get("cache_read_tokens")),
        );
        let cache_write_tokens = safe_i64(
            usage
                .and_then(|u| u.get("cache_creation_input_tokens"))
                .or_else(|| obj.get("cache_write_tokens_cum"))
                .or_else(|| obj.get("cache_write_tokens")),
        )
        .or(cache_creation_sum);
        UsageSample {
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cache_write_tokens,
        }
    }

    fn extract_tool_name(&self, ev: &RawEvent) -> String {
        let Some(obj) = ev.as_json() else {
            return String::new();
        };
        if let Some(v) = obj.get("tool_name").and_then(Value::as_str) {
            return v.to_string();
        }
        if let Some(v) = obj
            .get("toolUseResult")
            .and_then(|t| t.get("commandName"))
            .and_then(Value::as_str)
        {
            return v.to_string();
        }
        obj.get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_array)
            .and_then(|arr| {
                arr.iter().find_map(|item| {
                    if item.get("type").and_then(Value::as_str) == Some("tool_use") {
                        item.get("name")
                            .and_then(Value::as_str)
                            .map(|s| s.to_string())
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_default()
    }

    fn extract_plugin_id(&self, ev: &RawEvent, tool_name: &str) -> Option<String> {
        let obj = ev.as_json()?;
        if let Some(v) = obj.get("plugin_id").and_then(Value::as_str) {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
        if tool_name == "Skill" {
            if let Some(skill) = obj
                .get("message")
                .and_then(|m| m.get("content"))
                .and_then(Value::as_array)
                .and_then(|arr| {
                    arr.iter().find_map(|item| {
                        if item.get("type").and_then(Value::as_str) == Some("tool_use")
                            && item.get("name").and_then(Value::as_str) == Some("Skill")
                        {
                            item.get("input")
                                .and_then(|v| v.get("skill"))
                                .and_then(Value::as_str)
                                .map(|s| format!("skill:{s}"))
                        } else {
                            None
                        }
                    })
                })
            {
                return Some(skill);
            }
        }
        if tool_name.starts_with("mcp__") {
            if let Some(server) = self.extract_mcp_server_name(tool_name) {
                if server.starts_with("plugin_") {
                    return Some(server);
                }
                return Some(format!("mcp:{server}"));
            }
            return Some("mcp:unknown".to_string());
        }
        if let Some(cmd) = obj
            .get("toolUseResult")
            .and_then(|t| t.get("commandName"))
            .and_then(Value::as_str)
        {
            if !cmd.is_empty() {
                return Some(format!("tool-result:{cmd}"));
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

    fn extract_hook_name(&self, ev: &RawEvent) -> String {
        let Some(obj) = ev.as_json() else {
            return String::new();
        };
        obj.get("hook_event_name")
            .or_else(|| obj.get("data").and_then(|data| data.get("hookName")))
            .or_else(|| obj.get("data").and_then(|data| data.get("hookEvent")))
            .or_else(|| obj.get("subtype"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    fn infer_event_type(&self, ev: &RawEvent) -> String {
        if !self.extract_tool_name(ev).is_empty() {
            return "tool_call".to_string();
        }
        if !self.extract_hook_name(ev).is_empty() {
            return "hook_event".to_string();
        }
        let Some(obj) = ev.as_json() else {
            return "assistant_turn".to_string();
        };
        if obj.get("type").and_then(Value::as_str) == Some("user")
            || obj
                .get("message")
                .and_then(|m| m.get("role"))
                .and_then(Value::as_str)
                == Some("user")
        {
            return "prompt_submit".to_string();
        }
        "assistant_turn".to_string()
    }

    fn extract_prompt_text(&self, ev: &RawEvent) -> Option<String> {
        let obj = ev.as_json()?;
        if obj.get("type").and_then(Value::as_str) != Some("user")
            && obj
                .get("message")
                .and_then(|message| message.get("role"))
                .and_then(Value::as_str)
                != Some("user")
        {
            return None;
        }
        let content = obj
            .get("message")
            .and_then(|message| message.get("content"))?;
        match content {
            Value::String(text) => Some(text.to_string()),
            Value::Array(items) => {
                let mut parts = Vec::new();
                for item in items {
                    let item_type = item.get("type").and_then(Value::as_str).unwrap_or("");
                    match item_type {
                        "tool_result" | "tool_reference" => {}
                        "text" => {
                            if let Some(text) = item.get("text").and_then(Value::as_str) {
                                parts.push(text.to_string());
                            }
                        }
                        _ => {
                            if let Some(text) = item.get("text").and_then(Value::as_str) {
                                parts.push(text.to_string());
                            } else if let Some(text) = item.as_str() {
                                parts.push(text.to_string());
                            }
                        }
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

    fn event_time_value(&self, ev: &RawEvent) -> Option<String> {
        let obj = ev.as_json()?;
        if let Some(ts) = obj.get("timestamp") {
            if let Some(s) = ts.as_str() {
                return Some(s.to_string());
            }
            if let Some(i) = ts.as_i64() {
                return Some(i.to_string());
            }
        }
        obj.get("created_at")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
    }

    fn event_time_epoch(&self, ev: &RawEvent) -> Option<i64> {
        let obj = ev.as_json()?;
        obj.get("timestamp")
            .and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
            })
            .or_else(|| obj.get("created_at").and_then(Value::as_i64))
    }

    fn is_compact_summary(&self, ev: &RawEvent) -> bool {
        ev.as_json()
            .and_then(|obj| obj.get("isCompactSummary"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    fn continuation_markers(&self) -> &'static [&'static str] {
        CONTINUATION_MARKERS
    }

    fn workflow_tools(&self) -> &'static [&'static str] {
        WORKFLOW_TOOLS
    }
}
