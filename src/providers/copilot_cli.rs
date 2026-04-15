// Tier-1 target: the `copilot` CLI tool (session logs under
// `~/.copilot/session-state/<session-id>/events.jsonl`).
//
// Shape (real, probed 2026-04-15):
//   - Each session is its own directory; events.jsonl is an append-only stream.
//   - Top-level fields: { type, data, id, timestamp, parentId }.
//   - `session.start` / `session.resume` carry data.sessionId.
//   - `user.message`.data.content holds the raw prompt text.
//   - `tool.execution_start`.data.toolName / .arguments / .toolCallId.
//   - Usage is NOT attached per-turn. It only appears on `session.shutdown`
//     as cumulative counts per model under
//     data.modelMetrics.<model>.usage.{inputTokens,outputTokens,cacheReadTokens,cacheWriteTokens}.
//     We surface these as a single end-of-session sample; per-turn attribution
//     is not recoverable from these logs.

use super::{read_jsonl_file, safe_i64, Provider, RawEvent, Source, UsageSample};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

pub struct CopilotCliProvider;

const CONTINUATION_MARKERS: &[&str] = &["session.resume"];

const WORKFLOW_TOOLS: &[&str] = &[
    "bash",
    "shell",
    "run_command",
    "read_file",
    "write_file",
    "edit_file",
    "str_replace_editor",
    "view",
    "create_file",
];

impl Provider for CopilotCliProvider {
    fn id(&self) -> &'static str {
        "copilot-cli"
    }

    fn detect(&self, path: &Path) -> u8 {
        let s = path.to_string_lossy();
        if s.contains(".copilot/session-state") && s.ends_with("events.jsonl") {
            return 95;
        }
        if s.contains("gh-copilot") || s.contains("copilot-cli") {
            return 60;
        }
        // Shape sniff — first few lines should carry session.start / user.message.
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        for line in raw.lines().take(4) {
            if line.contains("\"copilot-agent\"") || line.contains("\"session.start\"") {
                return 85;
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
        obj.get("data")
            .and_then(|d| d.get("sessionId"))
            .and_then(Value::as_str)
            .map(|s| s.to_string())
    }

    fn extract_usage(&self, ev: &RawEvent) -> UsageSample {
        let Some(obj) = ev.as_json() else {
            return UsageSample::default();
        };
        // Usage only lands on session.shutdown — cumulative across the session,
        // split by model. Sum across all models so we capture the full spend
        // regardless of which model handled which turn.
        if obj.get("type").and_then(Value::as_str) != Some("session.shutdown") {
            return UsageSample::default();
        }
        let Some(metrics) = obj
            .get("data")
            .and_then(|d| d.get("modelMetrics"))
            .and_then(Value::as_object)
        else {
            return UsageSample::default();
        };
        let mut input = 0i64;
        let mut output = 0i64;
        let mut cache_read = 0i64;
        let mut cache_write = 0i64;
        let mut any = false;
        for (_, per_model) in metrics {
            let Some(usage) = per_model.get("usage") else {
                continue;
            };
            any = true;
            input += safe_i64(usage.get("inputTokens")).unwrap_or(0);
            output += safe_i64(usage.get("outputTokens")).unwrap_or(0);
            cache_read += safe_i64(usage.get("cacheReadTokens")).unwrap_or(0);
            cache_write += safe_i64(usage.get("cacheWriteTokens")).unwrap_or(0);
        }
        if !any {
            return UsageSample::default();
        }
        UsageSample {
            input_tokens: Some(input),
            output_tokens: Some(output),
            cache_read_tokens: Some(cache_read),
            cache_write_tokens: Some(cache_write),
        }
    }

    fn extract_tool_name(&self, ev: &RawEvent) -> String {
        let Some(obj) = ev.as_json() else {
            return String::new();
        };
        if obj.get("type").and_then(Value::as_str) != Some("tool.execution_start") {
            return String::new();
        }
        obj.get("data")
            .and_then(|d| d.get("toolName"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    fn extract_plugin_id(&self, ev: &RawEvent, tool_name: &str) -> Option<String> {
        if tool_name.starts_with("mcp__") {
            let parts: Vec<&str> = tool_name.split("__").collect();
            if parts.len() >= 2 {
                return Some(format!("mcp:{}", parts[1]));
            }
        }
        // copilot also namespaces some extension tools as "<ext>.<tool>".
        if let Some(obj) = ev.as_json() {
            if let Some(ext) = obj
                .get("data")
                .and_then(|d| d.get("extension"))
                .and_then(Value::as_str)
            {
                if !ext.is_empty() {
                    return Some(format!("extension:{ext}"));
                }
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
        let ty = obj.get("type").and_then(Value::as_str).unwrap_or("");
        match ty {
            "user.message" => "prompt_submit".to_string(),
            "tool.execution_start" => "tool_call".to_string(),
            "assistant.message" | "assistant.turn_end" | "assistant.turn_start" => {
                "assistant_turn".to_string()
            }
            "session.start" | "session.resume" => "session_meta".to_string(),
            "session.shutdown" => "session_end".to_string(),
            _ => "assistant_turn".to_string(),
        }
    }

    fn extract_prompt_text(&self, ev: &RawEvent) -> Option<String> {
        let obj = ev.as_json()?;
        if obj.get("type").and_then(Value::as_str) != Some("user.message") {
            return None;
        }
        obj.get("data")
            .and_then(|d| d.get("content"))
            .and_then(Value::as_str)
            .map(|s| s.to_string())
    }

    fn event_time_value(&self, ev: &RawEvent) -> Option<String> {
        ev.as_json()
            .and_then(|obj| obj.get("timestamp").and_then(Value::as_str).map(|s| s.to_string()))
    }

    fn event_time_epoch(&self, ev: &RawEvent) -> Option<i64> {
        ev.as_json().and_then(|obj| {
            obj.get("timestamp").and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_str().and_then(parse_rfc3339_epoch))
            })
        })
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
        // Cumulative cacheReadTokens/cacheWriteTokens are present on
        // session.shutdown, so the cache-read-dominated finding still applies
        // at the session level.
        true
    }

    fn has_continuation_summaries(&self) -> bool {
        false
    }
}

fn parse_rfc3339_epoch(s: &str) -> Option<i64> {
    // Best-effort: strip millis + Z and parse via chrono-free math.
    // We only need a monotonic integer for ordering, so fall back to 0 on any parse trouble.
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let (y, rest) = date.split_once('-')?;
    let (m, d) = rest.split_once('-')?;
    let (hms, _frac) = time.split_once('.').unwrap_or((time, ""));
    let mut parts = hms.split(':');
    let hh: i64 = parts.next()?.parse().ok()?;
    let mm: i64 = parts.next()?.parse().ok()?;
    let ss: i64 = parts.next()?.parse().ok()?;
    let y: i64 = y.parse().ok()?;
    let m: i64 = m.parse().ok()?;
    let d: i64 = d.parse().ok()?;
    // Days from 1970-01-01 (naive; ignores leap seconds, fine for ordering).
    let days_from_epoch = (y - 1970) * 365 + ((y - 1969) / 4) + day_of_year(y, m, d) - 1;
    Some(days_from_epoch * 86400 + hh * 3600 + mm * 60 + ss)
}

fn day_of_year(y: i64, m: i64, d: i64) -> i64 {
    let mdays = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let total: i64 = mdays.iter().take((m - 1) as usize).sum();
    let mut total = total;
    if m > 2 && leap {
        total += 1;
    }
    total + d
}
