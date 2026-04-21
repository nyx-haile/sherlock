use anyhow::Result;
use serde_json::Value;
use std::path::Path;

pub mod antigravity;
pub mod claude_code;
pub mod codex;
pub mod copilot_cli;
pub mod copilot_vscode;
#[cfg(feature = "cursor")]
pub mod cursor;

#[derive(Default, Clone, Copy, Debug)]
pub struct UsageSample {
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cache_read_tokens: Option<i64>,
    pub cache_write_tokens: Option<i64>,
}

#[derive(Clone, Debug)]
pub enum RawEvent {
    Json(Value),
}

impl RawEvent {
    pub fn as_json(&self) -> Option<&Value> {
        match self {
            RawEvent::Json(v) => Some(v),
        }
    }
}

#[allow(dead_code)]
pub enum Source<'a> {
    JsonlFile(&'a Path),
}

pub trait Provider: Send + Sync {
    fn id(&self) -> &'static str;

    fn detect(&self, path: &Path) -> u8;

    #[allow(dead_code)]
    fn iter_events<'a>(&self, source: &'a Source<'a>) -> Result<Vec<RawEvent>>;

    fn extract_session_id(&self, ev: &RawEvent) -> Option<String>;
    fn extract_usage(&self, ev: &RawEvent) -> UsageSample;
    fn extract_tool_name(&self, ev: &RawEvent) -> String;
    fn extract_plugin_id(&self, ev: &RawEvent, tool: &str) -> Option<String>;
    fn extract_mcp_server_name(&self, tool: &str) -> Option<String>;
    fn extract_hook_name(&self, ev: &RawEvent) -> String;
    fn extract_subagent_type(&self, _ev: &RawEvent) -> Option<String> {
        None
    }
    fn infer_event_type(&self, ev: &RawEvent) -> String;
    fn extract_prompt_text(&self, ev: &RawEvent) -> Option<String>;
    fn event_time_value(&self, ev: &RawEvent) -> Option<String>;
    fn event_time_epoch(&self, ev: &RawEvent) -> Option<i64>;
    fn is_compact_summary(&self, ev: &RawEvent) -> bool;

    fn continuation_markers(&self) -> &'static [&'static str];
    fn workflow_tools(&self) -> &'static [&'static str];
    fn spike_threshold(&self) -> i64 {
        1000
    }

    fn has_cache_tokens(&self) -> bool {
        true
    }
    fn has_continuation_summaries(&self) -> bool {
        true
    }

    fn is_continuation_summary(&self, text: &str) -> bool {
        let compact = text.to_ascii_lowercase();
        self.continuation_markers()
            .iter()
            .any(|m| compact.contains(m))
    }

    fn is_workflow_tool(&self, tool_name: &str) -> bool {
        self.workflow_tools().iter().any(|t| *t == tool_name)
    }

    fn instability_warning(&self) -> Option<&'static str> {
        None
    }
}

pub fn registry() -> Vec<Box<dyn Provider>> {
    let mut out: Vec<Box<dyn Provider>> = vec![
        Box::new(claude_code::ClaudeCodeProvider),
        Box::new(codex::CodexProvider),
        Box::new(copilot_cli::CopilotCliProvider),
        Box::new(copilot_vscode::CopilotVscodeProvider),
        Box::new(antigravity::AntigravityProvider),
    ];
    #[cfg(feature = "cursor")]
    out.push(Box::new(cursor::CursorProvider));
    out
}

pub fn by_id(id: &str) -> Option<Box<dyn Provider>> {
    registry().into_iter().find(|p| p.id() == id)
}

pub fn detect_provider(path: &Path) -> Box<dyn Provider> {
    let mut best: (u8, Option<Box<dyn Provider>>) = (0, None);
    for p in registry() {
        let score = p.detect(path);
        if score > best.0 {
            best = (score, Some(p));
        }
    }
    best.1
        .unwrap_or_else(|| Box::new(claude_code::ClaudeCodeProvider))
}

pub(crate) fn safe_i64(v: Option<&Value>) -> Option<i64> {
    match v {
        None => None,
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.parse::<i64>().ok(),
        _ => None,
    }
}

#[allow(dead_code)]
pub(crate) fn read_jsonl_file(path: &Path) -> Result<Vec<RawEvent>> {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            out.push(RawEvent::Json(v));
        }
    }
    Ok(out)
}
