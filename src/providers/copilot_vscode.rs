// Tier-2 target: GitHub Copilot Chat inside VS Code. Storage is extension-local
// under ~/.config/Code/User/globalStorage/github.copilot-chat/. This adapter is
// a placeholder — once a fixture is captured we'll implement real extraction.

use super::{read_jsonl_file, Provider, RawEvent, Source, UsageSample};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

pub struct CopilotVscodeProvider;

impl Provider for CopilotVscodeProvider {
    fn id(&self) -> &'static str {
        "copilot-vscode"
    }

    fn detect(&self, path: &Path) -> u8 {
        let s = path.to_string_lossy();
        if s.contains("github.copilot-chat") || s.contains("copilot-vscode") {
            return 80;
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
            .and_then(|o| o.get("sessionId").or_else(|| o.get("session_id")))
            .and_then(Value::as_str)
            .map(|s| s.to_string())
    }

    fn extract_usage(&self, _ev: &RawEvent) -> UsageSample {
        UsageSample::default()
    }

    fn extract_tool_name(&self, _ev: &RawEvent) -> String {
        String::new()
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

    fn infer_event_type(&self, _ev: &RawEvent) -> String {
        "assistant_turn".to_string()
    }

    fn extract_prompt_text(&self, _ev: &RawEvent) -> Option<String> {
        None
    }

    fn event_time_value(&self, _ev: &RawEvent) -> Option<String> {
        None
    }

    fn event_time_epoch(&self, _ev: &RawEvent) -> Option<i64> {
        None
    }

    fn is_compact_summary(&self, _ev: &RawEvent) -> bool {
        false
    }

    fn continuation_markers(&self) -> &'static [&'static str] {
        &[]
    }

    fn workflow_tools(&self) -> &'static [&'static str] {
        &[]
    }

    fn has_cache_tokens(&self) -> bool {
        false
    }

    fn instability_warning(&self) -> Option<&'static str> {
        Some("copilot-vscode adapter is a stub — fixture pending; totals will be zero until shape is confirmed")
    }
}
