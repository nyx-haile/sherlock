use anyhow::{anyhow, Result};
use serde_json::Value;

pub mod anthropic;
pub mod gemini;
pub mod openai;
pub mod openai_compatible;
pub mod prompt_only;

pub struct ReviewRequest {
    pub system: String,
    pub user: String,
}

pub trait ChatBackend {
    #[allow(dead_code)]
    fn id(&self) -> &'static str;
    fn send(&self, req: &ReviewRequest) -> Result<String>;
}

pub const SYSTEM_PROMPT: &str = r#"You are Sherlock, a token-usage forensic analyst. You have been given one or more structured JSON reports describing agent-CLI sessions (Claude Code, Codex, Cursor, Antigravity, or Copilot).

Your job:
1. Identify the top 3 cost drivers by name — specific prompts, tools, plugins, or workflow patterns.
2. Separate deterministic facts (present in the JSON `findings`) from your own synthesis.
3. Produce 2–5 concrete, actionable changes the user could make to reduce wasteful spend.
4. When multiple sessions are provided, compare them — note what changed, whether interventions worked, and which session was more efficient per prompt.
5. Be blunt about uncertainty. If the report lacks token attribution, say so.

Keep the response under 600 words. No preamble, no filler."#;

pub fn assemble(reports: &[Value]) -> ReviewRequest {
    let user = if reports.len() == 1 {
        format!(
            "# Session Report\n\n```json\n{}\n```\n\nAnalyze this session and report per your instructions.",
            serde_json::to_string_pretty(&reports[0]).unwrap_or_default()
        )
    } else {
        let mut out = String::from("# Multi-Session Comparison\n\n");
        for (i, rep) in reports.iter().enumerate() {
            let id = rep
                .get("session_id")
                .and_then(Value::as_str)
                .unwrap_or(&format!("session-{i}"))
                .to_string();
            out.push_str(&format!(
                "## Session {}\n\n```json\n{}\n```\n\n",
                id,
                serde_json::to_string_pretty(rep).unwrap_or_default()
            ));
        }
        out.push_str("Compare these sessions per your instructions. Call out what changed and whether interventions worked.");
        out
    };
    ReviewRequest {
        system: SYSTEM_PROMPT.to_string(),
        user,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendId {
    Anthropic,
    Openai,
    Gemini,
    OpenaiCompatible,
    PromptOnly,
}

pub fn auto_select() -> BackendId {
    if std::env::var("ANTHROPIC_API_KEY").is_ok() {
        BackendId::Anthropic
    } else if std::env::var("OPENAI_API_KEY").is_ok() {
        BackendId::Openai
    } else if std::env::var("GEMINI_API_KEY").is_ok() || std::env::var("GOOGLE_API_KEY").is_ok() {
        BackendId::Gemini
    } else {
        BackendId::PromptOnly
    }
}

pub fn make_backend(
    id: BackendId,
    model: Option<String>,
    base_url: Option<String>,
    api_key_env: Option<String>,
) -> Result<Box<dyn ChatBackend>> {
    match id {
        BackendId::Anthropic => Ok(Box::new(anthropic::AnthropicBackend::new(
            model.unwrap_or_else(|| "claude-sonnet-4-5".to_string()),
            api_key_env.unwrap_or_else(|| "ANTHROPIC_API_KEY".to_string()),
        )?)),
        BackendId::Openai => Ok(Box::new(openai::OpenAIBackend::new(
            model.unwrap_or_else(|| "gpt-5".to_string()),
            api_key_env.unwrap_or_else(|| "OPENAI_API_KEY".to_string()),
        )?)),
        BackendId::Gemini => Ok(Box::new(gemini::GeminiBackend::new(
            model.unwrap_or_else(|| "gemini-2.5-pro".to_string()),
            api_key_env.unwrap_or_else(|| "GEMINI_API_KEY".to_string()),
        )?)),
        BackendId::OpenaiCompatible => {
            let model = model.ok_or_else(|| {
                anyhow!("--model is required for openai-compatible backend")
            })?;
            let base_url = base_url.ok_or_else(|| {
                anyhow!("--base-url is required for openai-compatible backend")
            })?;
            Ok(Box::new(openai_compatible::OpenAICompatibleBackend::new(
                model,
                base_url,
                api_key_env,
            )?))
        }
        BackendId::PromptOnly => Ok(Box::new(prompt_only::PromptOnlyBackend)),
    }
}

pub fn parse_backend_id(s: &str) -> Result<BackendId> {
    match s {
        "anthropic" => Ok(BackendId::Anthropic),
        "openai" => Ok(BackendId::Openai),
        "gemini" => Ok(BackendId::Gemini),
        "openai-compatible" => Ok(BackendId::OpenaiCompatible),
        "prompt-only" => Ok(BackendId::PromptOnly),
        other => Err(anyhow!(
            "unknown backend: {other} (expected anthropic|openai|gemini|openai-compatible|prompt-only)"
        )),
    }
}
