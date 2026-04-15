use super::{ChatBackend, ReviewRequest};
use anyhow::Result;

pub struct PromptOnlyBackend;

impl ChatBackend for PromptOnlyBackend {
    fn id(&self) -> &'static str {
        "prompt-only"
    }

    fn send(&self, req: &ReviewRequest) -> Result<String> {
        Ok(format!(
            "--- SYSTEM ---\n{}\n\n--- USER ---\n{}\n\n(Copy the above into any chat interface for analysis. No API key was used.)",
            req.system, req.user
        ))
    }
}
