use super::{ChatBackend, ReviewRequest};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};

pub struct GeminiBackend {
    model: String,
    api_key: String,
}

impl GeminiBackend {
    pub fn new(model: String, api_key_env: String) -> Result<Self> {
        let api_key = std::env::var(&api_key_env)
            .or_else(|_| std::env::var("GOOGLE_API_KEY"))
            .map_err(|_| anyhow!("env var {api_key_env} (or GOOGLE_API_KEY) is not set"))?;
        Ok(Self { model, api_key })
    }
}

impl ChatBackend for GeminiBackend {
    fn id(&self) -> &'static str {
        "gemini"
    }

    fn send(&self, req: &ReviewRequest) -> Result<String> {
        #[cfg(not(feature = "analyze"))]
        {
            let _ = req;
            return Err(anyhow!("sherlock built without the `analyze` feature"));
        }
        #[cfg(feature = "analyze")]
        {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()?;
            let url = format!(
                "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
                self.model, self.api_key
            );
            let body = json!({
                "systemInstruction": {"parts": [{"text": req.system}]},
                "contents": [{"role": "user", "parts": [{"text": req.user}]}],
            });
            let resp = client
                .post(url)
                .header("content-type", "application/json")
                .json(&body)
                .send()?;
            let status = resp.status();
            let parsed: Value = resp.json()?;
            if !status.is_success() {
                return Err(anyhow!("gemini api error ({}): {}", status, parsed));
            }
            let text = parsed
                .get("candidates")
                .and_then(Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(|c| c.get("content"))
                .and_then(|m| m.get("parts"))
                .and_then(Value::as_array)
                .map(|parts| {
                    parts
                        .iter()
                        .filter_map(|p| p.get("text").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join("")
                })
                .unwrap_or_default();
            Ok(text)
        }
    }
}
