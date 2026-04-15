use super::{ChatBackend, ReviewRequest};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};

pub struct AnthropicBackend {
    model: String,
    api_key: String,
}

impl AnthropicBackend {
    pub fn new(model: String, api_key_env: String) -> Result<Self> {
        let api_key = std::env::var(&api_key_env)
            .map_err(|_| anyhow!("env var {api_key_env} is not set"))?;
        Ok(Self { model, api_key })
    }
}

impl ChatBackend for AnthropicBackend {
    fn id(&self) -> &'static str {
        "anthropic"
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
            let body = json!({
                "model": self.model,
                "max_tokens": 2048,
                "system": [{
                    "type": "text",
                    "text": req.system,
                    "cache_control": {"type": "ephemeral"}
                }],
                "messages": [{
                    "role": "user",
                    "content": req.user,
                }]
            });
            let resp = client
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .json(&body)
                .send()?;
            let status = resp.status();
            let parsed: Value = resp.json()?;
            if !status.is_success() {
                return Err(anyhow!(
                    "anthropic api error ({}): {}",
                    status,
                    parsed
                ));
            }
            let text = parsed
                .get("content")
                .and_then(Value::as_array)
                .and_then(|arr| arr.iter().find_map(|item| item.get("text").and_then(Value::as_str)))
                .unwrap_or("")
                .to_string();
            Ok(text)
        }
    }
}
