use super::{ChatBackend, ReviewRequest};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};

pub struct OpenAIBackend {
    model: String,
    api_key: String,
}

impl OpenAIBackend {
    pub fn new(model: String, api_key_env: String) -> Result<Self> {
        let api_key = std::env::var(&api_key_env)
            .map_err(|_| anyhow!("env var {api_key_env} is not set"))?;
        Ok(Self { model, api_key })
    }
}

impl ChatBackend for OpenAIBackend {
    fn id(&self) -> &'static str {
        "openai"
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
                "messages": [
                    {"role": "system", "content": req.system},
                    {"role": "user", "content": req.user},
                ],
            });
            let resp = client
                .post("https://api.openai.com/v1/chat/completions")
                .bearer_auth(&self.api_key)
                .header("content-type", "application/json")
                .json(&body)
                .send()?;
            let status = resp.status();
            let parsed: Value = resp.json()?;
            if !status.is_success() {
                return Err(anyhow!("openai api error ({}): {}", status, parsed));
            }
            let text = parsed
                .get("choices")
                .and_then(Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(|c| c.get("message"))
                .and_then(|m| m.get("content"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            Ok(text)
        }
    }
}
