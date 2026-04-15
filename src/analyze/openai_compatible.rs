use super::{ChatBackend, ReviewRequest};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};

pub struct OpenAICompatibleBackend {
    model: String,
    base_url: String,
    api_key: Option<String>,
}

impl OpenAICompatibleBackend {
    pub fn new(model: String, base_url: String, api_key_env: Option<String>) -> Result<Self> {
        let api_key = match api_key_env {
            Some(var) => Some(
                std::env::var(&var)
                    .map_err(|_| anyhow!("env var {var} is not set"))?,
            ),
            None => std::env::var("OPENAI_COMPATIBLE_API_KEY").ok(),
        };
        Ok(Self {
            model,
            base_url,
            api_key,
        })
    }
}

impl ChatBackend for OpenAICompatibleBackend {
    fn id(&self) -> &'static str {
        "openai-compatible"
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
                .timeout(std::time::Duration::from_secs(180))
                .build()?;
            let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
            let body = json!({
                "model": self.model,
                "messages": [
                    {"role": "system", "content": req.system},
                    {"role": "user", "content": req.user},
                ],
            });
            let mut req_builder = client
                .post(&url)
                .header("content-type", "application/json")
                .json(&body);
            if let Some(key) = &self.api_key {
                req_builder = req_builder.bearer_auth(key);
            }
            let resp = req_builder.send()?;
            let status = resp.status();
            let parsed: Value = resp.json()?;
            if !status.is_success() {
                return Err(anyhow!(
                    "openai-compatible api error ({}) at {}: {}",
                    status,
                    url,
                    parsed
                ));
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
