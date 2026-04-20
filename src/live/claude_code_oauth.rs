//! Claude Code OAuth quota source (`GET /api/oauth/usage`).
//!
//! Authoritative live quota data — 5h/7d windows, per-model sub-limits, and
//! pay-as-you-go overage state — sourced from the same endpoint Claude Code
//! itself queries for `/usage`. Strictly better than transcript-estimated spend
//! when the question is "where am I against Anthropic's rate limits right now?"
//!
//! Security: the bearer token lives in `~/.claude/.credentials.json` (mode
//! 0600). This module reads it, holds it in memory only for the request, and
//! never writes it to the cache file, error messages, or any Debug output.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";
pub const OAUTH_BETA_HEADER: &str = "oauth-2025-04-20";
pub const DEFAULT_CACHE_TTL_SECS: u64 = 60;

/// One window inside the usage payload (five_hour, seven_day, per-model …).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct QuotaWindow {
    pub utilization: f64,
    #[serde(default)]
    pub resets_at: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExtraUsage {
    #[serde(default)]
    pub is_enabled: bool,
    #[serde(default)]
    pub monthly_limit: Option<f64>,
    #[serde(default)]
    pub used_credits: Option<f64>,
    #[serde(default)]
    pub utilization: f64,
    #[serde(default)]
    pub currency: String,
}

/// Structured view of the `/api/oauth/usage` payload.
///
/// `raw` carries the parsed JSON so new fields surface in JSON output without
/// a recompile — the Anthropic endpoint has evolved (e.g. `iguana_necktie`,
/// `omelette_promotional`) and we do not want to drop unknown buckets.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct QuotaSnapshot {
    pub provider: String,
    pub fetched_at: String,
    pub cached: bool,
    pub cache_age_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_tier: Option<String>,
    pub five_hour: Option<QuotaWindow>,
    pub seven_day: Option<QuotaWindow>,
    pub seven_day_opus: Option<QuotaWindow>,
    pub seven_day_sonnet: Option<QuotaWindow>,
    pub seven_day_cowork: Option<QuotaWindow>,
    pub seven_day_oauth_apps: Option<QuotaWindow>,
    pub seven_day_omelette: Option<QuotaWindow>,
    pub extra_usage: Option<ExtraUsage>,
    pub raw: Value,
}

/// Credentials as stored by Claude Code. Only the fields we actually inspect
/// are modelled; the rest of the file (mcpOAuth etc.) is ignored on purpose.
///
/// Never log or serialise values of this type.
pub struct Credentials {
    pub access_token: String,
    pub expires_at_ms: Option<i64>,
    pub subscription_type: Option<String>,
    pub rate_limit_tier: Option<String>,
}

pub fn default_credentials_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not resolve HOME directory"))?;
    Ok(home.join(".claude").join(".credentials.json"))
}

pub fn default_cache_path() -> Result<PathBuf> {
    let cache = dirs::cache_dir()
        .ok_or_else(|| anyhow!("could not resolve user cache dir"))?;
    Ok(cache.join("sherlock").join("claude_code_oauth.json"))
}

/// Parse `~/.claude/.credentials.json`. The `accessToken` is required; every
/// other field is best-effort so format drift doesn't break us.
pub fn parse_credentials(raw: &str) -> Result<Credentials> {
    let v: Value = serde_json::from_str(raw).context("credentials.json is not valid JSON")?;
    let oauth = v
        .get("claudeAiOauth")
        .ok_or_else(|| anyhow!("credentials.json missing `claudeAiOauth` section"))?;
    let access_token = oauth
        .get("accessToken")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("credentials.json missing `claudeAiOauth.accessToken`"))?
        .to_string();
    let expires_at_ms = oauth.get("expiresAt").and_then(Value::as_i64);
    let subscription_type = oauth
        .get("subscriptionType")
        .and_then(Value::as_str)
        .map(str::to_string);
    let rate_limit_tier = oauth
        .get("rateLimitTier")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(Credentials {
        access_token,
        expires_at_ms,
        subscription_type,
        rate_limit_tier,
    })
}

pub fn load_credentials(path: &Path) -> Result<Credentials> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read credentials at {}", path.display()))?;
    parse_credentials(&raw)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `true` if `expires_at_ms` is in the past (with 30s slop so we refresh before
/// the endpoint returns 401 on us).
pub fn credentials_expired(expires_at_ms: Option<i64>) -> bool {
    match expires_at_ms {
        Some(exp) => exp - 30_000 <= now_ms(),
        None => false,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedPayload {
    fetched_at_secs: u64,
    fetched_at_iso: String,
    payload: Value,
}

pub fn read_cache(path: &Path, ttl_secs: u64) -> Option<(Value, String, u64)> {
    let raw = fs::read_to_string(path).ok()?;
    let cached: CachedPayload = serde_json::from_str(&raw).ok()?;
    if ttl_secs == 0 {
        return None;
    }
    let age = now_secs().saturating_sub(cached.fetched_at_secs);
    if age >= ttl_secs {
        return None;
    }
    Some((cached.payload, cached.fetched_at_iso, age))
}

pub fn write_cache(path: &Path, payload: &Value, fetched_at_iso: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    let cached = CachedPayload {
        fetched_at_secs: now_secs(),
        fetched_at_iso: fetched_at_iso.to_string(),
        payload: payload.clone(),
    };
    let raw = serde_json::to_string_pretty(&cached)?;
    fs::write(path, raw).with_context(|| format!("write cache {}", path.display()))?;
    // Tighten perms: user's quota state shouldn't be world-readable, even
    // though the access token itself never lands here.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn parse_window(v: Option<&Value>) -> Option<QuotaWindow> {
    let v = v?;
    if v.is_null() {
        return None;
    }
    serde_json::from_value(v.clone()).ok()
}

fn parse_extra(v: Option<&Value>) -> Option<ExtraUsage> {
    let v = v?;
    if v.is_null() {
        return None;
    }
    serde_json::from_value(v.clone()).ok()
}

pub fn snapshot_from_payload(
    payload: Value,
    fetched_at_iso: String,
    cached: bool,
    cache_age_secs: Option<u64>,
    plan: Option<&Credentials>,
) -> QuotaSnapshot {
    let five_hour = parse_window(payload.get("five_hour"));
    let seven_day = parse_window(payload.get("seven_day"));
    let seven_day_opus = parse_window(payload.get("seven_day_opus"));
    let seven_day_sonnet = parse_window(payload.get("seven_day_sonnet"));
    let seven_day_cowork = parse_window(payload.get("seven_day_cowork"));
    let seven_day_oauth_apps = parse_window(payload.get("seven_day_oauth_apps"));
    let seven_day_omelette = parse_window(payload.get("seven_day_omelette"));
    let extra_usage = parse_extra(payload.get("extra_usage"));
    QuotaSnapshot {
        provider: "claude-code".to_string(),
        fetched_at: fetched_at_iso,
        cached,
        cache_age_secs,
        subscription_type: plan.and_then(|c| c.subscription_type.clone()),
        rate_limit_tier: plan.and_then(|c| c.rate_limit_tier.clone()),
        five_hour,
        seven_day,
        seven_day_opus,
        seven_day_sonnet,
        seven_day_cowork,
        seven_day_oauth_apps,
        seven_day_omelette,
        extra_usage,
        raw: payload,
    }
}

pub struct FetchOptions {
    pub credentials_path: PathBuf,
    pub cache_path: PathBuf,
    pub cache_ttl_secs: u64,
    pub use_cache: bool,
}

impl FetchOptions {
    pub fn defaults() -> Result<Self> {
        Ok(Self {
            credentials_path: default_credentials_path()?,
            cache_path: default_cache_path()?,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            use_cache: true,
        })
    }
}

/// Fetch a live quota snapshot. Reads the cache first if `use_cache`, then
/// falls back to the live endpoint using the short-lived OAuth token on disk.
///
/// On HTTP 401 the caller should let Claude Code refresh the credentials file
/// (running `claude` once is the easiest path) — Sherlock does not touch the
/// token refresh endpoint because the embedded `client_id` is not reliably
/// extractable from the CLI bundle (see docs/claude-code-oauth-usage.md).
pub fn fetch_quota(opts: &FetchOptions) -> Result<QuotaSnapshot> {
    // Load credentials eagerly — `subscription_type` / `rate_limit_tier`
    // decorate the snapshot even on a cache hit. Failure here is non-fatal
    // when the cache is usable; we fall back to plan-less output.
    let creds = load_credentials(&opts.credentials_path).ok();

    if opts.use_cache {
        if let Some((payload, fetched_at, age)) = read_cache(&opts.cache_path, opts.cache_ttl_secs) {
            return Ok(snapshot_from_payload(
                payload,
                fetched_at,
                true,
                Some(age),
                creds.as_ref(),
            ));
        }
    }

    let creds = creds.ok_or_else(|| {
        anyhow!(
            "read credentials at {}: file missing or unreadable",
            opts.credentials_path.display()
        )
    })?;
    if credentials_expired(creds.expires_at_ms) {
        return Err(anyhow!(
            "Claude Code OAuth token in {} is expired; run `claude` once to refresh it, then retry.",
            opts.credentials_path.display()
        ));
    }

    let payload = http_fetch(&creds.access_token)?;
    let fetched_at = iso_utc_now();
    // Best-effort cache write — a read-only cache dir shouldn't fail the call.
    let _ = write_cache(&opts.cache_path, &payload, &fetched_at);
    Ok(snapshot_from_payload(
        payload,
        fetched_at,
        false,
        None,
        Some(&creds),
    ))
}

fn iso_utc_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(feature = "live")]
fn http_fetch(access_token: &str) -> Result<Value> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let resp = client
        .get(USAGE_URL)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("anthropic-beta", OAUTH_BETA_HEADER)
        .send()?;
    let status = resp.status();
    if status.as_u16() == 401 {
        return Err(anyhow!(
            "401 Unauthorized from {} — OAuth token is invalid or expired. \
             Run `claude` once to refresh ~/.claude/.credentials.json and retry.",
            USAGE_URL
        ));
    }
    if !status.is_success() {
        // Surface status only; body may echo request headers in some edge
        // cases — never propagate it raw because that could leak the token.
        let body_len = resp
            .text()
            .map(|s| s.len())
            .unwrap_or(0);
        return Err(anyhow!(
            "quota API returned HTTP {} ({} bytes); redacted to avoid leaking auth headers",
            status,
            body_len
        ));
    }
    let payload: Value = resp.json()?;
    Ok(payload)
}

#[cfg(not(feature = "live"))]
fn http_fetch(_access_token: &str) -> Result<Value> {
    Err(anyhow!(
        "sherlock was built without the `live` feature; enable it to call /api/oauth/usage"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SAMPLE: &str = r#"{
        "five_hour":        {"utilization": 11.0, "resets_at": "2026-04-20T06:59:59+00:00"},
        "seven_day":        {"utilization": 60.0, "resets_at": "2026-04-23T19:00:00+00:00"},
        "seven_day_opus":   null,
        "seven_day_sonnet": {"utilization": 11.0, "resets_at": "2026-04-23T19:00:00+00:00"},
        "seven_day_cowork": null,
        "seven_day_omelette":    {"utilization": 0.0, "resets_at": null},
        "seven_day_oauth_apps":  null,
        "iguana_necktie":        null,
        "omelette_promotional":  null,
        "extra_usage": {
            "is_enabled":     true,
            "monthly_limit":  2000,
            "used_credits":   2264.0,
            "utilization":    100.0,
            "currency":       "USD"
        }
    }"#;

    #[test]
    fn parses_sample_payload_into_windows() {
        let payload: Value = serde_json::from_str(SAMPLE).unwrap();
        let snap = snapshot_from_payload(payload, "2026-04-20T00:00:00Z".into(), false, None, None);
        assert_eq!(snap.provider, "claude-code");
        assert_eq!(snap.five_hour.as_ref().unwrap().utilization, 11.0);
        assert_eq!(
            snap.seven_day.as_ref().unwrap().resets_at.as_deref(),
            Some("2026-04-23T19:00:00+00:00")
        );
        // `seven_day_opus: null` must map to None, not a zeroed window.
        assert!(snap.seven_day_opus.is_none());
        assert_eq!(snap.seven_day_sonnet.as_ref().unwrap().utilization, 11.0);
        let extra = snap.extra_usage.as_ref().unwrap();
        assert!(extra.is_enabled);
        assert_eq!(extra.used_credits, Some(2264.0));
        assert_eq!(extra.currency, "USD");
        // Unknown buckets must survive through `raw` so JSON output keeps them.
        assert!(snap.raw.get("iguana_necktie").is_some());
    }

    #[test]
    fn parse_credentials_extracts_access_token_and_expiry() {
        let raw = r#"{
            "claudeAiOauth": {
                "accessToken": "SECRET_TOKEN_DO_NOT_LOG",
                "refreshToken": "SECRET_REFRESH",
                "expiresAt": 1776664254430,
                "subscriptionType": "max",
                "rateLimitTier": "default_claude_max_5x"
            }
        }"#;
        let creds = parse_credentials(raw).unwrap();
        assert_eq!(creds.access_token, "SECRET_TOKEN_DO_NOT_LOG");
        assert_eq!(creds.expires_at_ms, Some(1776664254430));
        assert_eq!(creds.subscription_type.as_deref(), Some("max"));
        assert_eq!(creds.rate_limit_tier.as_deref(), Some("default_claude_max_5x"));
    }

    #[test]
    fn parse_credentials_rejects_missing_token() {
        let raw = r#"{"claudeAiOauth": {"expiresAt": 123}}"#;
        match parse_credentials(raw) {
            Ok(_) => panic!("expected error for missing accessToken"),
            Err(e) => assert!(e.to_string().contains("accessToken"), "got: {e}"),
        }
    }

    #[test]
    fn credentials_expired_flags_past_timestamps() {
        assert!(!credentials_expired(None));
        assert!(!credentials_expired(Some(now_ms() + 5 * 60 * 1000)));
        assert!(credentials_expired(Some(now_ms() - 1_000)));
    }

    #[test]
    fn cache_roundtrip_honours_ttl() {
        let dir = std::env::temp_dir().join(format!(
            "sherlock-oauth-cache-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.json");
        let payload = json!({"five_hour": {"utilization": 5.0}});
        write_cache(&path, &payload, "2026-04-20T00:00:00Z").unwrap();
        let (got, iso, age) = read_cache(&path, 120).expect("cache hit");
        assert_eq!(got, payload);
        assert_eq!(iso, "2026-04-20T00:00:00Z");
        assert!(age <= 5, "fresh cache should be near-zero age, got {age}");
        // ttl=0 forces a miss even on a fresh file.
        assert!(read_cache(&path, 0).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cache_never_contains_access_token() {
        let dir = std::env::temp_dir().join(format!(
            "sherlock-oauth-cache-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.json");
        let payload = json!({"five_hour": {"utilization": 1.0}});
        write_cache(&path, &payload, "2026-04-20T00:00:00Z").unwrap();
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.to_lowercase().contains("accesstoken"));
        assert!(!on_disk.contains("Bearer"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
