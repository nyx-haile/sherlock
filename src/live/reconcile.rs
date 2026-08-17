//! Cross-check the live OAuth 7-day utilization against transcript-derived
//! token spend (sherlock-h4u).
//!
//! # What the two sides actually are
//!
//! * `QuotaSnapshot.seven_day.utilization` is a **percentage of an opaque
//!   rate-limit allowance** for the authenticated account, over a rolling
//!   7-day window. Anthropic does not publish the allowance in any unit we
//!   can convert from.
//! * The transcript side is **USD of list-price token spend**, summed from
//!   the JSONL files Sherlock can see on this machine.
//!
//! There is no shared identifier between them — no session id, no request id,
//! no account id on the transcript side. **The only join key is the window
//! itself**: both describe "this account, these last 7 days". That is a real
//! join, but a coarse one, and it is why this module reports the two numbers
//! side by side and refuses to derive a ratio unless the operator supplies
//! their plan's 7-day budget via `--plan-budget-usd`. Turning a percentage
//! into dollars without that input would be inventing the denominator.
//!
//! Every structural reason the two can legitimately disagree is emitted as a
//! caveat rather than left for the reader to infer.

use crate::pricing;
use crate::providers::{Provider, RawEvent};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Token totals and list-price cost for one model.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ModelSpend {
    pub model: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_write_tokens: i64,
    /// `None` when the model has no entry in [`crate::pricing::RATES`].
    pub estimated_cost_usd: Option<f64>,
}

/// Transcript-side estimate over a window.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TranscriptEstimate {
    pub since: String,
    pub files_scanned: usize,
    pub files_unreadable: usize,
    pub events_counted: usize,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_write_tokens: i64,
    pub total_tokens: i64,
    /// Sum over priced models only.
    pub estimated_cost_usd: f64,
    /// Models seen in the transcripts with no rate table entry. Their tokens
    /// are counted but contribute nothing to `estimated_cost_usd`.
    pub unpriced_models: Vec<String>,
    pub per_model: Vec<ModelSpend>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct OauthSide {
    pub seven_day_utilization_pct: Option<f64>,
    pub resets_at: Option<String>,
    pub cached: bool,
    pub subscription_type: Option<String>,
}

/// The side-by-side comparison. Every USD-denominated field stays `None`
/// unless the operator supplied `--plan-budget-usd`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Comparison {
    pub plan_budget_usd: Option<f64>,
    /// utilization% x plan budget — what OAuth implies was spent.
    pub oauth_implied_usd: Option<f64>,
    /// transcripts - oauth_implied.
    pub delta_usd: Option<f64>,
    /// delta as a percentage of `oauth_implied_usd`.
    pub delta_pct: Option<f64>,
    /// `aligned` | `transcripts-under` | `transcripts-over` | `not-comparable`.
    pub verdict: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Reconciliation {
    pub generated_at: String,
    pub provider: String,
    pub window: String,
    pub oauth: OauthSide,
    pub transcripts: TranscriptEstimate,
    pub comparison: Comparison,
    pub caveats: Vec<String>,
}

/// Flag divergence beyond this fraction of the OAuth-implied figure.
const DIVERGENCE_THRESHOLD_PCT: f64 = 25.0;

/// Sum token usage and list-price cost across `files`, counting only events at
/// or after `since_epoch`.
///
/// Per-file read errors are counted (`files_unreadable`) rather than aborting:
/// a projects directory routinely contains files this process cannot read, and
/// a partial estimate with a stated gap beats no estimate at all.
pub fn estimate_since(
    provider: &dyn Provider,
    files: &[PathBuf],
    since_epoch: i64,
    since_label: &str,
) -> Result<TranscriptEstimate> {
    let mut est = TranscriptEstimate {
        since: since_label.to_string(),
        files_scanned: files.len(),
        ..TranscriptEstimate::default()
    };
    let mut by_model: HashMap<String, ModelSpend> = HashMap::new();

    for path in files {
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(_) => {
                est.files_unreadable += 1;
                continue;
            }
        };
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let obj: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let ev = RawEvent::Json(obj);
            // Events with no parseable timestamp are dropped rather than
            // assumed in-window: including them would silently inflate the
            // estimate on transcripts that predate the window.
            let ts = match provider
                .event_time_value(&ev)
                .and_then(|s| crate::parse_ts_epoch(&s))
            {
                Some(ts) => ts,
                None => continue,
            };
            if ts < since_epoch {
                continue;
            }
            let usage = provider.extract_usage(&ev);
            let input = usage.input_tokens.unwrap_or(0);
            let output = usage.output_tokens.unwrap_or(0);
            let cache_read = usage.cache_read_tokens.unwrap_or(0);
            let cache_write = usage.cache_write_tokens.unwrap_or(0);
            if input == 0 && output == 0 && cache_read == 0 && cache_write == 0 {
                continue;
            }
            est.events_counted += 1;
            est.input_tokens += input;
            est.output_tokens += output;
            est.cache_read_tokens += cache_read;
            est.cache_write_tokens += cache_write;

            let model = provider
                .extract_model(&ev)
                .unwrap_or_else(|| "unknown".to_string());
            let entry = by_model.entry(model.clone()).or_insert_with(|| ModelSpend {
                model,
                ..ModelSpend::default()
            });
            entry.input_tokens += input;
            entry.output_tokens += output;
            entry.cache_read_tokens += cache_read;
            entry.cache_write_tokens += cache_write;
        }
    }

    est.total_tokens =
        est.input_tokens + est.output_tokens + est.cache_read_tokens + est.cache_write_tokens;

    let mut per_model: Vec<ModelSpend> = by_model.into_values().collect();
    for spend in &mut per_model {
        spend.estimated_cost_usd = pricing::cost_usd(
            &spend.model,
            spend.input_tokens,
            spend.output_tokens,
            spend.cache_read_tokens,
            spend.cache_write_tokens,
        );
        match spend.estimated_cost_usd {
            Some(cost) => est.estimated_cost_usd += cost,
            None => est.unpriced_models.push(spend.model.clone()),
        }
    }
    per_model.sort_by(|a, b| {
        b.estimated_cost_usd
            .unwrap_or(0.0)
            .partial_cmp(&a.estimated_cost_usd.unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.model.cmp(&b.model))
    });
    est.unpriced_models.sort();
    est.unpriced_models.dedup();
    est.per_model = per_model;
    Ok(est)
}

/// Join the live OAuth snapshot and the transcript estimate on the shared
/// 7-day window.
///
/// Without `plan_budget_usd` the comparison stays deliberately incomplete —
/// `verdict` is `not-comparable` and both raw figures are reported unchanged.
pub fn reconcile(
    snapshot: &crate::live::claude_code_oauth::QuotaSnapshot,
    transcripts: TranscriptEstimate,
    plan_budget_usd: Option<f64>,
    generated_at: String,
) -> Reconciliation {
    let seven_day = snapshot.seven_day.as_ref();
    let oauth = OauthSide {
        seven_day_utilization_pct: seven_day.map(|w| w.utilization),
        resets_at: seven_day.and_then(|w| w.resets_at.clone()),
        cached: snapshot.cached,
        subscription_type: snapshot.subscription_type.clone(),
    };

    let mut caveats = vec![
        "OAuth utilization is a share of an opaque rate-limit allowance; the transcript figure is list-price USD. They share only the 7-day window, not a common key.".to_string(),
        "Transcripts cover only history files on this machine — usage from other machines, the web app, or other surfaces is invisible here.".to_string(),
        "List prices ignore subscription plans and negotiated rates, so the USD figure is a volume sanity check, not an invoice.".to_string(),
        "Cache writes are priced at the 5-minute-TTL rate; 1-hour-TTL writes cost more and are under-counted.".to_string(),
    ];
    if oauth.cached {
        caveats.push(
            "OAuth snapshot came from the local cache — re-run with --no-cache for a live read."
                .to_string(),
        );
    }
    if transcripts.files_unreadable > 0 {
        caveats.push(format!(
            "{} transcript file(s) could not be read and are missing from the estimate.",
            transcripts.files_unreadable
        ));
    }
    if !transcripts.unpriced_models.is_empty() {
        caveats.push(format!(
            "No list price for {} — their tokens are counted but contribute $0 to the estimate.",
            transcripts.unpriced_models.join(", ")
        ));
    }

    let comparison = match (plan_budget_usd, oauth.seven_day_utilization_pct) {
        (Some(budget), Some(util)) if budget > 0.0 => {
            let implied = budget * util / 100.0;
            let delta = transcripts.estimated_cost_usd - implied;
            let delta_pct = if implied > 0.0 {
                Some(delta / implied * 100.0)
            } else {
                None
            };
            let verdict = match delta_pct {
                Some(pct) if pct.abs() <= DIVERGENCE_THRESHOLD_PCT => "aligned",
                Some(pct) if pct < 0.0 => "transcripts-under",
                Some(_) => "transcripts-over",
                None => "not-comparable",
            };
            let note = match verdict {
                "aligned" => format!(
                    "Transcript spend is within {DIVERGENCE_THRESHOLD_PCT:.0}% of the OAuth-implied figure."
                ),
                "transcripts-under" => "Transcripts account for less spend than OAuth reports — expect usage from surfaces Sherlock cannot see, or an un-ingested machine.".to_string(),
                "transcripts-over" => "Transcripts account for more spend than OAuth reports — check the plan budget, and whether transcripts outside the window are being counted.".to_string(),
                _ => "Cannot compare.".to_string(),
            };
            Comparison {
                plan_budget_usd: Some(budget),
                oauth_implied_usd: Some(implied),
                delta_usd: Some(delta),
                delta_pct,
                verdict: verdict.to_string(),
                note,
            }
        }
        (_, None) => Comparison {
            verdict: "not-comparable".to_string(),
            note: "The OAuth snapshot carries no seven_day window.".to_string(),
            ..Comparison::default()
        },
        _ => Comparison {
            verdict: "not-comparable".to_string(),
            note: "No --plan-budget-usd given, so the two figures are reported raw. Converting a rate-limit percentage into dollars needs a budget Sherlock cannot know.".to_string(),
            ..Comparison::default()
        },
    };

    Reconciliation {
        generated_at,
        provider: snapshot.provider.clone(),
        window: "7d".to_string(),
        oauth,
        transcripts,
        comparison,
        caveats,
    }
}

/// Every Claude Code transcript under `projects_root` touched at or after
/// `since_epoch`, across all project directories.
///
/// Account-wide by design: the OAuth quota is per account, so restricting the
/// transcript side to one project would guarantee a mismatch.
pub fn history_files_since(projects_root: &Path, since_epoch: i64) -> Result<Vec<PathBuf>> {
    let entries = std::fs::read_dir(projects_root)
        .with_context(|| format!("read projects root {}", projects_root.display()))?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let files = match std::fs::read_dir(&dir) {
            Ok(files) => files,
            Err(_) => continue,
        };
        for file in files.flatten() {
            let path = file.path();
            if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
                continue;
            }
            let mtime = std::fs::metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if mtime >= since_epoch {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}
