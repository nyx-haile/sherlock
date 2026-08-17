//! Anthropic list prices, in USD per million tokens.
//!
//! These are the first-party Claude API rates. Cache pricing is derived from
//! the base input rate rather than published separately: a 5-minute-TTL cache
//! write costs 1.25x base input, and a cache read costs 0.1x. The 1-hour TTL
//! write (2x) is not modelled — transcripts do not record which TTL was used,
//! and 5m is the default, so estimates skew low on 1h-cached workloads.
//!
//! Deliberately *list* prices: a reconciliation against OAuth utilization is a
//! sanity check on volume, not an invoice. Subscription plans, negotiated
//! rates, and Bedrock/Vertex pricing all differ, which is one of the reasons
//! `reconcile` refuses to invent a ratio without an explicit budget.

/// Per-million-token rates for one model.
#[derive(Clone, Copy, Debug)]
pub struct ModelRates {
    /// Model id prefix this row prices (see [`rates_for`] for match rules).
    pub id: &'static str,
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
    pub cache_write_per_mtok: f64,
    pub cache_read_per_mtok: f64,
}

const fn rates(
    id: &'static str,
    input_per_mtok: f64,
    output_per_mtok: f64,
    cache_write_per_mtok: f64,
    cache_read_per_mtok: f64,
) -> ModelRates {
    ModelRates {
        id,
        input_per_mtok,
        output_per_mtok,
        cache_write_per_mtok,
        cache_read_per_mtok,
    }
}

/// Known models, most specific id first so [`rates_for`] can prefix-match.
pub const RATES: &[ModelRates] = &[
    // Fable / Mythos tier — $10 / $50.
    rates("claude-fable-5", 10.0, 50.0, 12.50, 1.00),
    rates("claude-mythos-5", 10.0, 50.0, 12.50, 1.00),
    // Opus tier — $5 / $25.
    rates("claude-opus-5", 5.0, 25.0, 6.25, 0.50),
    rates("claude-opus-4-8", 5.0, 25.0, 6.25, 0.50),
    rates("claude-opus-4-7", 5.0, 25.0, 6.25, 0.50),
    rates("claude-opus-4-6", 5.0, 25.0, 6.25, 0.50),
    // Sonnet tier — $3 / $15.
    rates("claude-sonnet-5", 3.0, 15.0, 3.75, 0.30),
    rates("claude-sonnet-4-6", 3.0, 15.0, 3.75, 0.30),
    // Haiku tier — $1 / $5.
    rates("claude-haiku-4-5", 1.0, 5.0, 1.25, 0.10),
];

/// Look up rates for a model id recorded in a transcript.
///
/// Transcripts carry ids in several shapes — bare (`claude-opus-4-6`), date
/// suffixed (`claude-haiku-4-5-20251001`), or provider prefixed
/// (`anthropic.claude-opus-5` on Bedrock) — so this matches on the longest
/// known id contained in the string rather than requiring equality. Unknown
/// models return `None`; callers must surface those rather than pricing them
/// at zero.
pub fn rates_for(model: &str) -> Option<&'static ModelRates> {
    let needle = model.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return None;
    }
    let mut best: Option<&'static ModelRates> = None;
    for row in RATES {
        if !needle.contains(row.id) {
            continue;
        }
        match best {
            Some(current) if current.id.len() >= row.id.len() => {}
            _ => best = Some(row),
        }
    }
    best
}

/// Cost in USD for one bucket of token counts on `model`.
///
/// Returns `None` for an unknown model so the caller can report it as
/// unpriced instead of silently under-counting the total.
pub fn cost_usd(
    model: &str,
    input_tokens: i64,
    output_tokens: i64,
    cache_read_tokens: i64,
    cache_write_tokens: i64,
) -> Option<f64> {
    let r = rates_for(model)?;
    let per = |tokens: i64, rate: f64| (tokens.max(0) as f64) * rate / 1_000_000.0;
    Some(
        per(input_tokens, r.input_per_mtok)
            + per(output_tokens, r.output_per_mtok)
            + per(cache_read_tokens, r.cache_read_per_mtok)
            + per(cache_write_tokens, r.cache_write_per_mtok),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_for_matches_bare_dated_and_prefixed_ids() {
        assert_eq!(
            rates_for("claude-opus-4-6").map(|r| r.id),
            Some("claude-opus-4-6")
        );
        assert_eq!(
            rates_for("claude-haiku-4-5-20251001").map(|r| r.id),
            Some("claude-haiku-4-5")
        );
        assert_eq!(
            rates_for("anthropic.claude-opus-5").map(|r| r.id),
            Some("claude-opus-5")
        );
        // Longest match wins: "claude-opus-4-8" must not fall back to a
        // shorter id that also happens to be a substring.
        assert_eq!(
            rates_for("claude-opus-4-8").map(|r| r.id),
            Some("claude-opus-4-8")
        );
        assert!(rates_for("gpt-4o").is_none());
        assert!(rates_for("").is_none());
    }

    #[test]
    fn cost_usd_prices_each_token_bucket_separately() {
        // 1M input + 1M output + 1M cache read + 1M cache write on Sonnet 5:
        // 3.00 + 15.00 + 0.30 + 3.75.
        let cost = cost_usd(
            "claude-sonnet-5",
            1_000_000,
            1_000_000,
            1_000_000,
            1_000_000,
        )
        .expect("known model");
        assert!((cost - 22.05).abs() < 1e-9, "got {cost}");
        assert_eq!(cost_usd("claude-sonnet-5", 0, 0, 0, 0), Some(0.0));
        assert!(cost_usd("not-a-model", 1, 1, 1, 1).is_none());
    }
}
