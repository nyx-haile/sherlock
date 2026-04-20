mod analyze;
mod install_skill;
mod live;
mod providers;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use providers::{Provider, RawEvent};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::{stdout, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use uuid::Uuid;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    started_at TEXT,
    ended_at TEXT,
    project_root TEXT,
    branch TEXT,
    model_family TEXT,
    provider VARCHAR(32) NOT NULL DEFAULT 'claude-code'
);

CREATE TABLE IF NOT EXISTS session_aliases (
    alias VARCHAR(128) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id VARCHAR(64) PRIMARY KEY,
    captured_at TEXT NOT NULL,
    settings_hash TEXT,
    mcp_hash TEXT,
    enabled_plugins_hash TEXT
);

CREATE TABLE IF NOT EXISTS turns (
    turn_id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    turn_index INTEGER NOT NULL,
    started_at TEXT,
    ended_at TEXT,
    input_tokens_cum INTEGER,
    output_tokens_cum INTEGER,
    cache_read_tokens_cum INTEGER,
    cache_write_tokens_cum INTEGER,
    cost_cum_usd REAL
);

CREATE TABLE IF NOT EXISTS sources (
    source_id VARCHAR(64) PRIMARY KEY,
    source_kind VARCHAR(32) NOT NULL,
    plugin_id VARCHAR(128),
    hook_name VARCHAR(128),
    mcp_server_name VARCHAR(128),
    tool_name VARCHAR(128),
    fingerprint VARCHAR(512) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS events (
    event_id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    turn_id VARCHAR(64),
    event_time VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    source_id VARCHAR(64),
    payload_bytes INTEGER,
    raw_ref VARCHAR(255),
    provider VARCHAR(32) NOT NULL DEFAULT 'claude-code'
);

CREATE TABLE IF NOT EXISTS windows (
    window_id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    start_time VARCHAR(64) NOT NULL,
    end_time VARCHAR(64) NOT NULL,
    reason VARCHAR(32) NOT NULL,
    delta_tokens INTEGER,
    delta_cost_usd REAL
);

CREATE TABLE IF NOT EXISTS attributions (
    attribution_id VARCHAR(64) PRIMARY KEY,
    window_id VARCHAR(64) NOT NULL,
    source_id VARCHAR(64) NOT NULL,
    score REAL NOT NULL,
    confidence VARCHAR(16) NOT NULL,
    estimated_tokens INTEGER,
    evidence_json VARCHAR(2048)
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    artifact_type VARCHAR(64) NOT NULL,
    path_or_key VARCHAR(1024) NOT NULL,
    sha256 VARCHAR(128),
    captured_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS beads_context (
    beads_ctx_id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    issue_id VARCHAR(64),
    status VARCHAR(32),
    priority INTEGER,
    note_excerpt VARCHAR(1024),
    captured_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_session_time ON events(session_id, event_time);
CREATE INDEX IF NOT EXISTS idx_turns_session_index ON turns(session_id, turn_index);
CREATE INDEX IF NOT EXISTS idx_windows_session_time ON windows(session_id, start_time, end_time);
CREATE INDEX IF NOT EXISTS idx_attributions_window_score ON attributions(window_id, score DESC);
CREATE INDEX IF NOT EXISTS idx_sources_fingerprint ON sources(fingerprint);
CREATE INDEX IF NOT EXISTS idx_session_aliases_session ON session_aliases(session_id);
"#;

// Columns added after initial schema. Applied idempotently on every store open
// via an information_schema probe — Dolt (1.86) does not support
// `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, so we check-then-add.
const ADDED_COLUMNS: &[(&str, &str, &str)] = &[
    ("sessions", "provider", "VARCHAR(32) NOT NULL DEFAULT 'claude-code'"),
    ("events", "provider", "VARCHAR(32) NOT NULL DEFAULT 'claude-code'"),
];

#[derive(Parser)]
#[command(name = "sherlock")]
#[command(about = "Sherlock token-usage forensic tool (Rust runtime)")]
struct Cli {
    #[arg(long, default_value_os_t = default_repo())]
    repo: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Init {
        #[arg(long, default_value_t = false)]
        commit: bool,
    },
    Ingest {
        #[arg(long)]
        history: Option<PathBuf>,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long, default_value_os_t = std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))]
        project_root: PathBuf,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long, default_value = "")]
        model_family: String,
        /// Provider id (claude-code, codex, copilot-cli, copilot-vscode, antigravity, cursor). Auto-detected if omitted.
        #[arg(long)]
        provider: Option<String>,
        /// Acknowledge that the cursor adapter is experimental.
        #[arg(long, default_value_t = false)]
        experimental_cursor: bool,
        #[arg(long, default_value_t = false)]
        commit: bool,
    },
    Report {
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
        /// Warn if any single plugin exceeds this fraction of session spend (0.0–1.0).
        #[arg(long)]
        warn_plugin_share: Option<f64>,
        /// Warn if any single plugin exceeds this absolute token count.
        #[arg(long)]
        warn_plugin_tokens: Option<i64>,
        /// Exit with code 1 if any warn threshold is breached.
        #[arg(long, default_value_t = false)]
        exit_code_on_warn: bool,
    },
    Tui {
        #[arg(long)]
        session_id: Option<String>,
    },
    /// List all session aliases
    ListAliases,
    /// Set or update an alias for a session
    SetAlias {
        /// Human-friendly alias name
        alias: String,
        /// Session ID to alias
        session_id: String,
    },
    /// Remove an alias
    RemoveAlias {
        /// Alias to remove
        alias: String,
    },
    /// Produce an LLM-narrated analysis of one or more session reports.
    Analyze {
        /// Session id(s) to analyze. Pass multiple for comparison mode.
        #[arg(long, num_args = 1..)]
        session_id: Vec<String>,
        /// Backend: anthropic, openai, gemini, openai-compatible, prompt-only. Auto-detected from env if omitted.
        #[arg(long)]
        backend: Option<String>,
        /// Model id. Backend-specific default if omitted.
        #[arg(long)]
        model: Option<String>,
        /// Base URL for openai-compatible backends (Ollama, LM Studio, Together, DeepSeek, Groq).
        #[arg(long)]
        base_url: Option<String>,
        /// Env var name holding the API key. Defaults per backend.
        #[arg(long)]
        api_key_env: Option<String>,
    },
    /// Cross-session rollup — top plugins/tools by total spend across all ingested sessions.
    Rollup {
        /// Group by: plugin, tool, provider. Default: plugin.
        #[arg(long, default_value = "plugin")]
        group_by: String,
        /// Only include sessions ingested after this date (ISO 8601, e.g. 2026-04-01).
        #[arg(long)]
        since: Option<String>,
        /// Filter to a specific provider (claude-code, codex, copilot-cli, …).
        #[arg(long)]
        provider: Option<String>,
        /// Number of rows to return.
        #[arg(long, default_value_t = 20)]
        top: usize,
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
    },
    /// One-command multi-repo Claude Code usage report: discover modified repos,
    /// ingest their Claude Code history in a time window, render per-repo totals.
    Headline {
        /// Roots to scan for modified git repos (comma-separated). Defaults to cwd.
        #[arg(long, value_delimiter = ',')]
        roots: Vec<PathBuf>,
        /// Only include repos with git activity since this date
        /// (ISO 8601, `Nd`/`Nw`/`Nh`, `today`/`yesterday`, weekday name).
        #[arg(long, default_value = "7d")]
        modified_since: String,
        /// Only include usage since this date. Defaults to --modified-since.
        #[arg(long)]
        window_since: Option<String>,
        /// Provider id (default: claude-code).
        #[arg(long, default_value = "claude-code")]
        provider: String,
        /// Top N sources per repo.
        #[arg(long, default_value_t = 5)]
        top: usize,
        /// Skip ingest of newly discovered history files.
        #[arg(long, default_value_t = false)]
        skip_ingest: bool,
        /// Commit new ingests to the Dolt repo.
        #[arg(long, default_value_t = false)]
        commit: bool,
        #[arg(long, value_enum, default_value_t = ReportFormat::Markdown)]
        format: ReportFormat,
    },
    /// Live Claude Code quota snapshot via `GET /api/oauth/usage` — the
    /// authoritative data surfaced by Claude Code's `/usage`. Reads
    /// `~/.claude/.credentials.json`, caches the response for 60s.
    Quota {
        /// Source. Only `claude-code` is wired up today.
        #[arg(long, default_value = "claude-code")]
        provider: String,
        #[arg(long, value_enum, default_value_t = ReportFormat::Text)]
        format: ReportFormat,
        /// Bypass the 60s cache and hit the API every time.
        #[arg(long, default_value_t = false)]
        no_cache: bool,
        /// Override credentials path (default: ~/.claude/.credentials.json).
        #[arg(long)]
        credentials: Option<PathBuf>,
        /// Override cache TTL in seconds.
        #[arg(long, default_value_t = 60)]
        cache_ttl: u64,
    },
    /// Install the bundled Claude Code skill into ~/.claude/skills.
    InstallSkill {
        /// Destination directory (default: ~/.claude/skills/sherlock-analyze)
        #[arg(long)]
        dest: Option<PathBuf>,
        /// Overwrite existing files.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum ReportFormat {
    Json,
    Markdown,
    Text,
}

#[derive(Serialize)]
struct IngestSummary {
    ok: bool,
    session_id: String,
    events: usize,
    turns: usize,
    sources: usize,
    windows: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
struct SessionTotals {
    input_tokens: i64,
    output_tokens: i64,
    cache_read_tokens: i64,
    cache_write_tokens: i64,
    total_tokens: i64,
    cache_read_pct: f64,
    cache_write_pct: f64,
}

#[derive(Clone, Debug, Default, Serialize)]
struct PromptExcerpt {
    timestamp: String,
    prompt_kind: String,
    chars: usize,
    excerpt: String,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ContinuationSummaryStats {
    count: usize,
    total_chars: usize,
    average_chars: f64,
    max_chars: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
struct PromptStats {
    prompt_count: usize,
    total_prompt_chars: usize,
    average_prompt_chars: f64,
    longest_prompts: Vec<PromptExcerpt>,
    continuation_summaries: ContinuationSummaryStats,
}

#[derive(Clone, Debug, Default, Serialize)]
struct SourceFact {
    source_id: String,
    source_kind: String,
    plugin_id: String,
    tool_name: String,
    hook_name: String,
    event_count: i64,
    estimated_tokens: i64,
    estimated_pct: f64,
}

#[derive(Clone, Debug, Default, Serialize)]
struct LabelCount {
    label: String,
    count: i64,
}

#[derive(Clone, Debug, Default, Serialize)]
struct NearbyEvent {
    turn_index: i64,
    event_time: String,
    event_type: String,
    tool_name: String,
    plugin_id: String,
    hook_name: String,
}

#[derive(Clone, Debug, Default, Serialize)]
struct SpikeContext {
    top_tools: Vec<LabelCount>,
    top_event_types: Vec<LabelCount>,
    nearby_events: Vec<NearbyEvent>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct SpikeFact {
    start_time: String,
    end_time: String,
    reason: String,
    delta_tokens: i64,
    context: SpikeContext,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ComparisonSession {
    session_id: String,
    ended_at: String,
    total_tokens: i64,
    prompt_count: usize,
    total_prompt_chars: usize,
    cache_read_tokens: i64,
    cache_read_pct: f64,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ComparisonDelta {
    total_tokens: f64,
    total_tokens_pct: f64,
    prompt_count: f64,
    total_prompt_chars: f64,
    cache_read_tokens: f64,
    cache_read_pct_points: f64,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ComparisonFacts {
    project_root: String,
    compared_session_count: usize,
    recent_sessions: Vec<ComparisonSession>,
    delta_from_recent_average: Option<ComparisonDelta>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct Finding {
    id: String,
    severity: String,
    title: String,
    detail: String,
}

#[derive(Clone, Debug, Default, Serialize)]
struct Recommendation {
    id: String,
    priority: String,
    summary: String,
    detail: String,
}

#[derive(Clone, Debug, Default, Serialize)]
struct SessionReport {
    session_id: String,
    provider: String,
    started_at: String,
    ended_at: String,
    project_root: String,
    branch: String,
    model_family: String,
    turns: i64,
    events: i64,
    windows: i64,
    totals: SessionTotals,
    session_totals: SessionTotals,
    prompt_stats: PromptStats,
    top_sources: Vec<SourceFact>,
    plugin_sources: Vec<SourceFact>,
    sources_without_tokens: Vec<SourceFact>,
    spikes: Vec<SpikeFact>,
    comparisons: ComparisonFacts,
    findings: Vec<Finding>,
    recommendations: Vec<Recommendation>,
    insights: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct ReportFacts {
    session_totals: SessionTotals,
    prompt_stats: PromptStats,
    all_sources: Vec<SourceFact>,
    top_sources: Vec<SourceFact>,
    plugin_sources: Vec<SourceFact>,
    spikes: Vec<SpikeFact>,
    comparisons: ComparisonFacts,
}

#[derive(Clone, Debug, Default)]
struct PromptRecord {
    timestamp: String,
    text: String,
    is_continuation_summary: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Warn about running dolt servers that could be affected
    check_for_dolt_servers();
    
    fs::create_dir_all(&cli.repo)?;
    let store = SherlockStore::new(cli.repo);
    // Apply pending additive migrations on every invocation. Cheap — just an
    // information_schema probe when everything is already up to date — and
    // ensures old repos gain new columns without the user running `init`.
    let _ = store.migrate();

    match cli.cmd {
        Cmd::Init { commit } => {
            store.init()?;
            if commit {
                store.commit("sherlock: initialize schema")?;
            }
            println!(
                "{}",
                json!({"ok": true, "repo": store.repo.display().to_string()})
            );
        }
        Cmd::Ingest {
            history,
            session_id,
            project_root,
            branch,
            model_family,
            provider,
            experimental_cursor,
            commit,
        } => {
            store.init()?;
            let effective_history = resolve_history_path(history, &project_root)?;
            let provider_box: Box<dyn Provider> = match provider.as_deref() {
                Some(id) => providers::by_id(id)
                    .ok_or_else(|| anyhow!("unknown provider: {id}"))?,
                None => providers::detect_provider(&effective_history),
            };
            if provider_box.id() == "cursor" && !experimental_cursor {
                return Err(anyhow!(
                    "cursor adapter is experimental; re-run with --experimental-cursor to acknowledge"
                ));
            }
            if let Some(warning) = provider_box.instability_warning() {
                eprintln!("⚠️  {}", warning);
            }
            let sid = resolve_ingest_session_id(&*provider_box, &effective_history, session_id)?;
            let b = branch.unwrap_or_else(|| git_branch(&project_root).unwrap_or_default());
            let summary = ingest_session(
                &store,
                &*provider_box,
                &effective_history,
                &sid,
                &project_root,
                &b,
                &model_family,
            )?;
            if commit {
                store.commit(&format!(
                    "sherlock: ingest {} events={}",
                    sid, summary.events
                ))?;
            }
            println!("{}", serde_json::to_string(&summary)?);
        }
        Cmd::Report {
            session_id,
            format,
            warn_plugin_share,
            warn_plugin_tokens,
            exit_code_on_warn,
        } => {
            let sid = resolve_session_id_with_picker(&store, session_id)?;
            let report = summarize_session(&store, &sid)?;
            let rendered = render_report(&report, format)?;
            println!("{rendered}");

            if warn_plugin_share.is_some() || warn_plugin_tokens.is_some() {
                let warnings = check_plugin_thresholds(
                    &report,
                    warn_plugin_share,
                    warn_plugin_tokens,
                );
                for w in &warnings {
                    eprintln!("WARN: {w}");
                }
                if exit_code_on_warn && !warnings.is_empty() {
                    std::process::exit(1);
                }
            }
        }
        Cmd::Tui { session_id } => {
            let sid = match resolve_session_id_with_picker(&store, session_id) {
                Ok(s) => s,
                Err(e) if e.to_string().contains("no sessions found") => {
                    println!("No sessions found. Run `sherlock ingest` first, then re-run `sherlock tui`.");
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            if !stdout().is_terminal() {
                let report = summarize_session(&store, &sid)?;
                println!("Sherlock TUI fallback (non-interactive terminal)\n");
                println!("{}", render_report_json(&report)?);
                return Ok(());
            }
            run_tui(&store, &sid)?;
        }
        Cmd::ListAliases => {
            let rows = store.query_rows("SELECT alias, session_id, updated_at FROM session_aliases ORDER BY updated_at DESC")?;
            if rows.is_empty() {
                println!("No aliases defined.");
            } else {
                println!("Session Aliases:");
                for row in rows {
                    println!("  {} -> {}", get_str(&row, "alias"), get_str(&row, "session_id"));
                }
            }
        }
        Cmd::SetAlias { alias, session_id } => {
            // Resolve session_id if it's also an alias
            let resolved_sid = resolve_session_or_alias(&store, &session_id)?;
            
            // Check if session exists
            let check = store.query_rows(&format!(
                "SELECT session_id FROM sessions WHERE session_id='{}'",
                sql(&resolved_sid)
            ))?;
            if check.is_empty() {
                return Err(anyhow!("Session not found: {}", resolved_sid));
            }
            
            let now = iso_now();
            store.exec_script(&format!(
                "INSERT INTO session_aliases(alias, session_id, created_at, updated_at) VALUES ('{}','{}','{}','{}') \
                 ON DUPLICATE KEY UPDATE session_id='{}', updated_at='{}'",
                sql(&alias), sql(&resolved_sid), sql(&now), sql(&now), sql(&resolved_sid), sql(&now)
            ))?;
            println!("✓ Alias '{}' -> '{}'", alias, resolved_sid);
        }
        Cmd::RemoveAlias { alias } => {
            store.exec_script(&format!(
                "DELETE FROM session_aliases WHERE alias='{}'",
                sql(&alias)
            ))?;
            println!("✓ Removed alias '{}'", alias);
        }
        Cmd::Analyze {
            session_id,
            backend,
            model,
            base_url,
            api_key_env,
        } => {
            let sids = if session_id.is_empty() {
                vec![resolve_session_id_with_picker(&store, None)?]
            } else {
                session_id
                    .into_iter()
                    .map(|s| resolve_session_or_alias(&store, &s))
                    .collect::<Result<Vec<_>>>()?
            };
            let reports: Vec<Value> = sids
                .iter()
                .map(|sid| summarize_session(&store, sid))
                .collect::<Result<Vec<_>>>()?;
            let backend_id = match backend {
                Some(s) => analyze::parse_backend_id(&s)?,
                None => analyze::auto_select(),
            };
            let backend_impl = analyze::make_backend(backend_id, model, base_url, api_key_env)?;
            let req = analyze::assemble(&reports);
            let out = backend_impl.send(&req)?;
            println!("{}", out);
        }
        Cmd::Rollup {
            group_by,
            since,
            provider,
            top,
            format,
        } => {
            let report = rollup_report(&store, &group_by, since.as_deref(), provider.as_deref(), top)?;
            let rendered = match format {
                ReportFormat::Json => serde_json::to_string_pretty(&report)?,
                ReportFormat::Text | ReportFormat::Markdown => render_rollup_table(&report, &group_by)?,
            };
            println!("{rendered}");
        }
        Cmd::Headline {
            roots,
            modified_since,
            window_since,
            provider,
            top,
            skip_ingest,
            commit,
            format,
        } => {
            store.init()?;
            let roots_resolved = if roots.is_empty() {
                vec![std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))]
            } else {
                roots
            };
            let (mod_iso, mod_epoch) = parse_since_expr(&modified_since)?;
            let (win_iso, win_epoch) = match window_since.as_deref() {
                Some(s) => parse_since_expr(s)?,
                None => (mod_iso.clone(), mod_epoch),
            };
            let report = headline_report(
                &store,
                &roots_resolved,
                &mod_iso,
                mod_epoch,
                &win_iso,
                win_epoch,
                &provider,
                top,
                skip_ingest,
                commit,
            )?;
            let rendered = match format {
                ReportFormat::Json => serde_json::to_string_pretty(&report)?,
                ReportFormat::Text | ReportFormat::Markdown => render_headline_markdown(&report)?,
            };
            println!("{rendered}");
        }
        Cmd::Quota {
            provider,
            format,
            no_cache,
            credentials,
            cache_ttl,
        } => {
            if provider != "claude-code" {
                return Err(anyhow!(
                    "quota: only provider `claude-code` is supported today (got `{}`)",
                    provider
                ));
            }
            let mut opts = live::claude_code_oauth::FetchOptions::defaults()?;
            if let Some(path) = credentials {
                opts.credentials_path = path;
            }
            opts.use_cache = !no_cache;
            opts.cache_ttl_secs = cache_ttl;
            let snapshot = live::claude_code_oauth::fetch_quota(&opts)?;
            let rendered = render_quota(&snapshot, format)?;
            println!("{rendered}");
        }
        Cmd::InstallSkill { dest, force } => {
            let target = match dest {
                Some(p) => p,
                None => install_skill::default_dest()?,
            };
            let written = install_skill::install(&target, force)?;
            println!(
                "{}",
                json!({
                    "ok": true,
                    "dest": target.display().to_string(),
                    "files": written.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                })
            );
            eprintln!(
                "✓ Installed sherlock-analyze skill at {}\n  Restart Claude Code or run /help skills to confirm it's registered.",
                target.display()
            );
        }
    }

    Ok(())
}

struct SherlockStore {
    repo: PathBuf,
}

impl SherlockStore {
    fn new(repo: PathBuf) -> Self {
        Self { repo }
    }

    fn init(&self) -> Result<()> {
        self.run_allow_fail(&["dolt", "init", "-b", "main"])?;
        self.run_with_input(&["dolt", "sql"], SCHEMA_SQL)?;
        self.migrate()?;
        Ok(())
    }

    fn migrate(&self) -> Result<()> {
        for (table, column, decl) in ADDED_COLUMNS {
            let probe = format!(
                "SELECT COUNT(*) AS c FROM information_schema.columns \
                 WHERE table_schema = DATABASE() AND table_name = '{}' AND column_name = '{}'",
                table, column
            );
            let rows = match self.query_rows(&probe) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let exists = rows
                .first()
                .map(|row| get_i64(row, "c") > 0)
                .unwrap_or(false);
            if !exists {
                let alter = format!("ALTER TABLE {} ADD COLUMN {} {};", table, column, decl);
                let _ = self.run_with_input(&["dolt", "sql"], &alter);
            }
        }
        Ok(())
    }

    fn exec_script(&self, script: &str) -> Result<()> {
        self.run_with_input(&["dolt", "sql"], script).map(|_| ())
    }

    fn query_rows(&self, query: &str) -> Result<Vec<Value>> {
        let out = self.run(&["dolt", "sql", "-q", query, "-r", "json"])?;
        let parsed: Value = serde_json::from_str(if out.trim().is_empty() {
            r#"{"rows":[]}"#
        } else {
            &out
        })?;
        Ok(parsed
            .get("rows")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default())
    }

    fn commit(&self, message: &str) -> Result<()> {
        self.run(&["dolt", "add", "."])?;
        self.run_allow_fail(&["dolt", "commit", "-m", message])?;
        Ok(())
    }

    fn run(&self, args: &[&str]) -> Result<String> {
        let output = Command::new(args[0])
            .args(&args[1..])
            .current_dir(&self.repo)
            .output()
            .with_context(|| format!("failed to run {}", args.join(" ")))?;
        if !output.status.success() {
            return Err(anyhow!(
                "command failed: {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn run_allow_fail(&self, args: &[&str]) -> Result<String> {
        let output = Command::new(args[0])
            .args(&args[1..])
            .current_dir(&self.repo)
            .output()
            .with_context(|| format!("failed to run {}", args.join(" ")))?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn run_with_input(&self, args: &[&str], input: &str) -> Result<String> {
        let mut cmd = Command::new(args[0]);
        cmd.args(&args[1..]).current_dir(&self.repo);
        let output = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    stdin.write_all(input.as_bytes())?;
                }
                child.wait_with_output()
            })
            .with_context(|| format!("failed to run {}", args.join(" ")))?;
        if !output.status.success() {
            return Err(anyhow!(
                "command failed: {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

fn ingest_session(
    store: &SherlockStore,
    provider: &dyn Provider,
    history_path: &Path,
    session_id: &str,
    project_root: &Path,
    branch: &str,
    model_family: &str,
) -> Result<IngestSummary> {
    let started_at = iso_now();
    let raw = fs::read_to_string(history_path).unwrap_or_default();
    let artifact_id = short_id("artifact");
    let mut sql_script = String::new();
    sql_script.push_str("START TRANSACTION;\n");
    sql_script.push_str(&format!(
        "INSERT INTO sessions(session_id, started_at, project_root, branch, model_family, provider) \
         VALUES ('{}','{}','{}','{}','{}','{}') \
         ON DUPLICATE KEY UPDATE started_at=VALUES(started_at), project_root=VALUES(project_root), branch=VALUES(branch), model_family=VALUES(model_family), provider=VALUES(provider);\n",
        sql(session_id),
        sql(&started_at),
        sql(&project_root.display().to_string()),
        sql(branch),
        sql(model_family),
        sql(provider.id())
    ));
    // Re-ingest is idempotent: replace session-scoped derived records.
    sql_script.push_str(&format!(
        "DELETE FROM attributions WHERE window_id IN (SELECT window_id FROM windows WHERE session_id='{}');\n",
        sql(session_id)
    ));
    sql_script.push_str(&format!(
        "DELETE FROM windows WHERE session_id='{}';\n",
        sql(session_id)
    ));
    sql_script.push_str(&format!(
        "DELETE FROM events WHERE session_id='{}';\n",
        sql(session_id)
    ));
    sql_script.push_str(&format!(
        "DELETE FROM turns WHERE session_id='{}';\n",
        sql(session_id)
    ));
    sql_script.push_str(&format!(
        "DELETE FROM artifacts WHERE session_id='{}' AND artifact_type='history_jsonl';\n",
        sql(session_id)
    ));
    sql_script.push_str(&format!(
        "INSERT INTO artifacts(artifact_id, session_id, artifact_type, path_or_key, sha256, captured_at) \
         VALUES ('{}','{}','history_jsonl','{}','{}','{}');\n",
        artifact_id,
        sql(session_id),
        sql(&history_path.display().to_string()),
        sha256_hex(&raw),
        iso_now()
    ));

    let mut events = 0usize;
    let mut turns = 0usize;
    let mut windows = 0usize;
    let mut seen_sources = std::collections::HashSet::<String>::new();
    let mut prev_total: Option<i64> = None;
    let mut cum_input = 0i64;
    let mut cum_output = 0i64;
    let mut cum_cache_read = 0i64;
    let mut cum_cache_write = 0i64;
    let mut first_event_time: Option<String> = None;
    let mut last_event_time: Option<String> = None;

    for (idx, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let obj: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ev = RawEvent::Json(obj.clone());
        // An event belongs to the ingestion target if it explicitly names that
        // session, or if the provider doesn't tag every event (None) — copilot
        // CLI, for example, only stamps session.start with a sessionId.
        match provider.extract_session_id(&ev) {
            Some(id) if id != session_id => continue,
            _ => {}
        }

        let event_time = provider
            .event_time_value(&ev)
            .unwrap_or_else(|| started_at.clone());
        if first_event_time.is_none() {
            first_event_time = Some(event_time.clone());
        }
        last_event_time = Some(event_time.clone());
        let event_type = provider.infer_event_type(&ev);
        let tool_name = provider.extract_tool_name(&ev);
        let hook_name = provider.extract_hook_name(&ev);
        let plugin_id = provider.extract_plugin_id(&ev, &tool_name);
        let mcp_server_name = provider.extract_mcp_server_name(&tool_name);
        let plugin_part = plugin_id.clone().unwrap_or_default();
        let mcp_part = mcp_server_name.clone().unwrap_or_default();
        let fp = format!(
            "{event_type}|tool={tool_name}|hook={hook_name}|plugin={plugin_part}|mcp={mcp_part}"
        );
        let source_id = format!("source-{}", sha1_short(&fp));
        if !seen_sources.contains(&fp) {
            sql_script.push_str(&format!(
                "INSERT INTO sources(source_id, source_kind, plugin_id, hook_name, mcp_server_name, tool_name, fingerprint) \
                 VALUES ('{}','{}',{},'{}',{},'{}','{}') \
                 ON DUPLICATE KEY UPDATE source_kind=VALUES(source_kind), plugin_id=VALUES(plugin_id), hook_name=VALUES(hook_name), mcp_server_name=VALUES(mcp_server_name), tool_name=VALUES(tool_name);\n",
                source_id,
                source_kind(&event_type),
                sql_opt(&plugin_id),
                sql(&hook_name),
                sql_opt(&mcp_server_name),
                sql(&tool_name),
                sql(&fp)
            ));
            seen_sources.insert(fp);
        }

        let turn_id = short_id("turn");
        let usage = provider.extract_usage(&ev);
        cum_input += usage.input_tokens.unwrap_or(0);
        cum_output += usage.output_tokens.unwrap_or(0);
        cum_cache_read += usage.cache_read_tokens.unwrap_or(0);
        cum_cache_write += usage.cache_write_tokens.unwrap_or(0);
        let payload_bytes = serde_json::to_string(&obj).map(|s| s.len()).unwrap_or(0);

        sql_script.push_str(&format!(
            "INSERT INTO turns(turn_id, session_id, turn_index, started_at, ended_at, input_tokens_cum, output_tokens_cum, cache_read_tokens_cum, cache_write_tokens_cum, cost_cum_usd) \
             VALUES ('{}','{}',{},'{}','{}',{},{},{},{},NULL);\n",
            turn_id,
            sql(session_id),
            turns,
            sql(&event_time),
            sql(&event_time),
            cum_input,
            cum_output,
            cum_cache_read,
            cum_cache_write,
        ));
        turns += 1;

        sql_script.push_str(&format!(
            "INSERT INTO events(event_id, session_id, turn_id, event_time, event_type, source_id, payload_bytes, raw_ref, provider) \
             VALUES ('{}','{}','{}','{}','{}','{}',{},'{}:{}','{}');\n",
            short_id("event"),
            sql(session_id),
            turn_id,
            sql(&event_time),
            event_type,
            source_id,
            payload_bytes,
            artifact_id,
            idx + 1,
            sql(provider.id())
        ));
        events += 1;

        let total = cum_input + cum_output + cum_cache_read + cum_cache_write;
        if let Some(prev) = prev_total {
            let delta = total - prev;
            if delta >= provider.spike_threshold() {
                windows += 1;
                sql_script.push_str(&format!(
                    "INSERT INTO windows(window_id, session_id, start_time, end_time, reason, delta_tokens, delta_cost_usd) \
                     VALUES ('{}','{}','{}','{}','spike',{},NULL);\n",
                    short_id("window"),
                    sql(session_id),
                    sql(&event_time),
                    sql(&event_time),
                    delta
                ));
            }
        }
        prev_total = Some(total);
    }

    sql_script.push_str(&format!(
        "UPDATE sessions SET started_at='{}', ended_at='{}' WHERE session_id='{}'",
        sql(first_event_time.as_deref().unwrap_or(&started_at)),
        sql(last_event_time.as_deref().unwrap_or(&started_at)),
        sql(session_id)
    ));
    sql_script.push_str(";\nCOMMIT;\n");
    store.exec_script(&sql_script)?;

    Ok(IngestSummary {
        ok: true,
        session_id: session_id.to_string(),
        events,
        turns,
        sources: seen_sources.len(),
        windows,
    })
}

fn summarize_session(store: &SherlockStore, session_id: &str) -> Result<Value> {
    let session_rows = store.query_rows(&format!(
        "SELECT session_id, started_at, ended_at, project_root, branch, model_family, COALESCE(provider,'claude-code') AS provider FROM sessions WHERE session_id='{}'",
        sql(session_id)
    ))?;
    if session_rows.is_empty() {
        return Ok(json!({"error": "session_not_found", "session_id": session_id}));
    }
    let session = &session_rows[0];
    let provider_id = get_str(session, "provider");
    let provider = providers::by_id(if provider_id.is_empty() { "claude-code" } else { &provider_id })
        .unwrap_or_else(|| Box::new(providers::claude_code::ClaudeCodeProvider));
    let counts = store.query_rows(&format!(
        "SELECT \
         (SELECT COUNT(*) FROM turns WHERE session_id='{}') AS turns, \
         (SELECT COUNT(*) FROM events WHERE session_id='{}') AS events, \
         (SELECT COUNT(*) FROM windows WHERE session_id='{}') AS windows",
        sql(session_id),
        sql(session_id),
        sql(session_id)
    ))?;
    let totals = session_totals(store, session_id)?;
    let prompt_stats = prompt_facts(store, &*provider, session_id)?;
    let grand_total = totals.total_tokens;
    let top_source_rows = store.query_rows(&format!(
        "SELECT e.source_id, s.source_kind, COALESCE(s.plugin_id, '') AS plugin_id, COALESCE(s.tool_name, '') AS tool_name, COALESCE(s.hook_name, '') AS hook_name, COUNT(*) AS event_count \
         FROM events e JOIN sources s ON e.source_id = s.source_id \
         WHERE e.session_id='{}' \
         GROUP BY e.source_id, s.source_kind, s.plugin_id, s.tool_name, s.hook_name \
         ORDER BY event_count DESC LIMIT 50",
        sql(session_id)
    ))?;
    let source_token_totals = source_token_totals(store, session_id)?;
    let mut enriched_sources: Vec<SourceFact> = top_source_rows
        .iter()
        .map(|src| {
            let source_id = get_str(src, "source_id");
            let estimated_tokens = source_token_totals.get(&source_id).copied().unwrap_or(0);
            let estimated_pct = if grand_total > 0 {
                (estimated_tokens as f64 * 100.0) / grand_total as f64
            } else {
                0.0
            };
            SourceFact {
                source_id,
                source_kind: get_str(src, "source_kind"),
                plugin_id: get_str(src, "plugin_id"),
                tool_name: get_str(src, "tool_name"),
                hook_name: get_str(src, "hook_name"),
                event_count: get_i64(src, "event_count"),
                estimated_tokens,
                estimated_pct,
            }
        })
        .collect();
    enriched_sources.sort_by(|a, b| {
        b.estimated_tokens
            .cmp(&a.estimated_tokens)
            .then_with(|| b.event_count.cmp(&a.event_count))
    });

    let top_sources = enriched_sources.iter().take(5).cloned().collect::<Vec<_>>();
    let plugin_sources = enriched_sources
        .iter()
        .filter(|source| !source.plugin_id.is_empty())
        .take(10)
        .cloned()
        .collect::<Vec<_>>();
    let sources_without_tokens = enriched_sources
        .iter()
        .filter(|source| source.event_count > 0 && source.estimated_tokens == 0)
        .take(10)
        .cloned()
        .collect::<Vec<_>>();
    let spikes = spike_context(store, &*provider, session_id)?;
    let comparisons = session_comparison(store, &*provider, &get_str(session, "project_root"), session_id, 3)?;
    let facts = ReportFacts {
        session_totals: totals.clone(),
        prompt_stats: prompt_stats.clone(),
        all_sources: enriched_sources.clone(),
        top_sources: top_sources.clone(),
        plugin_sources: plugin_sources.clone(),
        spikes: spikes.clone(),
        comparisons: comparisons.clone(),
    };
    let findings = findings_from_facts(&*provider, &facts);
    let recommendations = recommendations_from_findings(&findings);
    let insights = insights_from_facts(&facts, &findings);
    let report = SessionReport {
        session_id: get_str(session, "session_id"),
        provider: provider.id().to_string(),
        started_at: get_str(session, "started_at"),
        ended_at: get_str(session, "ended_at"),
        project_root: get_str(session, "project_root"),
        branch: get_str(session, "branch"),
        model_family: get_str(session, "model_family"),
        turns: counts.first().map(|row| get_i64(row, "turns")).unwrap_or(0),
        events: counts
            .first()
            .map(|row| get_i64(row, "events"))
            .unwrap_or(0),
        windows: counts
            .first()
            .map(|row| get_i64(row, "windows"))
            .unwrap_or(0),
        totals: totals.clone(),
        session_totals: totals,
        prompt_stats,
        top_sources,
        plugin_sources,
        sources_without_tokens,
        spikes,
        comparisons,
        findings,
        recommendations,
        insights,
    };
    Ok(serde_json::to_value(report)?)
}

fn session_totals(store: &SherlockStore, session_id: &str) -> Result<SessionTotals> {
    let totals_rows = store.query_rows(&format!(
        "SELECT \
         COALESCE(MAX(input_tokens_cum),0) AS input_tokens, \
         COALESCE(MAX(output_tokens_cum),0) AS output_tokens, \
         COALESCE(MAX(cache_read_tokens_cum),0) AS cache_read_tokens, \
         COALESCE(MAX(cache_write_tokens_cum),0) AS cache_write_tokens \
         FROM turns WHERE session_id='{}'",
        sql(session_id)
    ))?;
    let totals = totals_rows.first().cloned().unwrap_or_else(|| json!({}));
    let input_tokens = get_i64(&totals, "input_tokens");
    let output_tokens = get_i64(&totals, "output_tokens");
    let cache_read_tokens = get_i64(&totals, "cache_read_tokens");
    let cache_write_tokens = get_i64(&totals, "cache_write_tokens");
    let total_tokens = input_tokens + output_tokens + cache_read_tokens + cache_write_tokens;
    Ok(SessionTotals {
        input_tokens,
        output_tokens,
        cache_read_tokens,
        cache_write_tokens,
        total_tokens,
        cache_read_pct: pct(cache_read_tokens, total_tokens),
        cache_write_pct: pct(cache_write_tokens, total_tokens),
    })
}

fn prompt_facts(
    store: &SherlockStore,
    provider: &dyn Provider,
    session_id: &str,
) -> Result<PromptStats> {
    let artifact_path = history_artifact_path(store, session_id)?;
    let Some(path) = artifact_path else {
        return Ok(PromptStats::default());
    };
    let raw = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(_) => return Ok(PromptStats::default()),
    };

    let mut prompts = Vec::<PromptRecord>::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let obj: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let ev = RawEvent::Json(obj);
        // An event belongs to the ingestion target if it explicitly names that
        // session, or if the provider doesn't tag every event (None) — copilot
        // CLI, for example, only stamps session.start with a sessionId.
        match provider.extract_session_id(&ev) {
            Some(id) if id != session_id => continue,
            _ => {}
        }
        let Some(text) = provider.extract_prompt_text(&ev) else {
            continue;
        };
        let is_compact = provider.is_compact_summary(&ev);
        prompts.push(PromptRecord {
            timestamp: provider.event_time_value(&ev).unwrap_or_default(),
            is_continuation_summary: provider.is_continuation_summary(&text) || is_compact,
            text,
        });
    }

    if prompts.is_empty() {
        return Ok(PromptStats::default());
    }

    let total_prompt_chars = prompts
        .iter()
        .map(|prompt| prompt.text.chars().count())
        .sum::<usize>();
    let prompt_count = prompts.len();
    let average_prompt_chars = total_prompt_chars as f64 / prompt_count as f64;
    let mut longest_prompts = prompts
        .iter()
        .map(|prompt| PromptExcerpt {
            timestamp: prompt.timestamp.clone(),
            prompt_kind: if prompt.is_continuation_summary {
                "continuation_summary".to_string()
            } else {
                "prompt".to_string()
            },
            chars: prompt.text.chars().count(),
            excerpt: excerpt(&prompt.text, 120),
        })
        .collect::<Vec<_>>();
    longest_prompts.sort_by(|a, b| b.chars.cmp(&a.chars));

    let continuation_prompts = prompts
        .iter()
        .filter(|prompt| prompt.is_continuation_summary)
        .collect::<Vec<_>>();
    let continuation_total_chars = continuation_prompts
        .iter()
        .map(|prompt| prompt.text.chars().count())
        .sum::<usize>();
    let continuation_count = continuation_prompts.len();
    let continuation_average = if continuation_count > 0 {
        continuation_total_chars as f64 / continuation_count as f64
    } else {
        0.0
    };
    let continuation_max = continuation_prompts
        .iter()
        .map(|prompt| prompt.text.chars().count())
        .max()
        .unwrap_or(0);

    Ok(PromptStats {
        prompt_count,
        total_prompt_chars,
        average_prompt_chars,
        longest_prompts: longest_prompts.into_iter().take(3).collect(),
        continuation_summaries: ContinuationSummaryStats {
            count: continuation_count,
            total_chars: continuation_total_chars,
            average_chars: continuation_average,
            max_chars: continuation_max,
        },
    })
}

fn session_comparison(
    store: &SherlockStore,
    provider: &dyn Provider,
    project_root: &str,
    session_id: &str,
    limit: usize,
) -> Result<ComparisonFacts> {
    let rows = store.query_rows(&format!(
        "SELECT session_id, COALESCE(ended_at, started_at, '') AS ended_at \
         FROM sessions \
         WHERE project_root='{}' AND session_id<>'{}' \
         ORDER BY COALESCE(ended_at, started_at) DESC LIMIT {}",
        sql(project_root),
        sql(session_id),
        limit
    ))?;
    let mut recent_sessions = Vec::new();
    for row in rows {
        let sid = get_str(&row, "session_id");
        let totals = session_totals(store, &sid)?;
        let prompts = prompt_facts(store, provider, &sid)?;
        recent_sessions.push(ComparisonSession {
            session_id: sid,
            ended_at: get_str(&row, "ended_at"),
            total_tokens: totals.total_tokens,
            prompt_count: prompts.prompt_count,
            total_prompt_chars: prompts.total_prompt_chars,
            cache_read_tokens: totals.cache_read_tokens,
            cache_read_pct: totals.cache_read_pct,
        });
    }

    let delta_from_recent_average = if recent_sessions.is_empty() {
        None
    } else {
        let divisor = recent_sessions.len() as f64;
        let avg_total_tokens = recent_sessions
            .iter()
            .map(|item| item.total_tokens as f64)
            .sum::<f64>()
            / divisor;
        let avg_prompt_count = recent_sessions
            .iter()
            .map(|item| item.prompt_count as f64)
            .sum::<f64>()
            / divisor;
        let avg_prompt_chars = recent_sessions
            .iter()
            .map(|item| item.total_prompt_chars as f64)
            .sum::<f64>()
            / divisor;
        let avg_cache_read_tokens = recent_sessions
            .iter()
            .map(|item| item.cache_read_tokens as f64)
            .sum::<f64>()
            / divisor;
        let avg_cache_read_pct = recent_sessions
            .iter()
            .map(|item| item.cache_read_pct)
            .sum::<f64>()
            / divisor;
        let current_totals = session_totals(store, session_id)?;
        let current_prompts = prompt_facts(store, provider, session_id)?;
        Some(ComparisonDelta {
            total_tokens: current_totals.total_tokens as f64 - avg_total_tokens,
            total_tokens_pct: if avg_total_tokens > 0.0 {
                ((current_totals.total_tokens as f64 - avg_total_tokens) * 100.0) / avg_total_tokens
            } else {
                0.0
            },
            prompt_count: current_prompts.prompt_count as f64 - avg_prompt_count,
            total_prompt_chars: current_prompts.total_prompt_chars as f64 - avg_prompt_chars,
            cache_read_tokens: current_totals.cache_read_tokens as f64 - avg_cache_read_tokens,
            cache_read_pct_points: current_totals.cache_read_pct - avg_cache_read_pct,
        })
    };

    Ok(ComparisonFacts {
        project_root: project_root.to_string(),
        compared_session_count: recent_sessions.len(),
        recent_sessions,
        delta_from_recent_average,
    })
}

fn spike_context(
    store: &SherlockStore,
    provider: &dyn Provider,
    session_id: &str,
) -> Result<Vec<SpikeFact>> {
    // Recompute spike windows from turn deltas so context links by turn_index instead of timestamp text.
    let turn_rows = store.query_rows(&format!(
        "SELECT turn_index, started_at, ended_at, input_tokens_cum, output_tokens_cum, cache_read_tokens_cum, cache_write_tokens_cum \
         FROM turns WHERE session_id='{}' ORDER BY turn_index ASC",
        sql(session_id)
    ))?;
    let event_rows = store.query_rows(&format!(
        "SELECT t.turn_index, e.event_time, e.event_type, COALESCE(s.tool_name, '') AS tool_name, \
         COALESCE(s.plugin_id, '') AS plugin_id, COALESCE(s.hook_name, '') AS hook_name \
         FROM events e \
         JOIN turns t ON e.turn_id=t.turn_id \
         JOIN sources s ON e.source_id=s.source_id \
         WHERE e.session_id='{}' ORDER BY t.turn_index ASC",
        sql(session_id)
    ))?;
    let nearby = event_rows
        .iter()
        .map(|row| NearbyEvent {
            turn_index: get_i64(row, "turn_index"),
            event_time: get_str(row, "event_time"),
            event_type: get_str(row, "event_type"),
            tool_name: get_str(row, "tool_name"),
            plugin_id: get_str(row, "plugin_id"),
            hook_name: get_str(row, "hook_name"),
        })
        .collect::<Vec<_>>();

    #[derive(Clone)]
    struct TurnSpike {
        turn_index: i64,
        start_time: String,
        end_time: String,
        delta_tokens: i64,
    }
    let mut prev_total: Option<i64> = None;
    let mut computed_spikes = Vec::<TurnSpike>::new();
    for row in &turn_rows {
        let total = get_i64(row, "input_tokens_cum")
            + get_i64(row, "output_tokens_cum")
            + get_i64(row, "cache_read_tokens_cum")
            + get_i64(row, "cache_write_tokens_cum");
        if let Some(prev) = prev_total {
            let delta = total - prev;
            if delta >= provider.spike_threshold() {
                computed_spikes.push(TurnSpike {
                    turn_index: get_i64(row, "turn_index"),
                    start_time: get_str(row, "started_at"),
                    end_time: get_str(row, "ended_at"),
                    delta_tokens: delta,
                });
            }
        }
        prev_total = Some(total);
    }
    computed_spikes.sort_by_key(|spike| -spike.delta_tokens);
    computed_spikes.truncate(5);

    let mut out = Vec::new();
    for spike in computed_spikes {
        let focus_idx = nearby
            .iter()
            .position(|event| event.turn_index == spike.turn_index)
            .unwrap_or(0);
        let start_idx = focus_idx.saturating_sub(2);
        let end_idx = usize::min(focus_idx + 3, nearby.len());
        let context_slice = nearby[start_idx..end_idx].to_vec();
        let mut tool_counts: HashMap<String, i64> = HashMap::new();
        let mut event_counts: HashMap<String, i64> = HashMap::new();
        for event in &context_slice {
            let tool_label = if !event.tool_name.is_empty() {
                event.tool_name.clone()
            } else if !event.hook_name.is_empty() {
                event.hook_name.clone()
            } else {
                "core".to_string()
            };
            *tool_counts.entry(tool_label).or_insert(0) += 1;
            *event_counts.entry(event.event_type.clone()).or_insert(0) += 1;
        }
        out.push(SpikeFact {
            start_time: spike.start_time,
            end_time: spike.end_time,
            reason: "spike".to_string(),
            delta_tokens: spike.delta_tokens,
            context: SpikeContext {
                top_tools: top_label_counts(&tool_counts, 3),
                top_event_types: top_label_counts(&event_counts, 3),
                nearby_events: context_slice,
            },
        });
    }
    Ok(out)
}

fn findings_from_facts(provider: &dyn Provider, facts: &ReportFacts) -> Vec<Finding> {
    let mut findings = Vec::new();
    let totals = &facts.session_totals;
    let prompts = &facts.prompt_stats;
    let workflow_tokens = workflow_tool_tokens(provider, &facts.all_sources);
    let plugin_tokens = facts
        .plugin_sources
        .iter()
        .map(|source| source.estimated_tokens)
        .sum::<i64>();
    let tool_tokens = facts
        .all_sources
        .iter()
        .filter(|source| source.source_kind == "tool")
        .map(|source| source.estimated_tokens)
        .sum::<i64>();

    if totals.total_tokens == 0 {
        findings.push(Finding {
            id: "no-token-usage".to_string(),
            severity: "medium".to_string(),
            title: "No token usage was captured for this session.".to_string(),
            detail: "The ingested history has events but no cumulative token growth, so the report cannot attribute spend beyond event volume.".to_string(),
        });
    }
    if provider.has_cache_tokens()
        && totals.total_tokens >= 10_000
        && totals.cache_read_pct >= 60.0
    {
        findings.push(Finding {
            id: "cache-read-dominated".to_string(),
            severity: "high".to_string(),
            title: "Cache reads dominate session spend.".to_string(),
            detail: format!(
                "Cache reads account for {:.1}% of total tokens ({} of {}).",
                totals.cache_read_pct, totals.cache_read_tokens, totals.total_tokens
            ),
        });
    }
    if provider.has_continuation_summaries()
        && prompts.continuation_summaries.count > 0
        && prompts.continuation_summaries.max_chars >= 3_000
    {
        findings.push(Finding {
            id: "oversized-continuation-summary".to_string(),
            severity: "medium".to_string(),
            title: "Continuation summaries are unusually large.".to_string(),
            detail: format!(
                "{} continuation summaries contributed {} chars; the largest was {} chars.",
                prompts.continuation_summaries.count,
                prompts.continuation_summaries.total_chars,
                prompts.continuation_summaries.max_chars
            ),
        });
    }
    if totals.total_tokens > 0 && pct(workflow_tokens, totals.total_tokens) >= 50.0 {
        findings.push(Finding {
            id: "workflow-heavy-session".to_string(),
            severity: "medium".to_string(),
            title: "Workflow orchestration tools dominate spend.".to_string(),
            detail: format!(
                "Read/TaskUpdate/Agent/Bash style tools account for {:.1}% of total tokens.",
                pct(workflow_tokens, totals.total_tokens)
            ),
        });
    }
    if plugin_tokens > 0 && tool_tokens >= plugin_tokens * 3 {
        findings.push(Finding {
            id: "tool-driven-cost-over-plugin-cost".to_string(),
            severity: "low".to_string(),
            title: "Plugins are present but secondary to tool-driven cost.".to_string(),
            detail: format!(
                "Plugin-attributed sources account for {} estimated tokens versus {} for tool sources.",
                plugin_tokens, tool_tokens
            ),
        });
    }
    if prompts.prompt_count <= 2 && totals.total_tokens >= 10_000 {
        findings.push(Finding {
            id: "low-prompt-count-high-usage".to_string(),
            severity: "medium".to_string(),
            title: "Few human prompts produced high total usage.".to_string(),
            detail: format!(
                "{} prompts drove {} total tokens, indicating context growth outside direct prompt volume.",
                prompts.prompt_count, totals.total_tokens
            ),
        });
    }
    
    // Check if sources have events but no token attribution
    let sources_with_events_but_no_tokens = facts
        .all_sources
        .iter()
        .filter(|s| s.event_count > 0 && s.estimated_tokens == 0)
        .count();
    
    if sources_with_events_but_no_tokens > 0 && totals.total_tokens > 0 {
        let sources_with_tokens = facts
            .all_sources
            .iter()
            .filter(|s| s.estimated_tokens > 0)
            .count();
        findings.push(Finding {
            id: "sources-missing-token-attribution".to_string(),
            severity: "medium".to_string(),
            title: "Some sources have events but no token attribution.".to_string(),
            detail: format!(
                "{} sources ({} events) lack token attribution while {} sources have tokens. This may indicate events without usage metadata or attribution gaps in the ingestion logic.",
                sources_with_events_but_no_tokens,
                facts.all_sources.iter().filter(|s| s.event_count > 0 && s.estimated_tokens == 0).map(|s| s.event_count).sum::<i64>(),
                sources_with_tokens
            ),
        });
    }

    findings
}

fn recommendations_from_findings(findings: &[Finding]) -> Vec<Recommendation> {
    let mut recommendations = Vec::new();
    for finding in findings {
        match finding.id.as_str() {
            "cache-read-dominated" => recommendations.push(Recommendation {
                id: "reduce-cache-churn".to_string(),
                priority: "high".to_string(),
                summary: "Reduce context rehydration between turns.".to_string(),
                detail: "Trim repeated context blocks, compress carry-forward state, and prefer shorter resumable summaries before the next turn boundary.".to_string(),
            }),
            "oversized-continuation-summary" => recommendations.push(Recommendation {
                id: "shrink-resume-summaries".to_string(),
                priority: "medium".to_string(),
                summary: "Shorten continuation summaries before resuming work.".to_string(),
                detail: "Keep resume prompts focused on open decisions, active files, and next steps rather than replaying full session history.".to_string(),
            }),
            "workflow-heavy-session" => recommendations.push(Recommendation {
                id: "batch-workflow-steps".to_string(),
                priority: "medium".to_string(),
                summary: "Batch orchestration work into fewer tool rounds.".to_string(),
                detail: "Combine adjacent read/update/bash steps when the workflow is predictable so the session spends more tokens on synthesis than on control flow.".to_string(),
            }),
            "tool-driven-cost-over-plugin-cost" => recommendations.push(Recommendation {
                id: "separate-plugin-vs-tool-optimization".to_string(),
                priority: "low".to_string(),
                summary: "Optimize the dominant tools before tuning plugin usage.".to_string(),
                detail: "Plugin events are present, but the spend is driven more by the base tool loop than by plugin overhead.".to_string(),
            }),
            "low-prompt-count-high-usage" => recommendations.push(Recommendation {
                id: "inspect-token-spikes".to_string(),
                priority: "medium".to_string(),
                summary: "Inspect the highest spike windows and long-running tool loops.".to_string(),
                detail: "A small number of prompts produced disproportionate usage, so the main savings are likely in downstream tool activity or resumed context.".to_string(),
            }),
            "no-token-usage" => recommendations.push(Recommendation {
                id: "reingest-rich-history".to_string(),
                priority: "medium".to_string(),
                summary: "Re-ingest from richer Claude project logs if available.".to_string(),
                detail: "The current artifact did not expose token growth, so attribution quality will improve only if the source history includes cumulative usage data.".to_string(),
            }),
            "sources-missing-token-attribution" => recommendations.push(Recommendation {
                id: "check-attribution-logic".to_string(),
                priority: "medium".to_string(),
                summary: "Compare event-based metrics when token attribution is incomplete.".to_string(),
                detail: "For sources without token data, use event counts and payload sizes as proxy metrics. Consider enriching logs with per-event token metadata or implementing more sophisticated attribution heuristics.".to_string(),
            }),
            _ => {}
        }
    }
    recommendations
}

fn insights_from_facts(facts: &ReportFacts, findings: &[Finding]) -> Vec<String> {
    let mut insights = Vec::new();
    let totals = &facts.session_totals;
    if totals.total_tokens > 0 {
        insights.push(format!(
            "Session used {} total tokens; cache reads were {:.1}% of spend.",
            totals.total_tokens, totals.cache_read_pct
        ));
    } else {
        insights.push(
            "No token usage found for this session in the ingested source. Re-ingest from in-depth Claude project logs (.claude/projects/.../*.jsonl)."
                .to_string(),
        );
    }
    if facts.prompt_stats.prompt_count > 0 {
        insights.push(format!(
            "{} prompts totaled {} chars; average prompt length was {:.0} chars.",
            facts.prompt_stats.prompt_count,
            facts.prompt_stats.total_prompt_chars,
            facts.prompt_stats.average_prompt_chars
        ));
    }
    if let Some(top) = facts.top_sources.first() {
        insights.push(format!(
            "Top source: kind={} tool={} plugin={} estimated_tokens={}.",
            top.source_kind,
            if top.tool_name.is_empty() {
                "n/a"
            } else {
                &top.tool_name
            },
            if top.plugin_id.is_empty() {
                "n/a"
            } else {
                &top.plugin_id
            },
            top.estimated_tokens
        ));
    }
    if let Some(delta) = &facts.comparisons.delta_from_recent_average {
        insights.push(format!(
            "Vs recent same-project sessions: total tokens {:+.0} ({:+.1}%), cache-read share {:+.1} points.",
            delta.total_tokens, delta.total_tokens_pct, delta.cache_read_pct_points
        ));
    }
    if let Some(spike) = facts.spikes.first() {
        insights.push(format!(
            "Largest spike window started at {} and added {} tokens.",
            spike.start_time, spike.delta_tokens
        ));
    }
    insights.extend(findings.iter().take(2).map(|finding| finding.title.clone()));
    insights
}

fn render_report(report: &Value, format: ReportFormat) -> Result<String> {
    match format {
        ReportFormat::Json => render_report_json(report),
        ReportFormat::Markdown => render_report_markdown(report),
        ReportFormat::Text => render_report_text(report),
    }
}

fn render_report_json(report: &Value) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

fn render_report_markdown(report: &Value) -> Result<String> {
    let mut out = String::new();
    let totals = report
        .get("session_totals")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let prompts = report
        .get("prompt_stats")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let continuation = prompts
        .get("continuation_summaries")
        .cloned()
        .unwrap_or_else(|| json!({}));
    writeln!(&mut out, "# Session Report")?;
    writeln!(
        &mut out,
        "\nSession `{}` on `{}` used **{}** total tokens across **{}** turns and **{}** events. Cache reads were **{:.1}%** of spend. The session had **{}** human prompts totaling **{}** chars.",
        get_str(report, "session_id"),
        get_str(report, "project_root"),
        get_i64(&totals, "total_tokens"),
        get_i64(report, "turns"),
        get_i64(report, "events"),
        get_f64(&totals, "cache_read_pct"),
        get_i64(&prompts, "prompt_count"),
        get_i64(&prompts, "total_prompt_chars"),
    )?;
    if get_i64(&continuation, "count") > 0 {
        writeln!(
            &mut out,
            "Continuation summaries appeared **{}** time(s) and contributed **{}** chars.",
            get_i64(&continuation, "count"),
            get_i64(&continuation, "total_chars"),
        )?;
    }

    let findings = report
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !findings.is_empty() {
        writeln!(&mut out, "\n## Findings")?;
        for finding in findings {
            writeln!(
                &mut out,
                "- **{}** (`{}`): {}",
                get_str(&finding, "title"),
                get_str(&finding, "severity"),
                get_str(&finding, "detail")
            )?;
        }
    }

    let recommendations = report
        .get("recommendations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !recommendations.is_empty() {
        writeln!(&mut out, "\n## Recommendations")?;
        for recommendation in recommendations {
            writeln!(
                &mut out,
                "- **{}** (`{}`): {}",
                get_str(&recommendation, "summary"),
                get_str(&recommendation, "priority"),
                get_str(&recommendation, "detail")
            )?;
        }
    }

    let top_sources = report
        .get("top_sources")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !top_sources.is_empty() {
        writeln!(&mut out, "\n## Top Sources")?;
        for source in top_sources {
            let label = if !get_str(&source, "tool_name").is_empty() {
                get_str(&source, "tool_name")
            } else if !get_str(&source, "hook_name").is_empty() {
                get_str(&source, "hook_name")
            } else {
                get_str(&source, "source_kind")
            };
            writeln!(
                &mut out,
                "- `{}`: {} estimated tokens ({:.1}%), {} events{}",
                label,
                get_i64(&source, "estimated_tokens"),
                get_f64(&source, "estimated_pct"),
                get_i64(&source, "event_count"),
                if get_str(&source, "plugin_id").is_empty() {
                    String::new()
                } else {
                    format!(", plugin `{}`", get_str(&source, "plugin_id"))
                }
            )?;
        }
    }

    let spikes = report
        .get("spikes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !spikes.is_empty() {
        writeln!(&mut out, "\n## Spikes")?;
        for spike in spikes {
            let tools = spike
                .get("context")
                .and_then(|ctx| ctx.get("top_tools"))
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|item| {
                            format!("{} ({})", get_str(item, "label"), get_i64(item, "count"))
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            writeln!(
                &mut out,
                "- `{}`: {} tokens; nearby tools: {}",
                get_str(&spike, "start_time"),
                get_i64(&spike, "delta_tokens"),
                if tools.is_empty() {
                    "n/a".to_string()
                } else {
                    tools
                }
            )?;
        }
    }

    Ok(out.trim_end().to_string())
}

fn render_report_text(report: &Value) -> Result<String> {
    let mut out = String::new();
    let totals = report
        .get("session_totals")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let prompts = report
        .get("prompt_stats")
        .cloned()
        .unwrap_or_else(|| json!({}));
    writeln!(
        &mut out,
        "Session {} on {}",
        get_str(report, "session_id"),
        get_str(report, "project_root")
    )?;
    writeln!(
        &mut out,
        "Totals: {} tokens, {} turns, {} events, cache read {:.1}%",
        get_i64(&totals, "total_tokens"),
        get_i64(report, "turns"),
        get_i64(report, "events"),
        get_f64(&totals, "cache_read_pct"),
    )?;
    writeln!(
        &mut out,
        "Prompts: {} prompts, {} chars total, {:.0} chars average",
        get_i64(&prompts, "prompt_count"),
        get_i64(&prompts, "total_prompt_chars"),
        get_f64(&prompts, "average_prompt_chars"),
    )?;

    let findings = report
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !findings.is_empty() {
        writeln!(&mut out, "\nFindings:")?;
        for finding in findings {
            writeln!(
                &mut out,
                "- [{}] {}: {}",
                get_str(&finding, "severity"),
                get_str(&finding, "title"),
                get_str(&finding, "detail")
            )?;
        }
    }

    let recommendations = report
        .get("recommendations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !recommendations.is_empty() {
        writeln!(&mut out, "\nRecommendations:")?;
        for recommendation in recommendations {
            writeln!(
                &mut out,
                "- [{}] {}: {}",
                get_str(&recommendation, "priority"),
                get_str(&recommendation, "summary"),
                get_str(&recommendation, "detail")
            )?;
        }
    }

    Ok(out.trim_end().to_string())
}

fn history_artifact_path(store: &SherlockStore, session_id: &str) -> Result<Option<PathBuf>> {
    let rows = store.query_rows(&format!(
        "SELECT path_or_key FROM artifacts \
         WHERE session_id='{}' AND artifact_type='history_jsonl' \
         ORDER BY captured_at DESC LIMIT 1",
        sql(session_id)
    ))?;
    Ok(rows
        .first()
        .map(|row| PathBuf::from(get_str(row, "path_or_key")))
        .filter(|path| !path.as_os_str().is_empty()))
}

fn check_plugin_thresholds(
    report: &Value,
    share_threshold: Option<f64>,
    token_threshold: Option<i64>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let plugin_sources = report
        .get("plugin_sources")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let grand_total = report
        .get("session_totals")
        .and_then(|t| t.get("total_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);

    for src in &plugin_sources {
        let plugin_id = get_str(src, "plugin_id");
        if plugin_id.is_empty() {
            continue;
        }
        let est = get_i64(src, "estimated_tokens");
        if let Some(thresh) = token_threshold {
            if est > thresh {
                warnings.push(format!(
                    "plugin '{}' spent {} tokens (threshold: {})",
                    plugin_id, est, thresh
                ));
            }
        }
        if let Some(share) = share_threshold {
            if grand_total > 0 {
                let actual_share = est as f64 / grand_total as f64;
                if actual_share > share {
                    warnings.push(format!(
                        "plugin '{}' used {:.1}% of session spend (threshold: {:.1}%)",
                        plugin_id,
                        actual_share * 100.0,
                        share * 100.0
                    ));
                }
            }
        }
    }

    // Also check top_sources with non-empty tool names as "plugin-equivalent"
    // spend when no explicit plugin_id exists.
    let top_sources = report
        .get("top_sources")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for src in &top_sources {
        let plugin_id = get_str(src, "plugin_id");
        if !plugin_id.is_empty() {
            continue; // already covered above
        }
        let tool = get_str(src, "tool_name");
        if tool.is_empty() {
            continue;
        }
        let est = get_i64(src, "estimated_tokens");
        if let Some(thresh) = token_threshold {
            if est > thresh {
                warnings.push(format!(
                    "tool '{}' spent {} tokens (threshold: {})",
                    tool, est, thresh
                ));
            }
        }
        if let Some(share) = share_threshold {
            if grand_total > 0 {
                let actual_share = est as f64 / grand_total as f64;
                if actual_share > share {
                    warnings.push(format!(
                        "tool '{}' used {:.1}% of session spend (threshold: {:.1}%)",
                        tool,
                        actual_share * 100.0,
                        share * 100.0
                    ));
                }
            }
        }
    }
    warnings
}

fn rollup_report(
    store: &SherlockStore,
    group_by: &str,
    since: Option<&str>,
    provider_filter: Option<&str>,
    top: usize,
) -> Result<Value> {
    let group_col = match group_by {
        "plugin" => "COALESCE(NULLIF(s.plugin_id, ''), NULLIF(s.tool_name, ''), s.source_kind)",
        "tool" => "COALESCE(NULLIF(s.tool_name, ''), s.source_kind)",
        "provider" => "COALESCE(sess.provider, 'claude-code')",
        other => return Err(anyhow!("unknown --group-by value: {other} (expected: plugin, tool, provider)")),
    };

    // Resolve sessions via a robust timestamp check (sherlock-ed0): compare
    // started_at, ended_at, latest windows.end_time, and latest event_time with
    // parse_ts_epoch so malformed iso_now() legacy strings still filter right.
    let mut wheres: Vec<String> = Vec::new();
    if let Some(prov) = provider_filter {
        wheres.push(format!(
            "COALESCE(sess.provider,'claude-code') = '{}'",
            sql(prov)
        ));
    }
    if since.is_some() {
        let (_, since_epoch) = parse_since_expr(since.unwrap())?;
        let ids = session_ids_in_window(store, None, provider_filter, since_epoch)?;
        if ids.is_empty() {
            return Ok(json!({
                "group_by": group_by,
                "since": since,
                "provider_filter": provider_filter,
                "total_sessions": 0,
                "grand_total_tokens": 0,
                "entries": [],
            }));
        }
        wheres.push(format!("sess.session_id IN ({})", sql_in_list(&ids)));
    }
    let where_clause = if wheres.is_empty() {
        String::new()
    } else {
        format!("AND {}", wheres.join(" AND "))
    };

    // Total tokens across all matching sessions (for percentage calculation).
    let grand_total_rows = store.query_rows(&format!(
        "SELECT COALESCE(SUM(t.input_tokens_cum + t.output_tokens_cum + t.cache_read_tokens_cum + t.cache_write_tokens_cum), 0) AS grand_total \
         FROM (SELECT session_id, MAX(input_tokens_cum) AS input_tokens_cum, MAX(output_tokens_cum) AS output_tokens_cum, \
               MAX(cache_read_tokens_cum) AS cache_read_tokens_cum, MAX(cache_write_tokens_cum) AS cache_write_tokens_cum \
               FROM turns GROUP BY session_id) t \
         JOIN sessions sess ON t.session_id = sess.session_id \
         WHERE 1=1 {where_clause}"
    ))?;
    let grand_total = grand_total_rows
        .first()
        .map(|r| get_i64(r, "grand_total"))
        .unwrap_or(0);

    // Per-group rollup: estimate tokens using cumulative-difference method
    // across all matching sessions, then count events.
    let query = format!(
        "SELECT {group_col} AS group_key, \
         COUNT(*) AS event_count, \
         COUNT(DISTINCT e.session_id) AS session_count \
         FROM events e \
         JOIN sources s ON e.source_id = s.source_id \
         JOIN sessions sess ON e.session_id = sess.session_id \
         WHERE 1=1 {where_clause} \
         GROUP BY group_key \
         ORDER BY event_count DESC \
         LIMIT {top}"
    );
    let rows = store.query_rows(&query)?;

    // For token estimation we need the source_token_totals path across all
    // matching sessions.  Build a cross-session source→token map.
    let token_query = format!(
        "SELECT {group_col} AS group_key, \
         e.source_id, t.turn_index, \
         t.input_tokens_cum, t.output_tokens_cum, \
         t.cache_read_tokens_cum, t.cache_write_tokens_cum, \
         e.session_id \
         FROM events e \
         JOIN sources s ON e.source_id = s.source_id \
         JOIN turns t ON e.turn_id = t.turn_id \
         JOIN sessions sess ON e.session_id = sess.session_id \
         WHERE 1=1 {where_clause} \
         ORDER BY e.session_id, t.turn_index ASC"
    );
    let token_rows = store.query_rows(&token_query)?;

    // Cumulative-difference per session, then sum into group buckets.
    let mut group_tokens: HashMap<String, i64> = HashMap::new();
    let mut prev_total: i64 = 0;
    let mut prev_session = String::new();
    for row in &token_rows {
        let sess = get_str(row, "session_id");
        if sess != prev_session {
            prev_total = 0;
            prev_session = sess;
        }
        let total = get_i64(row, "input_tokens_cum")
            + get_i64(row, "output_tokens_cum")
            + get_i64(row, "cache_read_tokens_cum")
            + get_i64(row, "cache_write_tokens_cum");
        let delta = (total - prev_total).max(0);
        prev_total = total;
        let group_key = get_str(row, "group_key");
        *group_tokens.entry(group_key).or_insert(0) += delta;
    }

    let mut entries: Vec<Value> = rows
        .iter()
        .map(|row| {
            let key = get_str(row, "group_key");
            let estimated_tokens = group_tokens.get(&key).copied().unwrap_or(0);
            let pct = if grand_total > 0 {
                (estimated_tokens as f64 * 100.0) / grand_total as f64
            } else {
                0.0
            };
            json!({
                "group": key,
                "estimated_tokens": estimated_tokens,
                "estimated_pct": (pct * 100.0).round() / 100.0,
                "event_count": get_i64(row, "event_count"),
                "session_count": get_i64(row, "session_count"),
            })
        })
        .collect();
    entries.sort_by(|a, b| {
        get_i64(b, "estimated_tokens")
            .cmp(&get_i64(a, "estimated_tokens"))
            .then_with(|| get_i64(b, "event_count").cmp(&get_i64(a, "event_count")))
    });
    entries.truncate(top);

    let session_count_rows = store.query_rows(&format!(
        "SELECT COUNT(*) AS c FROM sessions sess WHERE 1=1 {where_clause}"
    ))?;
    let total_sessions = session_count_rows
        .first()
        .map(|r| get_i64(r, "c"))
        .unwrap_or(0);

    Ok(json!({
        "group_by": group_by,
        "since": since,
        "provider_filter": provider_filter,
        "total_sessions": total_sessions,
        "grand_total_tokens": grand_total,
        "entries": entries,
    }))
}

fn render_rollup_table(report: &Value, group_by: &str) -> Result<String> {
    let entries = report
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing entries in rollup report"))?;
    let total_sessions = get_i64(report, "total_sessions");
    let grand_total = get_i64(report, "grand_total_tokens");

    let mut out = String::new();
    out.push_str(&format!(
        "Rollup by {group_by} — {total_sessions} sessions, {grand_total} total tokens\n"
    ));
    if let Some(since) = report.get("since").and_then(Value::as_str) {
        out.push_str(&format!("Since: {since}\n"));
    }
    if let Some(prov) = report.get("provider_filter").and_then(Value::as_str) {
        out.push_str(&format!("Provider: {prov}\n"));
    }
    out.push('\n');

    let col_w = entries
        .iter()
        .map(|e| get_str(e, "group").len())
        .max()
        .unwrap_or(10)
        .max(group_by.len())
        .min(60);
    out.push_str(&format!(
        "{:<col_w$}  {:>14}  {:>7}  {:>8}  {:>8}\n",
        group_by, "tokens", "pct", "events", "sessions"
    ));
    out.push_str(&format!(
        "{:-<col_w$}  {:->14}  {:->7}  {:->8}  {:->8}\n",
        "", "", "", "", ""
    ));
    for entry in entries {
        let group = get_str(entry, "group");
        let display = if group.len() > col_w {
            format!("{}…", &group[..col_w - 1])
        } else {
            group
        };
        out.push_str(&format!(
            "{:<col_w$}  {:>14}  {:>6.1}%  {:>8}  {:>8}\n",
            display,
            get_i64(entry, "estimated_tokens"),
            get_f64(entry, "estimated_pct"),
            get_i64(entry, "event_count"),
            get_i64(entry, "session_count"),
        ));
    }
    Ok(out)
}

fn workflow_tool_tokens(provider: &dyn Provider, sources: &[SourceFact]) -> i64 {
    sources
        .iter()
        .filter(|source| provider.is_workflow_tool(&source.tool_name))
        .map(|source| source.estimated_tokens)
        .sum()
}

fn top_label_counts(counts: &HashMap<String, i64>, limit: usize) -> Vec<LabelCount> {
    let mut items = counts
        .iter()
        .map(|(label, count)| LabelCount {
            label: label.clone(),
            count: *count,
        })
        .collect::<Vec<_>>();
    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.label.cmp(&b.label)));
    items.into_iter().take(limit).collect()
}

fn excerpt(text: &str, limit: usize) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= limit {
        collapsed
    } else {
        let mut shortened = collapsed.chars().take(limit).collect::<String>();
        shortened.push('…');
        shortened
    }
}

fn pct(part: i64, total: i64) -> f64 {
    if total > 0 {
        (part as f64 * 100.0) / total as f64
    } else {
        0.0
    }
}

fn resolve_session_or_alias(store: &SherlockStore, session_or_alias: &str) -> Result<String> {
    // First try as alias
    let rows = store.query_rows(&format!(
        "SELECT session_id FROM session_aliases WHERE alias='{}'",
        sql(session_or_alias)
    ))?;
    if let Some(row) = rows.first() {
        return Ok(get_str(row, "session_id"));
    }
    // If not found as alias, return as-is (assume it's a session_id)
    Ok(session_or_alias.to_string())
}

fn resolve_session_id(store: &SherlockStore, session_id: Option<String>) -> Result<String> {
    if let Some(sid) = session_id {
        // Resolve alias if provided
        return resolve_session_or_alias(store, &sid);
    }
    let rows =
        store.query_rows("SELECT session_id FROM sessions ORDER BY ended_at DESC LIMIT 1")?;
    let sid = rows
        .first()
        .and_then(|r| r.get("session_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("no sessions found; run sherlock ingest first"))?;
    Ok(sid.to_string())
}

fn resolve_session_id_with_picker(
    store: &SherlockStore,
    session_id: Option<String>,
) -> Result<String> {
    if session_id.is_some() {
        return resolve_session_id(store, session_id);
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let rows = session_candidates(store, 20)?;
    if rows.is_empty() {
        return Err(anyhow!("no sessions found; run sherlock ingest first"));
    }
    let preferred_idx = preferred_session_index(&rows, &cwd).unwrap_or(0);
    if !stdout().is_terminal() || rows.len() == 1 {
        return Ok(get_str(&rows[preferred_idx], "session_id"));
    }
    select_session_interactive(&rows, preferred_idx)
}

fn session_candidates(store: &SherlockStore, limit: usize) -> Result<Vec<Value>> {
    store.query_rows(&format!(
        "SELECT s.session_id, COALESCE(s.ended_at, s.started_at, '') AS ts, COALESCE(s.project_root, '') AS project_root, \
         COALESCE((SELECT MAX(t.input_tokens_cum + t.output_tokens_cum + t.cache_read_tokens_cum + t.cache_write_tokens_cum) \
                   FROM turns t WHERE t.session_id=s.session_id), 0) AS total_tokens \
         FROM sessions s ORDER BY COALESCE(s.ended_at, s.started_at) DESC LIMIT {}",
        limit
    ))
}

fn select_session_interactive(rows: &[Value], preferred_idx: usize) -> Result<String> {
    let _ = disable_raw_mode();
    println!("Select a session (default marked with *):");
    for (i, row) in rows.iter().enumerate() {
        let sid = get_str(row, "session_id");
        let ts = get_str(row, "ts");
        let project = get_str(row, "project_root");
        let total = get_i64(row, "total_tokens");
        let marker = if i == preferred_idx { "*" } else { " " };
        println!(
            " {} {}) {}  ts={}  total_tokens={}  project={}",
            marker,
            i + 1,
            sid,
            ts,
            total,
            project
        );
    }
    println!(
        "Pick [1-{}] (Enter for {}): ",
        rows.len(),
        preferred_idx + 1
    );
    use std::io::{self, Write};
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let first_line = input.trim();
    let idx = if first_line.is_empty() {
        preferred_idx
    } else {
        first_line
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .filter(|n| *n < rows.len())
            .unwrap_or(preferred_idx)
    };
    Ok(get_str(&rows[idx], "session_id"))
}

fn preferred_session_index(rows: &[Value], cwd: &Path) -> Option<usize> {
    let cwd_s = cwd.to_string_lossy();

    // Best: same project and has token data
    if let Some((idx, _)) = rows
        .iter()
        .enumerate()
        .find(|(_, row)| get_str(row, "project_root") == cwd_s && get_i64(row, "total_tokens") > 0)
    {
        return Some(idx);
    }

    // Next: same project (even if zero)
    if let Some((idx, _)) = rows
        .iter()
        .enumerate()
        .find(|(_, row)| get_str(row, "project_root") == cwd_s)
    {
        return Some(idx);
    }

    // Next: any session with token data
    if let Some((idx, _)) = rows
        .iter()
        .enumerate()
        .find(|(_, row)| get_i64(row, "total_tokens") > 0)
    {
        return Some(idx);
    }

    // Fallback: first row
    Some(0)
}

fn resolve_ingest_session_id(
    provider: &dyn Provider,
    history_path: &Path,
    provided: Option<String>,
) -> Result<String> {
    if let Some(sid) = provided {
        return Ok(sid);
    }
    let raw = fs::read_to_string(history_path).unwrap_or_default();
    let mut best: Option<(i64, String)> = None;
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let obj: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ev = RawEvent::Json(obj);
        let sid = match provider.extract_session_id(&ev) {
            Some(v) => v,
            None => continue,
        };
        let ts = provider.event_time_epoch(&ev).unwrap_or(0);
        match &best {
            Some((cur_ts, _)) if *cur_ts >= ts => {}
            _ => best = Some((ts, sid)),
        }
    }
    Ok(best.map(|(_, sid)| sid).unwrap_or_else(new_session_id))
}

fn resolve_history_path(provided: Option<PathBuf>, project_root: &Path) -> Result<PathBuf> {
    if let Some(path) = provided {
        return Ok(path);
    }
    if let Some(path) = latest_project_session_file(project_root) {
        return Ok(path);
    }
    if let Some(path) = latest_any_project_session_file() {
        return Ok(path);
    }
    Ok(default_history())
}

fn latest_project_session_file(project_root: &Path) -> Option<PathBuf> {
    let dir = default_projects_root().join(project_key(project_root));
    latest_jsonl_in_dir(&dir)
}

fn latest_any_project_session_file() -> Option<PathBuf> {
    let root = default_projects_root();
    let entries = fs::read_dir(root).ok()?;
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if let Some(candidate) = latest_jsonl_in_dir(&path) {
            let modified = fs::metadata(&candidate)
                .ok()
                .and_then(|m| m.modified().ok())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            match &best {
                Some((cur, _)) if *cur >= modified => {}
                _ => best = Some((modified, candidate)),
            }
        }
    }
    best.map(|(_, p)| p)
}

fn latest_jsonl_in_dir(dir: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
            continue;
        }
        let modified = fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        match &best {
            Some((cur, _)) if *cur >= modified => {}
            _ => best = Some((modified, path)),
        }
    }
    best.map(|(_, p)| p)
}

fn project_key(project_root: &Path) -> String {
    project_root.to_string_lossy().replace('/', "-")
}

fn run_tui(store: &SherlockStore, session_id: &str) -> Result<()> {
    println!("Launching Sherlock TUI for session `{session_id}`.");
    let session = summarize_session(store, session_id)?;
    let totals_rows = store.query_rows(&format!(
        "SELECT \
         COALESCE(MAX(input_tokens_cum),0) AS input_tokens, \
         COALESCE(MAX(output_tokens_cum),0) AS output_tokens, \
         COALESCE(MAX(cache_read_tokens_cum),0) AS cache_read_tokens, \
         COALESCE(MAX(cache_write_tokens_cum),0) AS cache_write_tokens \
         FROM turns WHERE session_id='{}'",
        sql(session_id)
    ))?;
    let totals = totals_rows.first().cloned().unwrap_or_else(|| json!({}));
    let top_sources = store.query_rows(&format!(
        "SELECT e.source_id, s.source_kind, COALESCE(s.plugin_id, '') AS plugin_id, COALESCE(s.tool_name, '') AS tool_name, COALESCE(s.hook_name, '') AS hook_name, COUNT(*) AS event_count \
         FROM events e JOIN sources s ON e.source_id=s.source_id \
         WHERE e.session_id='{}' \
         GROUP BY e.source_id, s.source_kind, s.plugin_id, s.tool_name, s.hook_name \
         ORDER BY event_count DESC LIMIT 8",
        sql(session_id)
    ))?;
    let source_tokens = source_token_totals(store, session_id)?;
    let spikes = store.query_rows(&format!(
        "SELECT start_time, end_time, reason, COALESCE(delta_tokens,0) AS delta_tokens \
         FROM windows WHERE session_id='{}' ORDER BY delta_tokens DESC LIMIT 8",
        sql(session_id)
    ))?;

    enable_raw_mode()?;
    execute!(stdout(), cursor::Hide)?;
    execute!(stdout(), EnterAlternateScreen)?;
    let _guard = TerminalGuard;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(7),
                    Constraint::Min(8),
                    Constraint::Min(8),
                ])
                .split(f.area());

            let title = format!("Sherlock TUI  session={}  (press q to quit)", session_id);
            f.render_widget(
                Paragraph::new(title).block(Block::default().borders(Borders::ALL).title("Header")),
                chunks[0],
            );

            let turns = get_i64(&session, "turns");
            let events = get_i64(&session, "events");
            let windows = get_i64(&session, "windows");
            let input = get_i64(&totals, "input_tokens");
            let output = get_i64(&totals, "output_tokens");
            let cache_read = get_i64(&totals, "cache_read_tokens");
            let cache_write = get_i64(&totals, "cache_write_tokens");
            let summary = format!(
                "turns: {turns}   events: {events}   windows: {windows}\ninput: {input}   output: {output}\ncache_read: {cache_read}   cache_write: {cache_write}"
            );
            f.render_widget(
                Paragraph::new(summary).block(Block::default().borders(Borders::ALL).title("Summary")),
                chunks[1],
            );

            let source_rows: Vec<Row> = top_sources
                .iter()
                .map(|r| {
                    Row::new(vec![
                        Cell::from(get_str(r, "source_kind")),
                        Cell::from(get_str(r, "tool_name")),
                        Cell::from(get_str(r, "plugin_id")),
                        Cell::from(get_str(r, "hook_name")),
                        Cell::from(
                            source_tokens
                                .get(&get_str(r, "source_id"))
                                .copied()
                                .unwrap_or(0)
                                .to_string(),
                        ),
                    ])
                })
                .collect();
            let source_table = Table::new(
                source_rows,
                [
                    Constraint::Length(10),
                    Constraint::Length(18),
                    Constraint::Length(18),
                    Constraint::Length(18),
                    Constraint::Length(14),
                ],
            )
            .header(
                Row::new(vec!["kind", "tool", "plugin", "hook", "est_tokens"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .block(Block::default().borders(Borders::ALL).title("Top Sources"));
            f.render_widget(source_table, chunks[2]);

            let spike_rows: Vec<Row> = if spikes.is_empty() {
                vec![Row::new(vec![
                    Cell::from("n/a"),
                    Cell::from("n/a"),
                    Cell::from("no spike windows detected"),
                    Cell::from("0"),
                ])]
            } else {
                spikes
                    .iter()
                    .map(|r| {
                        Row::new(vec![
                            Cell::from(get_str(r, "start_time")),
                            Cell::from(get_str(r, "end_time")),
                            Cell::from(get_str(r, "reason")),
                            Cell::from(get_i64(r, "delta_tokens").to_string()),
                        ])
                    })
                    .collect()
            };
            let spike_table = Table::new(
                spike_rows,
                [
                    Constraint::Length(14),
                    Constraint::Length(14),
                    Constraint::Length(18),
                    Constraint::Length(14),
                ],
            )
            .header(
                Row::new(vec!["start", "end", "reason", "delta_tokens"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .block(Block::default().borders(Borders::ALL).title("Suspect Windows"));
            f.render_widget(spike_table, chunks[3]);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) {
                    break;
                }
            }
        }
    }

    Ok(())
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), cursor::Show);
        let _ = execute!(stdout(), LeaveAlternateScreen);
    }
}

fn get_i64(row: &Value, key: &str) -> i64 {
    row.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn get_f64(row: &Value, key: &str) -> f64 {
    row.get(key).and_then(Value::as_f64).unwrap_or(0.0)
}

fn get_str(row: &Value, key: &str) -> String {
    row.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn source_kind(event_type: &str) -> &'static str {
    if event_type.starts_with("hook") {
        "hook"
    } else if event_type == "tool_call" {
        "tool"
    } else {
        "core"
    }
}

fn sql(s: &str) -> String {
    s.replace('\'', "''")
}

fn sql_opt(v: &Option<String>) -> String {
    match v {
        Some(s) if !s.is_empty() => format!("'{}'", sql(s)),
        _ => "NULL".to_string(),
    }
}

fn source_token_totals(store: &SherlockStore, session_id: &str) -> Result<HashMap<String, i64>> {
    let rows = store.query_rows(&format!(
        "SELECT e.source_id, t.turn_index, t.input_tokens_cum, t.output_tokens_cum, t.cache_read_tokens_cum, t.cache_write_tokens_cum \
         FROM events e JOIN turns t ON e.turn_id=t.turn_id \
         WHERE e.session_id='{}' ORDER BY t.turn_index ASC",
        sql(session_id)
    ))?;
    let mut prev_total = 0i64;
    let mut out: HashMap<String, i64> = HashMap::new();
    for row in rows {
        let total = get_i64(&row, "input_tokens_cum")
            + get_i64(&row, "output_tokens_cum")
            + get_i64(&row, "cache_read_tokens_cum")
            + get_i64(&row, "cache_write_tokens_cum");
        let delta = (total - prev_total).max(0);
        prev_total = total;
        let sid = get_str(&row, "source_id");
        *out.entry(sid).or_insert(0) += delta;
    }
    Ok(out)
}

fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn sha1_short(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    format!("{:x}", hasher.finalize())[..12].to_string()
}

fn short_id(prefix: &str) -> String {
    format!(
        "{}-{}",
        prefix,
        Uuid::new_v4().simple().to_string()[..12].to_string()
    )
}

fn new_session_id() -> String {
    short_id("session")
}

fn iso_now() -> String {
    // Proper RFC3339/ISO8601 so lexicographic string compares in SQL line up
    // with wall-clock order (the old epoch-seconds+Z form broke `>=` filters
    // against ISO-formatted thresholds — see bug sherlock-ed0).
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Parse a timestamp value (from session.started_at/ended_at, event_time,
/// windows.*_time) into epoch seconds. Tolerates:
/// - RFC3339 ("2026-04-20T01:02:03Z", with or without fractional seconds)
/// - Legacy Sherlock epoch-Z form ("1776361213Z")
/// - Bare integer strings ("1776361213")
/// - Millisecond epochs (auto-detected by magnitude, divided by 1000)
/// Returns None when nothing parseable remains.
fn parse_ts_epoch(s: &str) -> Option<i64> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    let stripped = trimmed.trim_end_matches('Z');
    if let Ok(n) = stripped.parse::<i64>() {
        // Heuristic: anything > ~11 digits is ms-since-epoch, not seconds.
        let normalized = if n > 9_999_999_999 { n / 1000 } else { n };
        return Some(normalized);
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.timestamp());
    }
    for fmt in &["%Y-%m-%dT%H:%M:%S%.fZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"] {
        if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(trimmed, fmt) {
            return Some(ndt.and_utc().timestamp());
        }
        if let Ok(nd) = chrono::NaiveDate::parse_from_str(trimmed, fmt) {
            if let Some(ndt) = nd.and_hms_opt(0, 0, 0) {
                return Some(ndt.and_utc().timestamp());
            }
        }
    }
    None
}

/// Parse a user-supplied `--since`/`--modified-since` expression into
/// (canonical ISO8601, epoch seconds). Accepts:
/// - ISO date (2026-04-16) or full RFC3339
/// - Relative: `today`, `yesterday`, `Nd`/`Nw`/`Nh`/`Nm` (e.g. `7d`, `2w`)
/// - Weekday names: `sunday`..`saturday` (most recent past occurrence,
///   inclusive of today if today matches)
fn parse_since_expr(expr: &str) -> Result<(String, i64)> {
    let raw = expr.trim().to_lowercase();
    let now = chrono::Utc::now();
    let today = now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc();

    let resolved: chrono::DateTime<chrono::Utc> = match raw.as_str() {
        "today" | "now" => today,
        "yesterday" => today - chrono::Duration::days(1),
        s if s.ends_with('d') => {
            let n: i64 = s.trim_end_matches('d').parse()
                .map_err(|_| anyhow!("bad --since days: {expr}"))?;
            now - chrono::Duration::days(n)
        }
        s if s.ends_with('w') => {
            let n: i64 = s.trim_end_matches('w').parse()
                .map_err(|_| anyhow!("bad --since weeks: {expr}"))?;
            now - chrono::Duration::weeks(n)
        }
        s if s.ends_with('h') => {
            let n: i64 = s.trim_end_matches('h').parse()
                .map_err(|_| anyhow!("bad --since hours: {expr}"))?;
            now - chrono::Duration::hours(n)
        }
        s if s.ends_with('m')
            && s.trim_end_matches('m').chars().all(|c| c.is_ascii_digit()) =>
        {
            let n: i64 = s.trim_end_matches('m').parse()
                .map_err(|_| anyhow!("bad --since minutes: {expr}"))?;
            now - chrono::Duration::minutes(n)
        }
        s => {
            let weekday = match s {
                "sunday" | "sun" => Some(chrono::Weekday::Sun),
                "monday" | "mon" => Some(chrono::Weekday::Mon),
                "tuesday" | "tue" | "tues" => Some(chrono::Weekday::Tue),
                "wednesday" | "wed" => Some(chrono::Weekday::Wed),
                "thursday" | "thu" | "thur" | "thurs" => Some(chrono::Weekday::Thu),
                "friday" | "fri" => Some(chrono::Weekday::Fri),
                "saturday" | "sat" => Some(chrono::Weekday::Sat),
                _ => None,
            };
            if let Some(wd) = weekday {
                use chrono::Datelike;
                let today_wd = today.weekday().num_days_from_monday() as i64;
                let want_wd = wd.num_days_from_monday() as i64;
                let delta = ((today_wd - want_wd) + 7) % 7;
                today - chrono::Duration::days(delta)
            } else if let Some(ts) = parse_ts_epoch(s) {
                chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
                    .ok_or_else(|| anyhow!("bad --since timestamp: {expr}"))?
            } else {
                return Err(anyhow!(
                    "unrecognized --since value `{expr}` (try YYYY-MM-DD, 7d, sunday, yesterday)"
                ));
            }
        }
    };
    Ok((
        resolved.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        resolved.timestamp(),
    ))
}

/// Walk a root looking for `.git` directories, bounded in depth. Skips common
/// vendored trees so big monorepos stay snappy.
fn find_git_repos(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let skip: &[&str] = &[
        "node_modules", "target", ".cargo", ".venv", "venv", "__pycache__",
        "dist", "build", ".next", ".nuxt", ".pnpm-store", ".yarn",
    ];
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if dir.join(".git").exists() {
            out.push(dir);
            continue;
        }
        if depth >= max_depth {
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name.starts_with('.') && name != "." && name != ".." {
                continue;
            }
            if skip.contains(&name) {
                continue;
            }
            stack.push((path, depth + 1));
        }
    }
    out
}

/// A git repo is "modified since X" if it has commits since X (on any ref) OR
/// a non-empty working tree. Cheap: two `git` calls.
fn repo_modified_since(repo: &Path, since_iso: &str) -> bool {
    // --all: consider every local ref, not just HEAD.
    let log = Command::new("git")
        .args([
            "-C",
            repo.to_string_lossy().as_ref(),
            "log",
            "--all",
            "--since",
            since_iso,
            "--format=%H",
            "-n",
            "1",
        ])
        .output();
    if let Ok(out) = log {
        if out.status.success() && !out.stdout.trim_ascii().is_empty() {
            return true;
        }
    }
    let status = Command::new("git")
        .args([
            "-C",
            repo.to_string_lossy().as_ref(),
            "status",
            "--porcelain",
        ])
        .output();
    if let Ok(out) = status {
        if out.status.success() && !out.stdout.trim_ascii().is_empty() {
            return true;
        }
    }
    false
}

/// All repos under the given roots that have activity since `since_iso`.
/// Deduplicated and canonicalized.
fn discover_modified_repos(roots: &[PathBuf], since_iso: &str) -> Vec<PathBuf> {
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut out: Vec<PathBuf> = Vec::new();
    for root in roots {
        let expanded = if root.starts_with("~") {
            let home = PathBuf::from(std::env::var("HOME").unwrap_or_default());
            let rest: PathBuf = root.strip_prefix("~").unwrap_or(root).to_path_buf();
            home.join(rest)
        } else {
            root.clone()
        };
        for repo in find_git_repos(&expanded, 4) {
            let canon = repo.canonicalize().unwrap_or(repo);
            if !seen.insert(canon.clone()) {
                continue;
            }
            if repo_modified_since(&canon, since_iso) {
                out.push(canon);
            }
        }
    }
    out.sort();
    out
}

/// List Claude Code JSONL history files for a given project_root, filtered by
/// file mtime >= since_epoch. Returns in deterministic order.
fn repo_history_files(project_root: &Path, since_epoch: i64) -> Vec<PathBuf> {
    let dir = default_projects_root().join(project_key(project_root));
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
            continue;
        }
        let mtime_epoch = fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if mtime_epoch >= since_epoch {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// Pick session_ids for a given project_root that fall inside the window, using
/// a robust timestamp check: compare started_at, ended_at, and the max
/// windows.end_time with parse_ts_epoch. This is what makes the filter tolerant
/// of malformed session timestamps (sherlock-ed0).
fn session_ids_in_window(
    store: &SherlockStore,
    project_root: Option<&Path>,
    provider: Option<&str>,
    since_epoch: i64,
) -> Result<Vec<String>> {
    let mut wheres: Vec<String> = Vec::new();
    if let Some(root) = project_root {
        wheres.push(format!(
            "s.project_root = '{}'",
            sql(&root.to_string_lossy())
        ));
    }
    if let Some(prov) = provider {
        wheres.push(format!(
            "COALESCE(s.provider,'claude-code') = '{}'",
            sql(prov)
        ));
    }
    let where_clause = if wheres.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", wheres.join(" AND "))
    };
    let rows = store.query_rows(&format!(
        "SELECT s.session_id, s.started_at, s.ended_at, \
         (SELECT MAX(w.end_time) FROM windows w WHERE w.session_id = s.session_id) AS max_window_end, \
         (SELECT MAX(e.event_time) FROM events e WHERE e.session_id = s.session_id) AS max_event_time \
         FROM sessions s {where_clause}"
    ))?;
    let mut out: Vec<String> = Vec::new();
    for row in rows {
        let candidates = [
            get_str(&row, "started_at"),
            get_str(&row, "ended_at"),
            get_str(&row, "max_window_end"),
            get_str(&row, "max_event_time"),
        ];
        let best = candidates
            .iter()
            .filter_map(|s| parse_ts_epoch(s))
            .max();
        if let Some(ts) = best {
            if ts >= since_epoch {
                out.push(get_str(&row, "session_id"));
            }
        }
    }
    Ok(out)
}

fn sql_in_list(ids: &[String]) -> String {
    if ids.is_empty() {
        return "''".to_string();
    }
    ids.iter()
        .map(|s| format!("'{}'", sql(s)))
        .collect::<Vec<_>>()
        .join(",")
}

fn headline_report(
    store: &SherlockStore,
    roots: &[PathBuf],
    modified_since_iso: &str,
    _modified_since_epoch: i64,
    window_since_iso: &str,
    window_since_epoch: i64,
    provider: &str,
    top: usize,
    skip_ingest: bool,
    commit: bool,
) -> Result<Value> {
    let repos = discover_modified_repos(roots, modified_since_iso);
    let mut ingest_errors: Vec<String> = Vec::new();
    let mut ingested_files: usize = 0;

    if !skip_ingest {
        let provider_box: Box<dyn Provider> = providers::by_id(provider)
            .ok_or_else(|| anyhow!("unknown provider: {provider}"))?;
        for repo in &repos {
            for hist in repo_history_files(repo, window_since_epoch) {
                let sha = sha256_hex(&fs::read_to_string(&hist).unwrap_or_default());
                let already = store
                    .query_rows(&format!(
                        "SELECT sha256 FROM artifacts WHERE path_or_key='{}' AND sha256='{}' LIMIT 1",
                        sql(&hist.to_string_lossy()),
                        sql(&sha)
                    ))
                    .unwrap_or_default();
                if !already.is_empty() {
                    continue;
                }
                let sid = match resolve_ingest_session_id(&*provider_box, &hist, None) {
                    Ok(s) => s,
                    Err(e) => {
                        ingest_errors.push(format!("{}: {}", hist.display(), e));
                        continue;
                    }
                };
                let branch = git_branch(repo).unwrap_or_default();
                match ingest_session(
                    store,
                    &*provider_box,
                    &hist,
                    &sid,
                    repo,
                    &branch,
                    "",
                ) {
                    Ok(_) => ingested_files += 1,
                    Err(e) => ingest_errors.push(format!("{}: {}", hist.display(), e)),
                }
            }
        }
        if commit && ingested_files > 0 {
            store.commit(&format!(
                "sherlock: headline ingest ({} files)",
                ingested_files
            ))?;
        }
    }

    let mut repo_entries: Vec<Value> = Vec::new();
    let mut global_total: i64 = 0;
    let mut global_input: i64 = 0;
    let mut global_output: i64 = 0;
    let mut global_cache_read: i64 = 0;
    let mut global_cache_write: i64 = 0;
    let mut repos_with_usage: i64 = 0;
    let mut total_malformed_ts: i64 = 0;

    for repo in &repos {
        let session_ids =
            session_ids_in_window(store, Some(repo), Some(provider), window_since_epoch)?;
        if session_ids.is_empty() {
            repo_entries.push(json!({
                "project_root": repo.display().to_string(),
                "sessions_in_window": 0,
                "total_tokens": 0,
                "top_sources": [],
            }));
            continue;
        }
        repos_with_usage += 1;
        let in_list = sql_in_list(&session_ids);

        let malformed_count = store
            .query_rows(&format!(
                "SELECT COUNT(*) AS c FROM sessions WHERE session_id IN ({in_list}) \
                 AND (started_at IS NULL OR started_at NOT LIKE '____-__-__T%')"
            ))
            .ok()
            .and_then(|r| r.first().map(|row| get_i64(row, "c")))
            .unwrap_or(0);
        total_malformed_ts += malformed_count;

        let totals_rows = store.query_rows(&format!(
            "SELECT \
             COALESCE(SUM(mi.input_tokens_cum),0) AS input_tokens, \
             COALESCE(SUM(mi.output_tokens_cum),0) AS output_tokens, \
             COALESCE(SUM(mi.cache_read_tokens_cum),0) AS cache_read_tokens, \
             COALESCE(SUM(mi.cache_write_tokens_cum),0) AS cache_write_tokens \
             FROM (SELECT session_id, \
                   MAX(input_tokens_cum) AS input_tokens_cum, \
                   MAX(output_tokens_cum) AS output_tokens_cum, \
                   MAX(cache_read_tokens_cum) AS cache_read_tokens_cum, \
                   MAX(cache_write_tokens_cum) AS cache_write_tokens_cum \
                   FROM turns WHERE session_id IN ({in_list}) \
                   GROUP BY session_id) mi"
        ))?;
        let totals = totals_rows.first().cloned().unwrap_or_else(|| json!({}));
        let input = get_i64(&totals, "input_tokens");
        let output = get_i64(&totals, "output_tokens");
        let cache_read = get_i64(&totals, "cache_read_tokens");
        let cache_write = get_i64(&totals, "cache_write_tokens");
        let total = input + output + cache_read + cache_write;
        global_total += total;
        global_input += input;
        global_output += output;
        global_cache_read += cache_read;
        global_cache_write += cache_write;

        let source_rows = store.query_rows(&format!(
            "SELECT COALESCE(NULLIF(s.plugin_id,''), NULLIF(s.tool_name,''), s.source_kind) AS group_key, \
             COUNT(*) AS event_count \
             FROM events e JOIN sources s ON e.source_id = s.source_id \
             WHERE e.session_id IN ({in_list}) \
             GROUP BY group_key ORDER BY event_count DESC LIMIT {top}"
        ))?;
        let top_sources: Vec<Value> = source_rows
            .iter()
            .map(|r| {
                json!({
                    "key": get_str(r, "group_key"),
                    "event_count": get_i64(r, "event_count"),
                })
            })
            .collect();

        let cache_read_pct = if total > 0 {
            (cache_read as f64 * 100.0 / total as f64 * 100.0).round() / 100.0
        } else {
            0.0
        };
        let cache_write_pct = if total > 0 {
            (cache_write as f64 * 100.0 / total as f64 * 100.0).round() / 100.0
        } else {
            0.0
        };

        repo_entries.push(json!({
            "project_root": repo.display().to_string(),
            "sessions_in_window": session_ids.len(),
            "total_tokens": total,
            "input_tokens": input,
            "output_tokens": output,
            "cache_read_tokens": cache_read,
            "cache_write_tokens": cache_write,
            "cache_read_pct": cache_read_pct,
            "cache_write_pct": cache_write_pct,
            "top_sources": top_sources,
            "malformed_session_timestamps": malformed_count,
        }));
    }

    repo_entries.sort_by(|a, b| get_i64(b, "total_tokens").cmp(&get_i64(a, "total_tokens")));

    let mut caveats: Vec<String> = Vec::new();
    if total_malformed_ts > 0 {
        caveats.push(format!(
            "{} session(s) had malformed started_at; included via windows/events fallback",
            total_malformed_ts
        ));
    }
    if !ingest_errors.is_empty() {
        caveats.push(format!("{} ingest error(s) — see ingest_errors", ingest_errors.len()));
    }

    Ok(json!({
        "generated_at": iso_now(),
        "provider": provider,
        "modified_since": modified_since_iso,
        "window_since": window_since_iso,
        "roots": roots.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "repos": repo_entries,
        "global": {
            "repos_discovered": repos.len(),
            "repos_with_usage": repos_with_usage,
            "repos_without_usage": repos.len() as i64 - repos_with_usage,
            "total_tokens": global_total,
            "input_tokens": global_input,
            "output_tokens": global_output,
            "cache_read_tokens": global_cache_read,
            "cache_write_tokens": global_cache_write,
        },
        "ingested_files": ingested_files,
        "ingest_errors": ingest_errors,
        "caveats": caveats,
    }))
}

fn render_headline_markdown(report: &Value) -> Result<String> {
    let mut out = String::new();
    let generated = get_str(report, "generated_at");
    let provider = get_str(report, "provider");
    let modified_since = get_str(report, "modified_since");
    let window_since = get_str(report, "window_since");
    writeln!(out, "# Sherlock Headline Report")?;
    writeln!(out)?;
    writeln!(out, "- generated: `{generated}`")?;
    writeln!(out, "- provider: `{provider}`")?;
    writeln!(out, "- modified since: `{modified_since}`")?;
    writeln!(out, "- window since: `{window_since}`")?;
    if let Some(roots) = report.get("roots").and_then(|v| v.as_array()) {
        let list = roots
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(out, "- roots: {list}")?;
    }

    let global = report.get("global").cloned().unwrap_or_else(|| json!({}));
    writeln!(out)?;
    writeln!(out, "## Global")?;
    writeln!(out)?;
    writeln!(
        out,
        "- repos discovered: {}",
        get_i64(&global, "repos_discovered")
    )?;
    writeln!(
        out,
        "- repos with usage: {}",
        get_i64(&global, "repos_with_usage")
    )?;
    writeln!(
        out,
        "- repos without usage: {}",
        get_i64(&global, "repos_without_usage")
    )?;
    writeln!(
        out,
        "- total tokens: {}",
        get_i64(&global, "total_tokens")
    )?;
    writeln!(
        out,
        "  - input: {}, output: {}, cache_read: {}, cache_write: {}",
        get_i64(&global, "input_tokens"),
        get_i64(&global, "output_tokens"),
        get_i64(&global, "cache_read_tokens"),
        get_i64(&global, "cache_write_tokens"),
    )?;

    writeln!(out)?;
    writeln!(out, "## Per-Repo")?;
    writeln!(out)?;
    writeln!(
        out,
        "| Repo | Sessions | Total | Cache-Read % | Top Source |"
    )?;
    writeln!(out, "|------|----------|-------|--------------|------------|")?;
    if let Some(repos) = report.get("repos").and_then(|v| v.as_array()) {
        for repo in repos {
            let root = get_str(repo, "project_root");
            let sessions = get_i64(repo, "sessions_in_window");
            let total = get_i64(repo, "total_tokens");
            let cr_pct = repo
                .get("cache_read_pct")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let top_source = repo
                .get("top_sources")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .map(|v| get_str(v, "key"))
                .unwrap_or_default();
            writeln!(
                out,
                "| `{root}` | {sessions} | {total} | {cr_pct:.2} | {top_source} |"
            )?;
        }
    }

    let caveats = report
        .get("caveats")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if !caveats.is_empty() {
        writeln!(out)?;
        writeln!(out, "## Caveats")?;
        writeln!(out)?;
        for c in caveats {
            if let Some(s) = c.as_str() {
                writeln!(out, "- {s}")?;
            }
        }
    }

    Ok(out)
}

fn render_quota(snapshot: &live::claude_code_oauth::QuotaSnapshot, format: ReportFormat) -> Result<String> {
    match format {
        ReportFormat::Json => Ok(serde_json::to_string_pretty(snapshot)?),
        ReportFormat::Markdown => render_quota_markdown(snapshot),
        ReportFormat::Text => render_quota_text(snapshot),
    }
}

fn render_quota_text(snapshot: &live::claude_code_oauth::QuotaSnapshot) -> Result<String> {
    let mut out = String::new();
    let source = if snapshot.cached {
        match snapshot.cache_age_secs {
            Some(age) => format!("cached {age}s ago"),
            None => "cached".to_string(),
        }
    } else {
        "live".to_string()
    };
    writeln!(
        out,
        "Claude Code quota  (provider={}, fetched {} — {})",
        snapshot.provider, snapshot.fetched_at, source
    )?;
    if snapshot.subscription_type.is_some() || snapshot.rate_limit_tier.is_some() {
        writeln!(
            out,
            "  plan: {}  tier: {}",
            snapshot.subscription_type.as_deref().unwrap_or("—"),
            snapshot.rate_limit_tier.as_deref().unwrap_or("—"),
        )?;
    }
    writeln!(out)?;
    write_window_line(&mut out, "5-hour window  ", snapshot.five_hour.as_ref())?;
    write_window_line(&mut out, "7-day window   ", snapshot.seven_day.as_ref())?;
    write_window_line(&mut out, "7d  Opus       ", snapshot.seven_day_opus.as_ref())?;
    write_window_line(&mut out, "7d  Sonnet     ", snapshot.seven_day_sonnet.as_ref())?;
    write_window_line(&mut out, "7d  Cowork     ", snapshot.seven_day_cowork.as_ref())?;
    write_window_line(&mut out, "7d  OAuth apps ", snapshot.seven_day_oauth_apps.as_ref())?;
    write_window_line(&mut out, "7d  Omelette   ", snapshot.seven_day_omelette.as_ref())?;
    if let Some(extra) = snapshot.extra_usage.as_ref() {
        writeln!(out)?;
        writeln!(
            out,
            "Pay-as-you-go ({}): enabled={} used={} limit={} util={:.1}%",
            if extra.currency.is_empty() { "USD" } else { &extra.currency },
            extra.is_enabled,
            extra.used_credits.map(|c| format!("{c:.2}")).unwrap_or_else(|| "—".into()),
            extra.monthly_limit.map(|c| format!("{c:.0}")).unwrap_or_else(|| "—".into()),
            extra.utilization,
        )?;
    }
    Ok(out)
}

fn render_quota_markdown(snapshot: &live::claude_code_oauth::QuotaSnapshot) -> Result<String> {
    let mut out = String::new();
    writeln!(out, "# Claude Code quota")?;
    writeln!(out)?;
    writeln!(out, "- provider: `{}`", snapshot.provider)?;
    writeln!(out, "- fetched: `{}`", snapshot.fetched_at)?;
    if let Some(plan) = snapshot.subscription_type.as_deref() {
        writeln!(out, "- plan: `{plan}`")?;
    }
    if let Some(tier) = snapshot.rate_limit_tier.as_deref() {
        writeln!(out, "- tier: `{tier}`")?;
    }
    writeln!(
        out,
        "- source: {}",
        if snapshot.cached {
            match snapshot.cache_age_secs {
                Some(age) => format!("cached ({age}s old)"),
                None => "cached".into(),
            }
        } else {
            "live".into()
        }
    )?;
    writeln!(out)?;
    writeln!(out, "| Window | Utilization | Resets at |")?;
    writeln!(out, "|--------|-------------|-----------|")?;
    for (label, w) in [
        ("5-hour", snapshot.five_hour.as_ref()),
        ("7-day", snapshot.seven_day.as_ref()),
        ("7d Opus", snapshot.seven_day_opus.as_ref()),
        ("7d Sonnet", snapshot.seven_day_sonnet.as_ref()),
        ("7d Cowork", snapshot.seven_day_cowork.as_ref()),
        ("7d OAuth apps", snapshot.seven_day_oauth_apps.as_ref()),
        ("7d Omelette", snapshot.seven_day_omelette.as_ref()),
    ] {
        match w {
            Some(win) => writeln!(
                out,
                "| {label} | {:.1}% | {} |",
                win.utilization,
                win.resets_at.as_deref().unwrap_or("—")
            )?,
            None => writeln!(out, "| {label} | — | — |")?,
        }
    }
    if let Some(extra) = snapshot.extra_usage.as_ref() {
        writeln!(out)?;
        writeln!(out, "## Pay-as-you-go")?;
        writeln!(out)?;
        writeln!(out, "- enabled: `{}`", extra.is_enabled)?;
        writeln!(
            out,
            "- used credits: {}",
            extra.used_credits.map(|c| format!("{c:.2}")).unwrap_or_else(|| "—".into())
        )?;
        writeln!(
            out,
            "- monthly limit: {}",
            extra.monthly_limit.map(|c| format!("{c:.0}")).unwrap_or_else(|| "—".into())
        )?;
        writeln!(out, "- utilization: {:.1}%", extra.utilization)?;
        writeln!(
            out,
            "- currency: `{}`",
            if extra.currency.is_empty() { "USD" } else { &extra.currency }
        )?;
    }
    Ok(out)
}

fn write_window_line(
    out: &mut String,
    label: &str,
    window: Option<&live::claude_code_oauth::QuotaWindow>,
) -> Result<()> {
    match window {
        Some(w) => writeln!(
            out,
            "  {label} {:>6.1}%   resets {}",
            w.utilization,
            w.resets_at.as_deref().unwrap_or("—")
        )?,
        None => writeln!(out, "  {label}     —")?,
    }
    Ok(())
}

fn git_branch(cwd: &Path) -> Option<String> {
    let out = Command::new("git")
        .args(["branch", "--show-current"])
        .current_dir(cwd)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn default_repo() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
        .join(".local/share/sherlock")
}

fn check_for_dolt_servers() {
    // Check for running dolt sql-server processes
    let output = Command::new("pgrep")
        .args(["-f", "dolt sql-server"])
        .output();
    
    if let Ok(out) = output {
        if out.status.success() && !out.stdout.is_empty() {
            // Found running servers
            eprintln!("⚠️  WARNING: Detected running 'dolt sql-server' processes.");
            eprintln!("   Sherlock uses dolt CLI commands which may temporarily interfere with these servers.");
            eprintln!("   If you experience issues with beads or other dolt-based tools, try:");
            eprintln!("   1. Complete your sherlock operation quickly");
            eprintln!("   2. Or stop dolt servers temporarily while using sherlock");
            eprintln!();
        }
    }
}

fn default_history() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
        .join(".claude/history.jsonl")
}

fn default_projects_root() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
        .join(".claude/projects")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestEnv {
        root: PathBuf,
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    fn setup_store() -> (TestEnv, SherlockStore) {
        let root = std::env::temp_dir().join(format!("sherlock-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create temp root");
        let env = TestEnv { root };
        let store = SherlockStore::new(env.root.join("repo"));
        fs::create_dir_all(&store.repo).expect("create repo dir");
        store.init().expect("init store");
        (env, store)
    }

    fn ingest_fixture(
        store: &SherlockStore,
        fixture: &str,
        session_id: &str,
        project_root: &Path,
    ) -> IngestSummary {
        let provider = providers::claude_code::ClaudeCodeProvider;
        ingest_session(
            store,
            &provider,
            &fixture_path(fixture),
            session_id,
            project_root,
            "main",
            "claude-sonnet",
        )
        .expect("ingest fixture")
    }

    #[test]
    fn extract_prompt_text_ignores_tool_only_user_turns() {
        let obj = json!({
            "type": "user",
            "message": {
                "role": "user",
                "content": [
                    {"type": "tool_result", "content": "done", "tool_use_id": "toolu_1"}
                ]
            }
        });
        let provider = providers::claude_code::ClaudeCodeProvider;
        let ev = RawEvent::Json(obj);
        assert_eq!(provider.extract_prompt_text(&ev), None);
    }

    #[test]
    fn continuation_summary_detection_matches_compacted_prompt() {
        let text = "This session is being continued from a previous conversation that ran out of context. The summary below covers the earlier portion of the conversation.";
        let provider = providers::claude_code::ClaudeCodeProvider;
        assert!(provider.is_continuation_summary(text));
    }

    #[test]
    fn recommendation_rules_flag_expected_thresholds() {
        let facts = ReportFacts {
            session_totals: SessionTotals {
                input_tokens: 1000,
                output_tokens: 3000,
                cache_read_tokens: 42000,
                cache_write_tokens: 1000,
                total_tokens: 47000,
                cache_read_pct: 89.36170212765957,
                cache_write_pct: 2.127659574468085,
            },
            prompt_stats: PromptStats {
                prompt_count: 1,
                total_prompt_chars: 4200,
                average_prompt_chars: 4200.0,
                longest_prompts: vec![],
                continuation_summaries: ContinuationSummaryStats {
                    count: 1,
                    total_chars: 4200,
                    average_chars: 4200.0,
                    max_chars: 4200,
                },
            },
            all_sources: vec![
                SourceFact {
                    tool_name: "Bash".to_string(),
                    source_kind: "tool".to_string(),
                    estimated_tokens: 26000,
                    ..SourceFact::default()
                },
                SourceFact {
                    tool_name: "Read".to_string(),
                    source_kind: "tool".to_string(),
                    estimated_tokens: 12000,
                    ..SourceFact::default()
                },
            ],
            plugin_sources: vec![SourceFact {
                plugin_id: "skill:workflow".to_string(),
                estimated_tokens: 4000,
                ..SourceFact::default()
            }],
            ..ReportFacts::default()
        };
        let provider = providers::claude_code::ClaudeCodeProvider;
        let finding_ids = findings_from_facts(&provider, &facts)
            .into_iter()
            .map(|finding| finding.id)
            .collect::<Vec<_>>();
        assert!(finding_ids.contains(&"cache-read-dominated".to_string()));
        assert!(finding_ids.contains(&"oversized-continuation-summary".to_string()));
        assert!(finding_ids.contains(&"workflow-heavy-session".to_string()));
        assert!(finding_ids.contains(&"low-prompt-count-high-usage".to_string()));
        let findings = findings_from_facts(&provider, &facts);
        let recommendation_ids = recommendations_from_findings(&findings)
            .into_iter()
            .map(|recommendation| recommendation.id)
            .collect::<Vec<_>>();
        assert!(recommendation_ids.contains(&"reduce-cache-churn".to_string()));
        assert!(recommendation_ids.contains(&"shrink-resume-summaries".to_string()));
    }

    #[test]
    fn prompt_facts_count_human_prompts_and_summary_size() {
        let (_temp, store) = setup_store();
        let project_root = PathBuf::from("/tmp/project-alpha");
        ingest_fixture(
            &store,
            "continuation_summary_heavy.jsonl",
            "continuation-summary-heavy",
            &project_root,
        );
        let provider = providers::claude_code::ClaudeCodeProvider;
        let facts = prompt_facts(&store, &provider, "continuation-summary-heavy").expect("prompt facts");
        assert_eq!(facts.prompt_count, 2);
        assert_eq!(facts.continuation_summaries.count, 1);
        assert!(facts.continuation_summaries.max_chars >= 3000);
        assert_eq!(facts.longest_prompts[0].prompt_kind, "continuation_summary");
    }

    #[test]
    fn ingest_summarize_and_render_report_end_to_end() {
        let (_temp, store) = setup_store();
        let project_root = PathBuf::from("/tmp/project-alpha");
        ingest_fixture(&store, "short_clean.jsonl", "short-clean", &project_root);
        ingest_fixture(
            &store,
            "cache_read_heavy.jsonl",
            "cache-read-heavy",
            &project_root,
        );
        let report = summarize_session(&store, "cache-read-heavy").expect("summarize");
        assert_eq!(get_str(&report, "session_id"), "cache-read-heavy");
        assert!(report.get("session_totals").is_some());
        assert!(report.get("prompt_stats").is_some());
        assert!(report.get("comparisons").is_some());
        assert!(report.get("recommendations").is_some());
        let markdown = render_report_markdown(&report).expect("markdown");
        let text = render_report_text(&report).expect("text");
        assert!(markdown.contains("## Findings"));
        assert!(markdown.contains("Cache reads dominate session spend."));
        assert!(text.contains("Recommendations:"));
        assert!(text.contains("Reduce context rehydration between turns."));
    }

    #[test]
    fn regression_known_session_has_expected_findings() {
        let (_temp, store) = setup_store();
        let project_root = PathBuf::from("/tmp/project-alpha");
        ingest_fixture(&store, "short_clean.jsonl", "short-clean", &project_root);
        ingest_fixture(
            &store,
            "continuation_summary_heavy.jsonl",
            "continuation-summary-heavy",
            &project_root,
        );
        let report = summarize_session(&store, "continuation-summary-heavy").expect("summarize");
        let finding_ids = report
            .get("findings")
            .and_then(Value::as_array)
            .expect("findings array")
            .iter()
            .map(|finding| get_str(finding, "id"))
            .collect::<Vec<_>>();
        assert!(finding_ids.contains(&"oversized-continuation-summary".to_string()));
        assert!(finding_ids.contains(&"low-prompt-count-high-usage".to_string()));
    }

    #[test]
    fn zero_token_noisy_fixture_reports_missing_usage() {
        let (_temp, store) = setup_store();
        let project_root = PathBuf::from("/tmp/project-beta");
        ingest_fixture(
            &store,
            "zero_token_noisy.jsonl",
            "zero-token-noisy",
            &project_root,
        );
        let report = summarize_session(&store, "zero-token-noisy").expect("summarize");
        let totals = report
            .get("session_totals")
            .cloned()
            .unwrap_or_else(|| json!({}));
        assert_eq!(get_i64(&totals, "total_tokens"), 0);
        let finding_ids = report
            .get("findings")
            .and_then(Value::as_array)
            .expect("findings array")
            .iter()
            .map(|finding| get_str(finding, "id"))
            .collect::<Vec<_>>();
        assert!(finding_ids.contains(&"no-token-usage".to_string()));
    }

    #[test]
    fn copilot_cli_provider_ingests_events_jsonl() {
        let (_temp, store) = setup_store();
        let provider = providers::copilot_cli::CopilotCliProvider;
        let project_root = PathBuf::from("/tmp/project-copilot");
        ingest_session(
            &store,
            &provider,
            &fixture_path("copilot-cli/basic.jsonl"),
            "copilot-basic",
            &project_root,
            "main",
            "claude-sonnet-4.5",
        )
        .expect("ingest copilot fixture");
        let report = summarize_session(&store, "copilot-basic").expect("summarize");
        assert_eq!(get_str(&report, "provider"), "copilot-cli");
        let totals = report.get("session_totals").cloned().unwrap_or_else(|| json!({}));
        assert_eq!(get_i64(&totals, "input_tokens"), 12000);
        assert_eq!(get_i64(&totals, "output_tokens"), 800);
        assert_eq!(get_i64(&totals, "cache_read_tokens"), 8500);
        let tool_names: Vec<String> = report
            .get("top_sources")
            .and_then(Value::as_array)
            .expect("top_sources")
            .iter()
            .map(|s| get_str(s, "tool_name"))
            .collect();
        assert!(tool_names.iter().any(|n| n == "bash"));
        let finding_ids: Vec<String> = report
            .get("findings")
            .and_then(Value::as_array)
            .expect("findings")
            .iter()
            .map(|f| get_str(f, "id"))
            .collect();
        // Copilot lacks per-turn token attribution — sherlock should flag that.
        assert!(finding_ids
            .iter()
            .any(|id| id == "sources-missing-token-attribution"));
    }

    #[test]
    fn codex_provider_ingests_rollout_shape() {
        let (_temp, store) = setup_store();
        let provider = providers::codex::CodexProvider;
        let project_root = PathBuf::from("/tmp/project-codex");
        ingest_session(
            &store,
            &provider,
            &fixture_path("codex/basic.jsonl"),
            "codex-basic",
            &project_root,
            "main",
            "gpt-5",
        )
        .expect("ingest codex fixture");
        let report = summarize_session(&store, "codex-basic").expect("summarize");
        assert_eq!(get_str(&report, "provider"), "codex");
        let totals = report.get("session_totals").cloned().unwrap_or_else(|| json!({}));
        assert_eq!(get_i64(&totals, "input_tokens"), 14700);
        assert_eq!(get_i64(&totals, "output_tokens"), 590);
        assert_eq!(get_i64(&totals, "cache_read_tokens"), 9900);
        let tool_names: Vec<String> = report
            .get("top_sources")
            .and_then(Value::as_array)
            .expect("top_sources")
            .iter()
            .map(|s| get_str(s, "tool_name"))
            .collect();
        assert!(tool_names.iter().any(|n| n == "shell"));
        assert!(tool_names.iter().any(|n| n == "apply_patch"));
    }

    #[test]
    fn parse_ts_epoch_handles_legacy_and_iso_forms() {
        assert_eq!(parse_ts_epoch("1776361213Z"), Some(1_776_361_213));
        assert_eq!(parse_ts_epoch("1776361213"), Some(1_776_361_213));
        // Millisecond epoch auto-detected.
        assert_eq!(parse_ts_epoch("1776361213000Z"), Some(1_776_361_213));
        assert_eq!(
            parse_ts_epoch("2026-04-16T00:00:00Z"),
            Some(
                chrono::DateTime::parse_from_rfc3339("2026-04-16T00:00:00Z")
                    .unwrap()
                    .timestamp()
            )
        );
        assert_eq!(
            parse_ts_epoch("2026-04-16"),
            Some(
                chrono::NaiveDate::parse_from_str("2026-04-16", "%Y-%m-%d")
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap()
                    .and_utc()
                    .timestamp()
            )
        );
        assert_eq!(parse_ts_epoch(""), None);
        assert_eq!(parse_ts_epoch("not-a-date"), None);
    }

    #[test]
    fn parse_since_expr_accepts_natural_language() {
        let (iso_today, _) = parse_since_expr("today").expect("today");
        assert!(iso_today.ends_with("T00:00:00Z"));
        let (iso_yday, ts_yday) = parse_since_expr("yesterday").expect("yesterday");
        let (_, ts_today) = parse_since_expr("today").unwrap();
        assert_eq!(ts_today - ts_yday, 86_400);
        assert!(iso_yday.ends_with("T00:00:00Z"));

        let (_, ts_7d) = parse_since_expr("7d").expect("7d");
        let now_ts = chrono::Utc::now().timestamp();
        assert!((now_ts - ts_7d - 7 * 86_400).abs() < 120);

        let (_, ts_iso) = parse_since_expr("2026-04-16").expect("iso");
        assert_eq!(ts_iso, 1_776_297_600);

        parse_since_expr("sunday").expect("sunday");
        parse_since_expr("bogus").expect_err("rejects garbage");
    }

    #[test]
    fn session_ids_in_window_tolerates_malformed_started_at() {
        let (_env, store) = setup_store();
        // Session with proper ISO, in window.
        store
            .exec_script(
                "INSERT INTO sessions(session_id, started_at, ended_at, project_root, branch, model_family) \
                 VALUES ('sess-iso', '2026-04-18T00:00:00Z', '2026-04-18T01:00:00Z', '/tmp/a', 'main', '');",
            )
            .unwrap();
        // Session with legacy epoch-Z started_at that LOOKS before 2026-04-16
        // lexicographically ('1' < '2') but whose epoch ~= 2026-04-17.
        let epoch_2026_04_17 = 1_776_729_600_i64;
        store
            .exec_script(&format!(
                "INSERT INTO sessions(session_id, started_at, ended_at, project_root, branch, model_family) \
                 VALUES ('sess-legacy', '{}Z', '{}Z', '/tmp/b', 'main', '');",
                epoch_2026_04_17, epoch_2026_04_17 + 3600
            ))
            .unwrap();
        // Session entirely before the window.
        store
            .exec_script(
                "INSERT INTO sessions(session_id, started_at, ended_at, project_root, branch, model_family) \
                 VALUES ('sess-old', '2025-01-01T00:00:00Z', '2025-01-01T01:00:00Z', '/tmp/c', 'main', '');",
            )
            .unwrap();

        let since_epoch = parse_ts_epoch("2026-04-16T00:00:00Z").unwrap();
        let mut ids = session_ids_in_window(&store, None, None, since_epoch).unwrap();
        ids.sort();
        assert_eq!(ids, vec!["sess-iso".to_string(), "sess-legacy".to_string()]);
    }

    #[test]
    fn rollup_since_does_not_silently_zero_on_legacy_timestamps() {
        // Regression for sherlock-ed0: with legacy epoch-Z started_at values,
        // `rollup --since 2026-04-16` used to return 0 despite populated data.
        let (_env, store) = setup_store();
        ingest_fixture(
            &store,
            "short_clean.jsonl",
            "short-clean",
            Path::new("/tmp/legacy-repo"),
        );
        // Rewrite started_at to the legacy epoch-Z form to simulate data from
        // before the iso_now() fix. Use a recent epoch so the window includes it.
        let epoch_now = chrono::Utc::now().timestamp();
        store
            .exec_script(&format!(
                "UPDATE sessions SET started_at='{}Z', ended_at='{}Z' WHERE session_id='short-clean';",
                epoch_now - 3600,
                epoch_now
            ))
            .unwrap();

        let report =
            rollup_report(&store, "plugin", Some("1d"), Some("claude-code"), 20).unwrap();
        let total_sessions = get_i64(&report, "total_sessions");
        assert!(
            total_sessions >= 1,
            "expected rollup to include legacy-timestamp session; got total_sessions={total_sessions}, report={report}"
        );
        let grand = get_i64(&report, "grand_total_tokens");
        assert!(
            grand > 0,
            "expected non-zero grand_total_tokens, got {grand}"
        );
    }
}
