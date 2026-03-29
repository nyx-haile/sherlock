use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
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
    model_family TEXT
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
    raw_ref VARCHAR(255)
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
"#;

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
        #[arg(long, default_value_t = false)]
        commit: bool,
    },
    Report {
        #[arg(long)]
        session_id: Option<String>,
    },
    Tui {
        #[arg(long)]
        session_id: Option<String>,
    },
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    fs::create_dir_all(&cli.repo)?;
    let store = SherlockStore::new(cli.repo);

    match cli.cmd {
        Cmd::Init { commit } => {
            store.init()?;
            if commit {
                store.commit("sherlock: initialize schema")?;
            }
            println!("{}", json!({"ok": true, "repo": store.repo.display().to_string()}));
        }
        Cmd::Ingest {
            history,
            session_id,
            project_root,
            branch,
            model_family,
            commit,
        } => {
            store.init()?;
            let effective_history = resolve_history_path(history, &project_root)?;
            let sid = resolve_ingest_session_id(&effective_history, session_id)?;
            let b = branch.unwrap_or_else(|| git_branch(&project_root).unwrap_or_default());
            let summary =
                ingest_session(&store, &effective_history, &sid, &project_root, &b, &model_family)?;
            if commit {
                store.commit(&format!("sherlock: ingest {} events={}", sid, summary.events))?;
            }
            println!("{}", serde_json::to_string(&summary)?);
        }
        Cmd::Report { session_id } => {
            let sid = resolve_session_id_with_picker(&store, session_id)?;
            let report = summarize_session(&store, &sid)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
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
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }
            run_tui(&store, &sid)?;
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
        Ok(())
    }

    fn exec_script(&self, script: &str) -> Result<()> {
        self.run_with_input(&["dolt", "sql"], script).map(|_| ())
    }

    fn query_rows(&self, query: &str) -> Result<Vec<Value>> {
        let out = self.run(&["dolt", "sql", "-q", query, "-r", "json"])?;
        let parsed: Value = serde_json::from_str(if out.trim().is_empty() { r#"{"rows":[]}"# } else { &out })?;
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
        "INSERT INTO sessions(session_id, started_at, project_root, branch, model_family) \
         VALUES ('{}','{}','{}','{}','{}') \
         ON DUPLICATE KEY UPDATE started_at=VALUES(started_at), project_root=VALUES(project_root), branch=VALUES(branch), model_family=VALUES(model_family);\n",
        sql(session_id),
        sql(&started_at),
        sql(&project_root.display().to_string()),
        sql(branch),
        sql(model_family)
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
        if line_session_id(&obj).as_deref() != Some(session_id) {
            continue;
        }

        let event_time = event_time_value(&obj).unwrap_or_else(|| started_at.clone());
        if first_event_time.is_none() {
            first_event_time = Some(event_time.clone());
        }
        last_event_time = Some(event_time.clone());
        let event_type = infer_event_type(&obj);
        let tool_name = extract_tool_name(&obj);
        let hook_name = extract_hook_name(&obj);
        let plugin_id = extract_plugin_id(&obj, &tool_name);
        let mcp_server_name = extract_mcp_server_name(&tool_name);
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
        let usage = extract_usage(&obj);
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
            "INSERT INTO events(event_id, session_id, turn_id, event_time, event_type, source_id, payload_bytes, raw_ref) \
             VALUES ('{}','{}','{}','{}','{}','{}',{},'{}:{}');\n",
            short_id("event"),
            sql(session_id),
            turn_id,
            sql(&event_time),
            event_type,
            source_id,
            payload_bytes,
            artifact_id,
            idx + 1
        ));
        events += 1;

        let total = cum_input + cum_output + cum_cache_read + cum_cache_write;
        if let Some(prev) = prev_total {
            let delta = total - prev;
            if delta >= 1000 {
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
        "SELECT session_id, started_at, ended_at, project_root, branch, model_family FROM sessions WHERE session_id='{}'",
        sql(session_id)
    ))?;
    if session_rows.is_empty() {
        return Ok(json!({"error": "session_not_found", "session_id": session_id}));
    }
    let counts = store.query_rows(&format!(
        "SELECT \
         (SELECT COUNT(*) FROM turns WHERE session_id='{}') AS turns, \
         (SELECT COUNT(*) FROM events WHERE session_id='{}') AS events, \
         (SELECT COUNT(*) FROM windows WHERE session_id='{}') AS windows",
        sql(session_id),
        sql(session_id),
        sql(session_id)
    ))?;
    let top_sources = store.query_rows(&format!(
        "SELECT e.source_id, s.source_kind, COALESCE(s.plugin_id, '') AS plugin_id, COALESCE(s.tool_name, '') AS tool_name, COALESCE(s.hook_name, '') AS hook_name, COUNT(*) AS event_count \
         FROM events e JOIN sources s ON e.source_id = s.source_id \
         WHERE e.session_id='{}' \
         GROUP BY e.source_id, s.source_kind, s.plugin_id, s.tool_name, s.hook_name \
         ORDER BY event_count DESC LIMIT 50",
        sql(session_id)
    ))?;
    let spikes = store.query_rows(&format!(
        "SELECT start_time, delta_tokens FROM windows WHERE session_id='{}' ORDER BY delta_tokens DESC LIMIT 5",
        sql(session_id)
    ))?;
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
    let source_token_totals = source_token_totals(store, session_id)?;
    let grand_total = get_i64(&totals, "input_tokens")
        + get_i64(&totals, "output_tokens")
        + get_i64(&totals, "cache_read_tokens")
        + get_i64(&totals, "cache_write_tokens");
    let mut enriched_sources: Vec<Value> = top_sources
        .iter()
        .map(|src| {
            let sid = get_str(src, "source_id");
            let est = source_token_totals.get(&sid).copied().unwrap_or(0);
            let pct = if grand_total > 0 {
                (est as f64 * 100.0) / grand_total as f64
            } else {
                0.0
            };
            let mut obj = src.clone();
            if let Some(m) = obj.as_object_mut() {
                m.insert("estimated_tokens".to_string(), json!(est));
                m.insert("estimated_pct".to_string(), json!(pct));
            }
            obj
        })
        .collect();
    enriched_sources.sort_by_key(|v| -get_i64(v, "estimated_tokens"));
    let plugin_sources: Vec<Value> = enriched_sources
        .iter()
        .filter(|v| !get_str(v, "plugin_id").is_empty())
        .take(10)
        .cloned()
        .collect();
    let cache_read = get_i64(&totals, "cache_read_tokens");
    let input = get_i64(&totals, "input_tokens");
    let output = get_i64(&totals, "output_tokens");
    let mut insights = Vec::<Value>::new();
    if grand_total > 0 {
        insights.push(json!(format!(
            "Cache read tokens are {:.1}% of total usage.",
            (cache_read as f64 * 100.0) / grand_total as f64
        )));
    }
    if let Some(top) = enriched_sources.first() {
        insights.push(json!(format!(
            "Top source: kind={} tool={} plugin={} estimated_tokens={}",
            get_str(top, "source_kind"),
            get_str(top, "tool_name"),
            get_str(top, "plugin_id"),
            get_i64(top, "estimated_tokens")
        )));
    }
    if grand_total == 0 {
        insights.push(json!(
            "No token usage found for this session in the ingested source. Re-ingest from in-depth Claude project logs (.claude/projects/.../*.jsonl)."
        ));
    }
    if cache_read > input + output {
        insights.push(json!(
            "Most spend appears to be context rehydration (cache reads), not direct prompt/response tokens."
        ));
    }

    let mut out = session_rows[0].clone();
    if let Some(obj) = out.as_object_mut() {
        if let Some(c) = counts.first().and_then(Value::as_object) {
            for (k, v) in c {
                obj.insert(k.clone(), v.clone());
            }
        }
        obj.insert("totals".to_string(), totals);
        obj.insert("top_sources".to_string(), Value::Array(enriched_sources.into_iter().take(5).collect()));
        obj.insert("plugin_sources".to_string(), Value::Array(plugin_sources));
        obj.insert("spikes".to_string(), Value::Array(spikes));
        obj.insert("insights".to_string(), Value::Array(insights));
    }
    Ok(out)
}

fn resolve_session_id(store: &SherlockStore, session_id: Option<String>) -> Result<String> {
    if let Some(sid) = session_id {
        return Ok(sid);
    }
    let rows = store.query_rows(
        "SELECT session_id FROM sessions ORDER BY ended_at DESC LIMIT 1",
    )?;
    let sid = rows
        .first()
        .and_then(|r| r.get("session_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("no sessions found; run sherlock ingest first"))?;
    Ok(sid.to_string())
}

fn resolve_session_id_with_picker(store: &SherlockStore, session_id: Option<String>) -> Result<String> {
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
    println!("Pick [1-{}] (Enter for {}): ", rows.len(), preferred_idx + 1);
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

fn resolve_ingest_session_id(history_path: &Path, provided: Option<String>) -> Result<String> {
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
        let sid = match line_session_id(&obj) {
            Some(v) => v,
            None => continue,
        };
        let ts = event_time_epoch(&obj).unwrap_or(0);
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

fn get_str(row: &Value, key: &str) -> String {
    row.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn infer_event_type(obj: &Value) -> String {
    if !extract_tool_name(obj).is_empty() {
        return "tool_call".to_string();
    }
    if !extract_hook_name(obj).is_empty() {
        return "hook_event".to_string();
    }
    if obj.get("type").and_then(Value::as_str) == Some("user")
        || obj
            .get("message")
            .and_then(|m| m.get("role"))
            .and_then(Value::as_str)
            == Some("user")
    {
        return "prompt_submit".to_string();
    }
    "assistant_turn".to_string()
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

fn safe_i64(v: Option<&Value>) -> Option<i64> {
    match v {
        None => None,
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.parse::<i64>().ok(),
        _ => None,
    }
}

#[derive(Default)]
struct UsageSample {
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    cache_read_tokens: Option<i64>,
    cache_write_tokens: Option<i64>,
}

fn extract_usage(obj: &Value) -> UsageSample {
    let usage = obj
        .get("message")
        .and_then(|m| m.get("usage"))
        .or_else(|| obj.get("usage"));
    let cache_creation_sum = usage
        .and_then(|u| u.get("cache_creation"))
        .map(|c| {
            let a = safe_i64(c.get("ephemeral_1h_input_tokens")).unwrap_or(0);
            let b = safe_i64(c.get("ephemeral_5m_input_tokens")).unwrap_or(0);
            a + b
        });

    let input_tokens = safe_i64(
        usage
            .and_then(|u| u.get("input_tokens"))
            .or_else(|| obj.get("input_tokens_cum"))
            .or_else(|| obj.get("input_tokens")),
    );
    let output_tokens = safe_i64(
        usage
            .and_then(|u| u.get("output_tokens"))
            .or_else(|| obj.get("output_tokens_cum"))
            .or_else(|| obj.get("output_tokens")),
    );
    let cache_read_tokens = safe_i64(
        usage
            .and_then(|u| u.get("cache_read_input_tokens"))
            .or_else(|| usage.and_then(|u| u.get("cache_read_tokens")))
            .or_else(|| obj.get("cache_read_tokens_cum"))
            .or_else(|| obj.get("cache_read_tokens")),
    );
    let cache_write_tokens = safe_i64(
        usage
            .and_then(|u| u.get("cache_creation_input_tokens"))
            .or_else(|| obj.get("cache_write_tokens_cum"))
            .or_else(|| obj.get("cache_write_tokens")),
    )
    .or(cache_creation_sum);

    UsageSample {
        input_tokens,
        output_tokens,
        cache_read_tokens,
        cache_write_tokens,
    }
}

fn line_session_id(obj: &Value) -> Option<String> {
    obj.get("sessionId")
        .or_else(|| obj.get("session_id"))
        .and_then(Value::as_str)
        .map(|s| s.to_string())
}

fn event_time_value(obj: &Value) -> Option<String> {
    if let Some(ts) = obj.get("timestamp") {
        if let Some(s) = ts.as_str() {
            return Some(s.to_string());
        }
        if let Some(i) = ts.as_i64() {
            return Some(i.to_string());
        }
    }
    obj.get("created_at")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .or_else(|| obj.get("timestamp").and_then(Value::as_str).map(|s| s.to_string()))
}

fn event_time_epoch(obj: &Value) -> Option<i64> {
    obj.get("timestamp")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
        })
        .or_else(|| obj.get("created_at").and_then(Value::as_i64))
}

fn extract_tool_name(obj: &Value) -> String {
    if let Some(v) = obj.get("tool_name").and_then(Value::as_str) {
        return v.to_string();
    }
    if let Some(v) = obj
        .get("toolUseResult")
        .and_then(|t| t.get("commandName"))
        .and_then(Value::as_str)
    {
        return v.to_string();
    }
    obj.get("message")
        .and_then(|m| m.get("content"))
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter().find_map(|item| {
                if item.get("type").and_then(Value::as_str) == Some("tool_use") {
                    item.get("name").and_then(Value::as_str).map(|s| s.to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_default()
}

fn extract_plugin_id(obj: &Value, tool_name: &str) -> Option<String> {
    if let Some(v) = obj.get("plugin_id").and_then(Value::as_str) {
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    if tool_name == "Skill" {
        if let Some(skill) = obj
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_array)
            .and_then(|arr| {
                arr.iter().find_map(|item| {
                    if item.get("type").and_then(Value::as_str) == Some("tool_use")
                        && item.get("name").and_then(Value::as_str) == Some("Skill")
                    {
                        item.get("input")
                            .and_then(|v| v.get("skill"))
                            .and_then(Value::as_str)
                            .map(|s| format!("skill:{s}"))
                    } else {
                        None
                    }
                })
            })
        {
            return Some(skill);
        }
    }
    if tool_name.starts_with("mcp__") {
        if let Some(server) = extract_mcp_server_name(tool_name) {
            if server.starts_with("plugin_") {
                return Some(server);
            }
            return Some(format!("mcp:{server}"));
        }
        return Some("mcp:unknown".to_string());
    }
    if let Some(cmd) = obj
        .get("toolUseResult")
        .and_then(|t| t.get("commandName"))
        .and_then(Value::as_str)
    {
        if !cmd.is_empty() {
            return Some(format!("tool-result:{cmd}"));
        }
    }
    None
}

fn extract_mcp_server_name(tool_name: &str) -> Option<String> {
    if !tool_name.starts_with("mcp__") {
        return None;
    }
    let parts: Vec<&str> = tool_name.split("__").collect();
    if parts.len() >= 2 {
        return Some(parts[1].to_string());
    }
    None
}

fn extract_hook_name(obj: &Value) -> String {
    obj.get("hook_event_name")
        .or_else(|| obj.get("subtype"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
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
    format!("{}-{}", prefix, Uuid::new_v4().simple().to_string()[..12].to_string())
}

fn new_session_id() -> String {
    short_id("session")
}

fn iso_now() -> String {
    // Keep RFC3339-like shape for SQL text sorting and consistency.
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Minimal timestamp for deterministic storage without extra deps
    format!("{}Z", now)
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

fn default_history() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
        .join(".claude/history.jsonl")
}

fn default_projects_root() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
        .join(".claude/projects")
}
