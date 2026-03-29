use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use crossterm::{
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
use std::fs;
use std::io::stdout;
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
        #[arg(long, default_value_os_t = default_history())]
        history: PathBuf,
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
        session_id: String,
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
            let sid = session_id.unwrap_or_else(new_session_id);
            let b = branch.unwrap_or_else(|| git_branch(&project_root).unwrap_or_default());
            let summary = ingest_session(&store, &history, &sid, &project_root, &b, &model_family)?;
            if commit {
                store.commit(&format!("sherlock: ingest {} events={}", sid, summary.events))?;
            }
            println!("{}", serde_json::to_string(&summary)?);
        }
        Cmd::Report { session_id } => {
            let report = summarize_session(&store, &session_id)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Cmd::Tui { session_id } => {
            let sid = resolve_session_id(&store, session_id)?;
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

    fn exec(&self, query: &str) -> Result<()> {
        self.run(&["dolt", "sql", "-q", query]).map(|_| ())
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
    store.exec(&format!(
        "INSERT INTO sessions(session_id, started_at, project_root, branch, model_family) \
         VALUES ('{}','{}','{}','{}','{}') \
         ON DUPLICATE KEY UPDATE started_at=VALUES(started_at), project_root=VALUES(project_root), branch=VALUES(branch), model_family=VALUES(model_family)",
        sql(session_id),
        sql(&started_at),
        sql(&project_root.display().to_string()),
        sql(branch),
        sql(model_family)
    ))?;
    store.exec(&format!(
        "INSERT INTO artifacts(artifact_id, session_id, artifact_type, path_or_key, sha256, captured_at) \
         VALUES ('{}','{}','history_jsonl','{}','{}','{}')",
        artifact_id,
        sql(session_id),
        sql(&history_path.display().to_string()),
        sha256_hex(&raw),
        iso_now()
    ))?;

    let mut events = 0usize;
    let mut turns = 0usize;
    let mut windows = 0usize;
    let mut seen_sources = std::collections::HashSet::<String>::new();
    let mut prev_total: Option<i64> = None;

    for (idx, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let obj: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let event_time = obj
            .get("timestamp")
            .or_else(|| obj.get("created_at"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| started_at.as_str())
            .to_string();
        let event_type = infer_event_type(&obj);
        let tool_name = obj.get("tool_name").and_then(Value::as_str).unwrap_or("");
        let hook_name = obj
            .get("hook_event_name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let fp = format!("{event_type}|tool={tool_name}|hook={hook_name}");
        let source_id = format!("source-{}", sha1_short(&fp));
        if !seen_sources.contains(&fp) {
            store.exec(&format!(
                "INSERT INTO sources(source_id, source_kind, plugin_id, hook_name, mcp_server_name, tool_name, fingerprint) \
                 VALUES ('{}','{}',NULL,'{}',NULL,'{}','{}') \
                 ON DUPLICATE KEY UPDATE source_kind=VALUES(source_kind), hook_name=VALUES(hook_name), tool_name=VALUES(tool_name)",
                source_id,
                source_kind(&event_type),
                sql(hook_name),
                sql(tool_name),
                sql(&fp)
            ))?;
            seen_sources.insert(fp);
        }

        let turn_id = short_id("turn");
        let input_cum = safe_i64(obj.get("input_tokens_cum").or_else(|| obj.get("input_tokens")));
        let output_cum = safe_i64(obj.get("output_tokens_cum").or_else(|| obj.get("output_tokens")));
        let cache_read = safe_i64(
            obj.get("cache_read_tokens_cum")
                .or_else(|| obj.get("cache_read_tokens")),
        );
        let cache_write = safe_i64(
            obj.get("cache_write_tokens_cum")
                .or_else(|| obj.get("cache_write_tokens")),
        );
        let payload_bytes = serde_json::to_string(&obj).map(|s| s.len()).unwrap_or(0);

        store.exec(&format!(
            "INSERT INTO turns(turn_id, session_id, turn_index, started_at, ended_at, input_tokens_cum, output_tokens_cum, cache_read_tokens_cum, cache_write_tokens_cum, cost_cum_usd) \
             VALUES ('{}','{}',{},'{}','{}',{},{},{},{},NULL)",
            turn_id,
            sql(session_id),
            idx,
            sql(&event_time),
            sql(&event_time),
            sql_num(input_cum),
            sql_num(output_cum),
            sql_num(cache_read),
            sql_num(cache_write),
        ))?;
        turns += 1;

        store.exec(&format!(
            "INSERT INTO events(event_id, session_id, turn_id, event_time, event_type, source_id, payload_bytes, raw_ref) \
             VALUES ('{}','{}','{}','{}','{}','{}',{},'{}:{}')",
            short_id("event"),
            sql(session_id),
            turn_id,
            sql(&event_time),
            event_type,
            source_id,
            payload_bytes,
            artifact_id,
            idx
        ))?;
        events += 1;

        let total = input_cum.unwrap_or(0) + output_cum.unwrap_or(0) + cache_read.unwrap_or(0) + cache_write.unwrap_or(0);
        if let Some(prev) = prev_total {
            let delta = total - prev;
            if delta >= 1000 {
                windows += 1;
                store.exec(&format!(
                    "INSERT INTO windows(window_id, session_id, start_time, end_time, reason, delta_tokens, delta_cost_usd) \
                     VALUES ('{}','{}','{}','{}','spike',{},NULL)",
                    short_id("window"),
                    sql(session_id),
                    sql(&event_time),
                    sql(&event_time),
                    delta
                ))?;
            }
        }
        prev_total = Some(total);
    }

    store.exec(&format!(
        "UPDATE sessions SET ended_at='{}' WHERE session_id='{}'",
        iso_now(),
        sql(session_id)
    ))?;

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
        "SELECT s.source_kind, COALESCE(s.tool_name, '') AS tool_name, COALESCE(s.hook_name, '') AS hook_name, COUNT(*) AS event_count \
         FROM events e JOIN sources s ON e.source_id = s.source_id \
         WHERE e.session_id='{}' \
         GROUP BY s.source_kind, s.tool_name, s.hook_name \
         ORDER BY event_count DESC LIMIT 5",
        sql(session_id)
    ))?;
    let spikes = store.query_rows(&format!(
        "SELECT start_time, delta_tokens FROM windows WHERE session_id='{}' ORDER BY delta_tokens DESC LIMIT 5",
        sql(session_id)
    ))?;

    let mut out = session_rows[0].clone();
    if let Some(obj) = out.as_object_mut() {
        if let Some(c) = counts.first().and_then(Value::as_object) {
            for (k, v) in c {
                obj.insert(k.clone(), v.clone());
            }
        }
        obj.insert("top_sources".to_string(), Value::Array(top_sources));
        obj.insert("spikes".to_string(), Value::Array(spikes));
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

fn run_tui(store: &SherlockStore, session_id: &str) -> Result<()> {
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
        "SELECT s.source_kind, COALESCE(s.tool_name, '') AS tool_name, COALESCE(s.hook_name, '') AS hook_name, COUNT(*) AS event_count \
         FROM events e JOIN sources s ON e.source_id=s.source_id \
         WHERE e.session_id='{}' \
         GROUP BY s.source_kind, s.tool_name, s.hook_name \
         ORDER BY event_count DESC LIMIT 8",
        sql(session_id)
    ))?;
    let spikes = store.query_rows(&format!(
        "SELECT start_time, end_time, reason, COALESCE(delta_tokens,0) AS delta_tokens \
         FROM windows WHERE session_id='{}' ORDER BY delta_tokens DESC LIMIT 8",
        sql(session_id)
    ))?;

    enable_raw_mode()?;
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
                        Cell::from(get_str(r, "hook_name")),
                        Cell::from(get_i64(r, "event_count").to_string()),
                    ])
                })
                .collect();
            let source_table = Table::new(
                source_rows,
                [
                    Constraint::Length(12),
                    Constraint::Length(22),
                    Constraint::Length(22),
                    Constraint::Length(12),
                ],
            )
            .header(
                Row::new(vec!["kind", "tool", "hook", "events"])
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
    if obj.get("tool_name").is_some() {
        return "tool_call".to_string();
    }
    if obj.get("hook_event_name").is_some() {
        return "hook_event".to_string();
    }
    if obj.get("role").and_then(Value::as_str) == Some("user") {
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

fn sql(s: &str) -> String {
    s.replace('\'', "''")
}

fn sql_num(v: Option<i64>) -> String {
    match v {
        Some(x) => x.to_string(),
        None => "NULL".to_string(),
    }
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
