# Claude Code — live quota API (`/api/oauth/usage`)

Notes extracted while building i3bar usage blocks on 2026-04-19. This is the
same data that powers `/usage` inside Claude Code. A first-class Sherlock data
source candidate — the transcript-based JSONL math only estimates; this
endpoint is authoritative for the user's 5h window, 7d window, per-model usage,
and overage-credits status.

## TL;DR

```bash
TOKEN=$(jq -r '.claudeAiOauth.accessToken' ~/.claude/.credentials.json)
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  -H "anthropic-beta: oauth-2025-04-20" \
  https://api.anthropic.com/api/oauth/usage
```

Returns live utilization percentages against the user's subscription limits.

## Example response

```json
{
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
}
```

Field notes:

- `five_hour` / `seven_day` — primary windows shown in `/usage`. `utilization`
  is a percentage (0–100+); `resets_at` is ISO-8601 UTC.
- `seven_day_opus`, `seven_day_sonnet`, `seven_day_cowork`, `seven_day_oauth_apps`,
  `seven_day_omelette` — per-model / per-surface sub-limits. `null` when the
  user's plan does not have that sub-limit carved out.
- `iguana_necktie`, `omelette_promotional` — internal / promotional buckets.
  Leave as opaque fields; do not hard-code assumptions.
- `extra_usage` — pay-as-you-go overage after subscription limits are hit.
  `monthly_limit` / `used_credits` are in `currency`. When `utilization >=
  100`, the user is paying per-request.

## Credentials

Local storage: `~/.claude/.credentials.json` (mode 0600). Shape:

```json
{
  "claudeAiOauth": {
    "accessToken":       "<108-char opaque>",
    "refreshToken":      "<108-char opaque>",
    "expiresAt":         1776664254430,
    "scopes": [
      "user:file_upload", "user:inference", "user:mcp_servers",
      "user:profile", "user:sessions:claude_code"
    ],
    "subscriptionType":  "max",
    "rateLimitTier":     "default_claude_max_5x"
  },
  "mcpOAuth": { ... }
}
```

`expiresAt` is a unix-ms timestamp. Tokens are short-lived (~hours), so long-
running consumers need to refresh.

## Token refresh

OAuth token endpoint (discovered via `strings` of the Claude Code ELF):

```
https://platform.claude.com/v1/oauth/token
```

Standard OAuth2 refresh grant:

```bash
curl -sS -X POST https://platform.claude.com/v1/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type":"refresh_token","refresh_token":"<refreshToken>","client_id":"<client_id>"}'
```

**Open item:** `client_id` was not cleanly extractable from the `strings` dump
— the UUID is embedded behind bundled JS. Either (a) sniff `claude`'s HTTPS
traffic once with `mitmproxy` to capture the `client_id`, or (b) rely on
Claude Code itself to refresh the credentials file and just re-read it from
consumers. Option (b) is what the i3bar block does today — if the API returns
401, back off and wait for the user's next `claude` session to refresh the
file on disk.

## How these URLs were found

```bash
BIN=/home/lunaris/.local/share/claude/versions/$(readlink -f ~/.local/bin/claude | xargs basename)

# API paths
strings "$BIN" | grep -oE '/api/[[:alnum:]_/-]+' | sort -u

# Full URLs
strings "$BIN" | grep -oE 'https?://[a-zA-Z0-9.-]+(anthropic|claude)\.[a-z]+[a-zA-Z0-9_/.-]*' | sort -u

# OAuth-specific
strings "$BIN" | grep -oE '/api/oauth/[[:alnum:]_/-]+' | sort -u

# client_id hunt (UUIDs)
strings "$BIN" | grep -oE '"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"' | sort -u
```

## Other useful OAuth-backed endpoints seen in the binary

| Endpoint                                       | Likely purpose |
|------------------------------------------------|----------------|
| `GET  /api/oauth/usage`                        | **This doc.** Live quota. |
| `GET  /api/oauth/profile`                      | User profile / org info. |
| `GET  /api/oauth/account/settings`             | Account settings. |
| `POST /api/oauth/claude_cli/create_api_key`    | Provisions a raw API key from an OAuth session. |
| `GET  /api/oauth/claude_cli/roles`             | Role membership. |
| `POST /api/oauth/file_upload`                  | Upload flow used by `claude file add`. |
| `GET  /api/claude_code/policy_limits`          | Org-level policy limits (non-OAuth path). |
| `GET  /api/claude_code/notification/preferences` | Notification prefs. |

The `anthropic-beta: oauth-2025-04-20` header appears to be required on the
OAuth-scoped endpoints. Without it some return 404 or 401.

## Implementation sketch (Sherlock `oauth-usage` source)

- New provider or sidecar source: `src/providers/claude_code_oauth.rs`
  fetching `/api/oauth/usage` on demand (cache 60s).
- Expose columns: `window`, `utilization_pct`, `resets_at`, `currency`,
  `used_credits`, `monthly_limit`, `subscription_type`, `rate_limit_tier`.
- Join with existing `claude_code` JSONL provider to cross-check: JSONL-based
  7d cost (`ccusage`-style) vs. Anthropic-reported `seven_day.utilization` —
  wide divergence would flag billing surprises.
- Do not write to the credentials file. Consumers read-only.

## Security

- Treat `accessToken` / `refreshToken` like passwords. Never log, never send
  to telemetry, never include in agent traces. Redact on ingest.
- `~/.claude/.credentials.json` is 0600 user-owned; preserve those perms if
  Sherlock ever re-writes (it shouldn't — read-only).
- The `/api/oauth/usage` endpoint only exposes the authenticated user's own
  data; no cross-account leakage.
