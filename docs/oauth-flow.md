# OAuth flow

The deployed `admin/accounts` frontend uses `/api/v1` as its Axios base path;
the helper adds that prefix to these OpenAI endpoints:

1. `POST /admin/accounts/generate-auth-url` with `{}` or `{proxy_id}`.
2. `POST /admin/accounts/exchange-code` with
   `{session_id, code, state}` and optional `proxy_id`.

The first response contains `auth_url` and `session_id`; the helper derives the
OAuth `state` from the authorization URL. The URL is navigated in the exact
BitBrowser profile `us001_codex`. `run` watches every page in that profile for
`http://localhost:1455/auth/callback?code=...`, verifies a returned state when
present, and sends the code through the second endpoint.

The callback code, state, session ID, URL, token, and account payload are kept
in memory only. Logs and CLI output are status-only. A failed exchange leaves
the browser profile available for manual inspection; the controller disconnects
without closing or deleting it.

Do not substitute the older Grok/Gemini OAuth endpoints, write PostgreSQL
directly, or infer account validity from a pool-level HTTP 200. Use the
supported administrator API so the server applies its current account policy,
proxy handling, and workspace-409 rule.
