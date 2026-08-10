---
name: sub2api-bitbrowser-oauth-operator
description: Use this skill when generating or exchanging a Sub2API OpenAI OAuth import through the fixed BitBrowser profile named us001_codex. It enforces exact-name matching, runtime-only administrator credentials, callback-state validation, and status-only logging.
---

# Sub2API BitBrowser OAuth operator

## Workflow

1. On the workstation where BitBrowser runs, set `BITBROWSER_API_URL` and use
   `check` to confirm one non-deleted exact `us001_codex` match. Missing or
   duplicate names stop the operation.
2. Inject exactly one Sub2API administrator credential at runtime. Never read
   `.env`, shell history, Curator records, or account exports into a commit.
3. Run `npm run start` to call `POST /admin/accounts/generate-auth-url` and
   navigate the returned URL in `us001_codex`. The profile is pre-created;
   creation/deletion/cleanup is prohibited.
4. Run `npm run run` when an end-to-end import is authorized. It waits for the
   localhost callback, checks the generated state, and calls
   `POST /admin/accounts/exchange-code`.
5. Keep the browser open for review. Only an explicit `--close-window` may
   call the close endpoint; deletion is not implemented.

## Verification and failure handling

- Run `npm test`, `npm run syntax`, and the exact-name `check` before use.
- Treat pool-level HTTP 200 as insufficient account verification; rely on the
  supported Sub2API admin response and its server-side policy.
- Do not modify NewAPI channels/abilities, PostgreSQL, Redis, proxy bindings,
  DNS, Cloudflare, or production containers as part of this workflow.
- If exchange fails, report only a sanitized HTTP/status error and leave the
  profile available. Never print callback codes, OAuth URL/state, tokens,
  cookies, or raw account data.
