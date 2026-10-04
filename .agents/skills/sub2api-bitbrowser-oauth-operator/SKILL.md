---
name: sub2api-bitbrowser-oauth-operator
description: Use this skill when generating or exchanging a Sub2API OpenAI or Google Gemini OAuth import through the fixed BitBrowser profile named us001_codex. It enforces exact-name matching, provider-isolated encrypted pools, runtime-only administrator credentials, callback-state validation, and status-only logging.
---

# Sub2API BitBrowser OAuth operator

## Workflow

1. On the workstation where BitBrowser runs, set `BITBROWSER_API_URL` and use
   `check` to confirm one non-deleted exact `us001_codex` match. Missing or
   duplicate names stop the operation.
2. Inject exactly one Sub2API administrator credential at runtime. Never read
   `.env`, shell history, Curator records, or account exports into a commit.
3. Run `npm run start` to call `POST /admin/openai/generate-auth-url` and
   navigate the returned URL in `us001_codex`. The profile is pre-created;
   creation/deletion/cleanup is prohibited.
4. Run `npm run run` for callback exchange only. Run `npm run import-account`
   for a complete account import: it waits for the localhost callback, checks
   the generated state, exchanges the code, then follows the deployed
   administrator UI contract to create a missing exact-email account or apply
   OAuth credentials to its single existing exact-email account.
5. Treat exchange HTTP 200 as an intermediate result. A complete import is
   successful only after `GET /admin/accounts` shows the exact email.
6. For a Google Gemini import, select one `stored` row only from the separate
   `.runtime/google-account-pool.dpapi`, default consumer accounts to
   `google_one`, use the supported Gemini auth/exchange endpoints, and require
   the exact `platform=gemini` account name in a fresh final list read before
   marking the row `imported`.
7. For an explicit login-status-only request, `probe-accounts` may read account
   rows from standard input and stop at OAuth consent or phone verification.
   It must not click consent, claim a phone, wait for or exchange a callback,
   import an account, or persist the input rows.
8. Retry a prior `account_banned` reauthorization result only after an explicit
   `reauthorize-errors --retry-banned` request. This does not opt into account
   replacement; `--replace-banned` remains a separate explicit mutation.
9. When phone verification is shown, poll the SMS API in two six-attempt,
   one-minute rounds. When the selected phone policy permits, click
   `Resend text message` once only after the first round fails; otherwise do
   not click it. After the second failure, call the injectable no-op
   `PhoneStatusApi.markInvalid` boundary and stop. On Windows, a Node TLS
   transport failure may use the hidden native HTTP fallback; it remains a
   direct API request and must not inherit administrator credentials.
10. Keep the browser open for review. Only an explicit `--close-window` may
   call the close endpoint; deletion is not implemented.
11. When using the local queue, persist rows only through current-user Windows
   DPAPI in the Git-ignored `.runtime` directory. Enforce the 45-minute phone
   cooldown from actual submission. Respect each phone's resend policy; pool
   imports default to no resend.
12. Reset phone cooldowns only on an explicit operator request. Preserve the
   prior use time, reset time, and reset count in the encrypted pool; never
   restore invalid phones through a cooldown reset.
13. Restore an invalid-marked phone only after explicit operator confirmation
    through the dedicated correction command, with correction audit fields.
    Change queued-phone resend policy only through its explicit policy command.
14. Replace a provider-banned Workstation account only after an explicit
    `inventory-ban-and-replace --email` request or `reauthorize-errors
    --replace-banned`. Persist its idempotency key in DPAPI before the request,
    reuse it after an unknown result, and never print ban or replacement rows.
15. Treat pending-replacement extraction as secret-bearing. The library may
    call it only with an approved private consume callback, then redact its
    returned metadata. Do not expose a CLI that prints or discards the batch.
16. A Google OAuth run may use `--direct-browser-egress` only after read-only
    checks prove the fixed profile proxy cannot reach Google while workstation
    direct egress can. This is a launch-only `--no-proxy-server` override; do
    not rewrite the saved proxy. Close exact `us001_codex` only with explicit
    owner authorization, then immediately reopen it for the bounded attempt.

## Verification and failure handling

- Run `npm test`, `npm run syntax`, and the exact-name `check` before use.
- Treat exchange HTTP 200 as insufficient account verification; require the
  supported account create/update response and exact-email list postcondition.
- For Google, accept only the allowlisted authorization/callback hosts and an
  exact state match. Stop on unsupported verification challenges and never
  expose the encrypted row, OAuth URL/code/state, token response, or cookies.
- Do not modify NewAPI channels/abilities, PostgreSQL, Redis, proxy bindings,
  DNS, Cloudflare, or production containers as part of this workflow.
- If exchange fails, report only a sanitized HTTP/status error and leave the
  profile available. Never print callback codes, OAuth URL/state, tokens,
  cookies, or raw account data.
