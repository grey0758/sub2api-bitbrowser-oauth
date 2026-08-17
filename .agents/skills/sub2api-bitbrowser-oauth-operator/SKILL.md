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
6. For an explicit login-status-only request, `probe-accounts` may read account
   rows from standard input and stop at OAuth consent or phone verification.
   It must not click consent, claim a phone, wait for or exchange a callback,
   import an account, or persist the input rows.
7. When phone verification is shown, poll the SMS API in two six-attempt,
   one-minute rounds. When the selected phone policy permits, click
   `Resend text message` once only after the first round fails; otherwise do
   not click it. After the second failure, call the injectable no-op
   `PhoneStatusApi.markInvalid` boundary and stop. On Windows, a Node TLS
   transport failure may use the hidden native HTTP fallback; it remains a
   direct API request and must not inherit administrator credentials.
8. Keep the browser open for review. Only an explicit `--close-window` may
   call the close endpoint; deletion is not implemented.
9. When using the local queue, persist rows only through current-user Windows
   DPAPI in the Git-ignored `.runtime` directory. Enforce the 45-minute phone
   cooldown from actual submission. Respect each phone's resend policy; pool
   imports default to no resend.
10. Reset phone cooldowns only on an explicit operator request. Preserve the
   prior use time, reset time, and reset count in the encrypted pool; never
   restore invalid phones through a cooldown reset.
11. Restore an invalid-marked phone only after explicit operator confirmation
    through the dedicated correction command, with correction audit fields.
    Change queued-phone resend policy only through its explicit policy command.
12. Replace a provider-banned Workstation account only after an explicit
    `inventory-ban-and-replace --email` request or `reauthorize-errors
    --replace-banned`. Persist its idempotency key in DPAPI before the request,
    reuse it after an unknown result, and never print ban or replacement rows.
13. Treat pending-replacement extraction as secret-bearing. The library may
    call it only with an approved private consume callback, then redact its
    returned metadata. Do not expose a CLI that prints or discards the batch.

## Verification and failure handling

- Run `npm test`, `npm run syntax`, and the exact-name `check` before use.
- Treat exchange HTTP 200 as insufficient account verification; require the
  supported account create/update response and exact-email list postcondition.
- Do not modify NewAPI channels/abilities, PostgreSQL, Redis, proxy bindings,
  DNS, Cloudflare, or production containers as part of this workflow.
- If exchange fails, report only a sanitized HTTP/status error and leave the
  profile available. Never print callback codes, OAuth URL/state, tokens,
  cookies, or raw account data.
