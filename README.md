# Sub2API BitBrowser OAuth

This small Node.js service opens the Sub2API OpenAI OAuth authorization flow in
the already-created BitBrowser window `us001_codex`.

It uses the same BitBrowser API/CDP approach as `plus_paypal`, but intentionally
does not use its random-window/cleanup mode. The exact-name controller is the
only browser path in this repository.

## Setup

```bash
npm ci
cp .env.example .env        # names only; inject values through your runtime
```

Required runtime values:

- `BITBROWSER_API_URL` (default `http://127.0.0.1:54345`)
- `BITBROWSER_WINDOW_NAME` (default `us001_codex`)
- `SUB2API_BASE_URL` (default `https://sub2apipro.opencodex.uk`)
- `SUB2API_API_PREFIX` (default `/api/v1`, matching the deployed frontend)
- one of `SUB2API_ADMIN_TOKEN`, `SUB2API_ADMIN_API_KEY`, or
  `SUB2API_ADMIN_COOKIE`

The production `SUB2API_ADMIN_API_KEY` is canonical in OpenBao at
`projects/sub2api/prod/bitbrowser-oauth` (KV mount `projects`, field
`admin_api_key`). On `ydy001` it is materialized only as the ACL-restricted
`.runtime/admin.env` file, which is ignored by Git. Do not copy that value into
`.env.example`, source files, docs, or command output. The CLI automatically
loads this allowlisted runtime file for `start`, `run`, and `import-account`;
an already-defined process environment variable takes precedence.

## Usage

First perform a read-only exact-name check:

```bash
npm run check
```

Generate the supported OpenAI OAuth URL through Sub2API and open it in
`us001_codex` launched with BitBrowser's `--incognito` startup argument:

```bash
npm run start
```

The URL is deliberately not printed. Complete login in the opened incognito
window. The window must be closed and relaunched for the startup argument to
take effect if it was already running.
For the complete interactive flow, including callback detection at
`localhost:1455/auth/callback` and supported exchange/import:

```bash
npm run run
```

For a repeatable account import, inject the account values only into the
process environment and run:

```bash
npm run import-account
```

The importer selects `Log in to another account`, submits the email and
password, calculates the local RFC 6238 SHA-1 TOTP, and then inspects the
OpenAI route. If the account is already phone-bound, it goes directly to the
consent page. If `/add-phone` and `/phone-verification` appear, it normalizes
the US number by removing a leading `1`, requests the SMS endpoint directly
(six attempts, 10 seconds apart). If the first one-minute round has no code,
it clicks `Resend text message` once on the current verification page and runs
one more six-attempt round. It extracts a six-digit code in memory and
continues. It captures the localhost callback request before Chromium can turn
the failed localhost navigation into a Chrome error page, validates the OAuth
state, and calls the supported Sub2API exchange endpoint.

Required process-only values for `import-account` are
`OPENAI_ACCOUNT_EMAIL`, `OPENAI_ACCOUNT_PASSWORD`, and `OPENAI_TOTP_SECRET`.
`OPENAI_PHONE` and `SMS_ACCESS_URL` are required only when OpenAI asks for
phone verification. No account value, SMS response, callback code, OAuth URL,
or administrator credential is printed or persisted.

If both one-minute SMS rounds fail, the importer calls the injectable
`PhoneStatusApi.markInvalid({ phone, reason, attempts })` integration point and
then stops. Its default implementation is intentionally a no-op with no network
request; a future phone-provider adapter can implement that method without
changing the OAuth flow.

SMS polling first uses Node HTTPS. On Windows, a transport-level TLS failure
falls back to `Invoke-WebRequest` in a hidden, non-interactive PowerShell child
process. The URL is passed only through that child's restricted environment,
not its arguments, and administrator credentials are not inherited. This is
still a direct API request; no browser page is opened.

The Sub2API administrator UI is served at the configured base URL (the
deployment default is `https://sub2apipro.opencodex.uk`), with accounts at
`/admin/accounts`; the API prefix is `/api/v1`.

`start` and `run` default to `--incognito` through the npm scripts. Direct CLI
use may omit the flag when the persistent profile context is intentionally
required. `run` leaves the named window open after disconnecting the CDP client.
It does not print callback codes or account data.

`import-account` does more than exchange the callback. It maps the exchanged
OpenAI result with the same allowlist as the deployed administrator frontend,
looks up an existing exact email, and then uses `POST /admin/accounts` or
`POST /admin/accounts/:id/apply-oauth-credentials` as appropriate. It reports
success only after a fresh `GET /admin/accounts` confirms the exact email.

## Encrypted local import pool

Pending accounts and phone/SMS pairs can be fed through stdin into a local
Windows DPAPI-encrypted pool:

```bash
npm run pool-import-phones < phones.txt
npm run pool-import-accounts < accounts.txt
npm run pool-status
npm run pool-reset-phone-cooldowns
npm run pool-correct-invalid-phone
npm run pool-enable-resend
npm run import-next
```

The encrypted file is `.runtime/import-pool.dpapi`, which is Git-ignored and
bound to the current Windows user by DPAPI. The CLI never prints pool rows.
Phone entries use a 45-minute cooldown starting only when the number is
actually submitted to OpenAI. `import-next` selects the first pending account
and first available phone, records a successful Sub2API import, and leaves a
failed account pending for a later retry.

`pool-reset-phone-cooldowns` is an explicit operator override. It clears only
cooldowns on non-invalid phones and preserves the previous use timestamp,
reset timestamp, and reset count inside the encrypted pool for auditability.

When an operator independently confirms a previously invalid-marked number
actually completed binding, `pool-correct-invalid-phone` restores the first
invalid row to cooldown and records the correction timestamp/count. The command
also enables its one-resend policy. `pool-enable-resend` enables one-resend for
all non-invalid rows and records the policy change time.

Phone batches imported through `pool-import-phones` default to a no-resend
policy: two one-minute, six-request SMS rounds are allowed, but the OpenAI
`Resend text message` control is not clicked. Direct `import-account` keeps its
existing one-resend behavior unless its runtime policy is changed in code.

## Workstation inventory integration

The production account inventory and phone binding counter can be consumed
through the API contract in `WORKSTATION_AUTOMATION_API.md`:

```bash
npm run inventory-sync-accounts
npm run inventory-import-next
npm run inventory-ban-pool-status
npm run inventory-ban-and-replace -- --email account@example.com
npm run probe-accounts < accounts.txt
npm run test:dependencies
```

Set `WORKSTATION_AUTOMATION_TOKEN` in the calling process through OpenBao or a
secret-manager injector. The project runtime env file does not load this token;
it is never printed, persisted, or passed to child processes. The optional
`WORKSTATION_AUTOMATION_BASE_URL` defaults to
`https://workstation.opencodex.uk`.

The canonical production document and token are stored in OpenBao at
`projects/opencodex/prod/cliproxy-inventory-api` (KV v2; read current metadata
before a CAS update). The local API document is explicitly ignored by Git
because it contains the production credential.

`inventory-sync-accounts` reads the complete remote `import-lines` response and
merges it into `.runtime/import-pool.dpapi`. Removed remote rows are no longer
eligible for new attempts. Plaintext account rows remain in memory only.

`inventory-import-next` syncs accounts before selecting the first pending row.
If OpenAI reaches the phone page, it first checks that the remotely eligible
phone has a matching local DPAPI SMS URL, persists an idempotency key, and then
uses the atomic phone claim endpoint. A transport-ambiguous claim retains that
key for the next retry. A definitive rejection retires it with an encrypted
audit record. The command does not claim a phone when the account reaches
consent without phone verification.

The Workstation API intentionally does not return SMS access URLs. Import the
local phone-to-SMS mappings first with `pool-import-phones`; those rows keep the
default no-resend policy. After two failed SMS rounds, the integration marks
the claimed remote phone unavailable and preserves pending sync state if that
status update fails.

`inventory-ban-pool-status` reads only redacted counts from the retained ban
pool. `inventory-ban-and-replace -- --email ...` is the explicit account
replacement operation: it saves a stable idempotency key in DPAPI before the
request, lets Workstation atomically select the replacement, and then
resynchronizes the active account inventory. An unknown result keeps the key
for replay; a definitive business rejection archives the attempt. Neither
command returns or prints banned or replacement credential lines.

The client library validates the documented one-time pending-replacement batch
endpoint but deliberately exposes no CLI for it. Calling it requires a private
`consume` callback that receives the complete in-memory batch before the method
returns only redacted metadata. The callback must write to an approved private
destination; silently discarding or printing the batch would break the API
contract.

`probe-accounts` is a login-status-only workflow. It accepts temporary
`email|password|TOTP` rows from standard input, uses an isolated context in the
fixed BitBrowser profile, and stops as soon as consent or phone verification is
reached. It never clicks consent, claims a phone, exchanges a callback, writes
Sub2API account data, or persists the input rows.

## Error-account health and reauthorization

```bash
npm run account-health-audit
npm run reauthorize-errors -- --limit 1
npm run reauthorize-errors -- --email account@example.com --replace-banned
```

`account-health-audit` reads the supported administrator account list and saves
only a redacted health record in the DPAPI pool: account ID, normalized email,
status, error category, a one-way error fingerprint, and whether matching login
material exists in the encrypted pool. It never writes the raw error message,
password, TOTP secret, OAuth token, or account response to a plaintext file.

`reauthorize-errors` processes only `status=error` accounts with matching local
login material, skips records already classified as banned/disabled, and stops
the whole batch at the first OpenAI rate-limit response. A successful run still
requires OAuth state validation, exchange, and the exact-email Sub2API account
postcondition. A banned/deactivated OpenAI page is recorded as `account_banned`
and is never retried automatically.

`--replace-banned` is an explicit Workstation mutation opt-in. It applies only
when the current login attempt returns `account_banned`, then uses the same
DPAPI-backed replacement coordinator and synchronizes the promoted replacement
into the local pending queue. Without the flag, reauthorization does not mutate
Workstation inventory. Historical banned outcomes never trigger a replacement
automatically.

If the opened OpenAI authorization page shows `Oops, an error occurred` with
`Route Error (500 Internal Server Error)`, the importer treats the OAuth session
as stale: it releases the current Playwright connection, generates a fresh
authorization URL through Sub2API, and reopens it in the same exact
`us001_codex` BitBrowser window. This session-level regeneration is limited to
three retries and does not consume a phone or mark the account as banned.

The current supported Sub2API administrator contract has no account-delete
endpoint. This project therefore does not delete production accounts or infer a
delete route from the web UI. The encrypted health audit remains the durable
list of accounts needing attention, accounts identified as banned, and
reauthorization outcomes.

`test:dependencies` exercises a fake account and fake phone through the real
Windows DPAPI store, Workstation client, idempotent claim coordinator, cooldown,
and invalidation path against a loopback server. It deletes the isolated test
pool afterward. It also performs read-only production checks against the
Workstation account inventory, Sub2API account list, and exact BitBrowser
window. It never creates a production test account or claims a production
phone, because the supported production APIs do not provide matching create
and cleanup operations for those test records.

## Safety

The helper fails closed if `us001_codex` is absent or ambiguous. It never
creates/deletes profiles and does not touch Sub2API channels or database rows
directly. The explicit OAuth account create/update is performed only through
Sub2API's administrator API, so account policy and workspace-409 handling remain
server-side.

The inventory integration changes only its documented account and phone
inventory endpoints. Account replacement stays atomic and server-owned; the
local tool does not edit Workstation account files directly. It does not change
DNS, SSH, Tailscale, Mihomo, NewAPI, Cloudflare, proxy
bindings, or production containers.

See [docs/oauth-flow.md](docs/oauth-flow.md) and
[docs/source-lineage.md](docs/source-lineage.md) for the durable workflow and
Curator context.

The route shapes, account statuses, timestamp history, one-time banned-account
replacement batches, and three-use phone rules are documented without secrets
in
[docs/workstation-inventory-automation.md](docs/workstation-inventory-automation.md).
The complete secret-bearing caller document remains local-only as
`WORKSTATION_AUTOMATION_API.md` on `ydy001`.
