# sub2api-bitbrowser-oauth

This repository is a focused Codex/Claude helper for one pre-created BitBrowser
profile and the Sub2API OpenAI OAuth account-import flow.

## Work types

- Read-only discovery and reporting: inspect the configured Sub2API account
  list, encrypted pool summaries, health categories, scheduling state, and the
  exact `us001_codex` BitBrowser match. Report counts and statuses by default;
  print email lists only when the operator explicitly asks for them.
- Account import: import one explicitly supplied or queued account through the
  complete BitBrowser login, OAuth callback exchange, Sub2API create/update,
  and exact-email verification workflow.
- Login-only probing: determine whether supplied credentials reach consent or
  phone verification without exchanging OAuth, claiming a phone, importing, or
  persisting the supplied rows.
- Account health and repair: run the supported Sub2API connection test, rebuild
  the redacted encrypted audit, reauthorize retryable HTTP 401/OAuth-token
  failures, distinguish confirmed provider bans from recoverable route errors,
  and verify the final list state.
- Scheduling management: change `schedulable` only after an explicit operator
  request and verify the requested state by reading the account list again.
- Account deletion: delete only the operator's explicit exact-email targets by
  the guarded deletion invariant below; keep local DPAPI login material.
- Pool and Workstation inventory operations: synchronize account material into
  DPAPI, claim a phone only at the OpenAI phone page, enforce cooldown/resend
  rules, and use the documented idempotent replacement workflow only when
  explicitly requested.
- Code, documentation, verification, and release work: preserve unrelated
  worktree changes, use tests proportional to the change, and commit, push, or
  deploy only when the operator asks for that external action.

## Standard operator workflows

### Common preflight

1. Treat `https://sub2apiplus.opencodex.uk` as the production Sub2API account
   pool and default base URL unless the operator explicitly selects a different
   instance.
2. Read the applicable repository skill, inspect `git status`, and preserve all
   unrelated or pre-existing changes.
3. Inject exactly one administrator credential into the current process. Do
   not source, echo, log, persist, or pass it to unrelated child processes.
4. Before browser OAuth work, run `npm test`, `npm run syntax`, and
   `npm run check`. Stop if any check fails or `us001_codex` is missing or
   ambiguous.
5. Keep production output status-only. Never print passwords, TOTP secrets,
   phone tokens, administrator credentials, OAuth URLs/codes, cookies, or raw
   account payloads.

### Full health test, reauthorization, and scheduling

1. Read `GET /admin/accounts` and record the total, status distribution, and
   current `schedulable` distribution without exposing account payloads.
2. Test accounts sequentially through
   `POST /admin/accounts/:id/test`; avoid a parallel burst against the upstream
   provider. A successful HTTP response only means the test request ran.
3. Read `GET /admin/accounts` again after all tests. Treat this post-test list,
   not the test endpoint response alone, as the authoritative health result.
   Persist the latest redacted instance-scoped audit through
   `account-health-audit`.
4. Reauthorize post-test `status=error` records classified as explicit HTTP 401
   or invalid/revoked OAuth tokens only when an exact local DPAPI login match
   exists. Process them sequentially and stop the batch on a real OpenAI rate
   limit.
5. The page error `Unexpected token '<' ... <!DOCTYPE ... is not valid JSON`,
   an invalid `text/html` content type, or an OpenAI Route Error 500 is a
   recoverable route failure, not a ban. Release the current incognito context,
   generate a fresh OAuth authorization session, and retry the complete login
   flow once. Only explicit provider text such as `account_deactivated`,
   banned, suspended, disabled, or terminated confirms a ban.
6. After reauthorization, read the full list again and rebuild the redacted
   audit. Count a reauthorization as successful only when the exact account is
   visible with the repaired state.
7. When the operator requests scheduling, call
   `POST /admin/accounts/:id/schedulable` with `{ "schedulable": true }` for
   each requested exact account, then re-read the full list and verify there
   are no unexpected disabled or missing scheduling values.

### Import and probe

1. For inventory-backed imports, synchronize remote account inventory into the
   encrypted local pool before selection. Never print the imported rows.
2. Open only the exact `us001_codex` profile and generate a new OAuth session
   for the selected account. On a recoverable route failure, discard that
   authorization session and retry once with a newly generated one.
3. A full import must validate callback state, exchange the code, create or
   update the exact account through the supported endpoints, and verify the
   exact email in a final list read.
4. A probe must stop before consent or phone verification and must not exchange
   a callback, mutate Sub2API, allocate a phone, or persist its input.

### Controlled deletion

1. Obtain the exact email targets from the operator's explicit request; do not
   recompute or expand the set from current status alone.
2. Before every deletion, re-read the account list and require exactly one
   case-insensitive exact-email match.
3. Delete that single ID through `DELETE /admin/accounts/:id`. After all
   deletions, re-read the full list and require every requested exact email to
   be absent.
4. Refresh the redacted DPAPI health audit after deletion, but retain local
   encrypted login material unless the operator separately and explicitly
   authorizes its removal.
5. Report how many records were deleted, how many were verified absent, and the
   final account/status/scheduling counts. State that Sub2API deletion is not
   recoverable through this tool.

## Invariants

- The default BitBrowser profile is the exact name `us001_codex`.
- The controller must never create, delete, clear, refresh, or close a different
  profile. A missing or duplicate exact name is a hard error.
- Releasing a session disconnects Playwright only; the named BitBrowser window
  remains open unless an operator explicitly passes `--close-window`.
- OAuth authorization is called through the supported administrator endpoints:
  `POST /admin/openai/generate-auth-url` and
  `POST /admin/openai/exchange-code`.
- A complete `import-account` follows the deployed administrator UI contract:
  it reads `GET /admin/accounts`, then calls `POST /admin/accounts` for a new
  exact email or `POST /admin/accounts/:id/apply-oauth-credentials` for an
  existing exact email. Success requires a final exact-email list check.
- Phone verification uses two six-request, one-minute SMS polling rounds. Only
  the boundary between rounds clicks `Resend text message`; after the second
  failure the no-op `PhoneStatusApi` integration point is called and import
  stops.
- Administrator credentials are runtime-only (`SUB2API_ADMIN_TOKEN`,
  `SUB2API_ADMIN_API_KEY`, or `SUB2API_ADMIN_COOKIE`). Never commit, print, or
  persist tokens, callback codes, OAuth URLs, cookies, or account payloads.
- Local phone/account pools are the only persistence exception: they must use
  current-user Windows DPAPI in the Git-ignored `.runtime` directory. Plaintext
  pool files, CLI row output, and child-process administrator credential
  inheritance are prohibited.
- A phone cooldown starts on actual OpenAI submission and lasts 45 minutes.
  Pool-imported phone entries default to no resend, even though direct
  `import-account` retains the explicit one-resend workflow.
- Cooldowns may be cleared only by an explicit operator request through
  `pool-reset-phone-cooldowns`; the encrypted pool must retain reset audit
  timestamps and counts. Invalid phone entries are never restored by reset.
- An invalid phone may be restored only after explicit operator confirmation
  through `pool-correct-invalid-phone`; correction timestamps/counts must be
  audited. Resend policy changes require the explicit `pool-enable-resend`
  command.
- Workstation inventory integration reads account import lines and uses the
  atomic phone claim endpoint only when OpenAI reaches the phone page. Its
  Bearer token is process-only and must not be loaded from a repository runtime
  file. Claim idempotency keys and remote phone IDs may be retained only inside
  the encrypted local pool.
- `account-health-audit` may retain only redacted error-account health records
  in the encrypted DPAPI pool. `reauthorize-errors` processes only error rows
  with matching pool login material, always skips management-classified
  banned/disabled rows, and retries a prior `account_banned` outcome only when
  the operator explicitly passes `--retry-banned`. It stops on OpenAI rate
  limiting.
- Sub2API account deletion is permitted only after an explicit operator request
  identifying the accounts by exact email. Before each deletion, read
  `GET /admin/accounts` and require exactly one case-insensitive exact-email
  match; a missing or duplicate match is a hard error. Delete only through the
  supported administrator endpoint `DELETE /admin/accounts/:id`, then require a
  final account-list check proving that the exact email is absent. Never infer
  deletion targets from status alone, use a broad/bulk deletion, delete local
  pool login material, or print account credentials while deleting.
- `probe-accounts` accepts account rows through standard input only and keeps
  them in memory. It stops at OAuth consent or phone verification, never clicks
  consent, never claims a phone, never exchanges a callback, and never imports
  or persists an account row.
- Outside that explicit Sub2API OAuth account create/update, this tool does not
  change NewAPI channels, abilities, proxy bindings, DNS, Cloudflare, or
  production containers. The only Workstation account mutation exposed as an
  operator workflow is an explicit, idempotent `ban-and-replace` request
  through the documented automation API; direct account-file or database
  writes remain prohibited.
- Workstation banned-account replacement requires an exact local email and an
  explicit operator command or `--replace-banned` option. Persist the stable
  idempotency key in DPAPI before the request, reuse it after an unknown result,
  and never print banned or replacement credential rows.
- Pending-replacement extraction returns complete account material and has no
  CLI in this tool. Do not call it without an approved private output sink.

## Commands

```bash
npm ci
npm test
npm run syntax
npm run check                         # exact-name BitBrowser read-only check
npm run start                         # generate + open, leave window open
npm run run                           # generate, wait callback, exchange only
npm run import-account                # login, exchange, create/update, verify
npm run probe-accounts                # login/ban check only; stdin, no import
npm run import-next                   # first pending account + available phone
npm run inventory-sync-accounts      # remote accounts -> encrypted local pool
npm run inventory-import-next        # remote account/phone allocation workflow
npm run account-health-audit          # encrypted redacted account status list
npm run reauthorize-errors            # guarded sequential error-account retry
npm run pool-status                   # status-only encrypted pool summary
```

Use a runtime environment or a secret manager injector for the administrator
credential. `.env.example` contains names only.

## Source lineage

The BitBrowser client/controller behavior was extracted from
`repos/plus_paypal/src/browser/driver.js` and
`repos/plus_paypal/src/browser/bitbrowser-module/`, then narrowed to a fixed
window controller. The original repository remains independent and unchanged.
