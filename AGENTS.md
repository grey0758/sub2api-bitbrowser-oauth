# sub2api-bitbrowser-oauth

This repository is a focused Codex/Claude helper for one pre-created BitBrowser
profile and the Sub2API OpenAI OAuth account-import flow.

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
  limiting. No account deletion route is implemented or permitted.
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
