# OAuth flow

The deployed frontend uses `/api/v1` as its Axios base path. OpenAI OAuth must
use the provider-specific routes; the similarly named `admin/accounts` routes
generate Claude authorization sessions. The helper adds the prefix to these
OpenAI endpoints:

1. `POST /admin/openai/generate-auth-url` with `{}` or `{proxy_id}`.
2. `POST /admin/openai/exchange-code` with
   `{session_id, code, state}` and optional `proxy_id`.
3. For `import-account`, `GET /admin/accounts` selects by one exact OpenAI
   email. A missing email uses `POST /admin/accounts`; one existing email uses
   `POST /admin/accounts/:id/apply-oauth-credentials`.
4. A second exact-email account-list read is the required postcondition.

The first response contains `auth_url` and `session_id`; the helper derives the
OAuth `state` from the authorization URL. The npm `start` and `run` commands
launch the exact BitBrowser profile `us001_codex` with the `--incognito` startup
argument and navigate the URL there. `run` watches every page in that window for
`http://localhost:1455/auth/callback?code=...`, verifies a returned state when
present, and sends the code through the second endpoint.

The callback code, state, session ID, URL, token, and account payload are kept
in memory only. Logs and CLI output are status-only. A failed exchange leaves
the browser profile available for manual inspection; the controller disconnects
without closing or deleting it.

## Repeatable account login

`npm run import-account` is the executable account-login variant. It uses
process-only `OPENAI_ACCOUNT_EMAIL`, `OPENAI_ACCOUNT_PASSWORD`, and
`OPENAI_TOTP_SECRET` values. The phone branch is detected from the OpenAI route:
an already-bound account reaches consent directly; `/add-phone` triggers the
normalized US number entry and `/phone-verification` triggers direct SMS API
polling in two rounds. Each round makes six attempts 10 seconds apart and lasts
at least one minute. After the first failed round the importer clicks the first
visible `Resend text message` control once on the current page, then starts the
second round. The SMS endpoint is never opened in a browser page. The callback
listener observes navigation requests as well as
final page URLs, because the localhost callback can become a Chrome error page
after the request is sent.

On Windows, a Node HTTPS transport failure uses a hidden PowerShell
`Invoke-WebRequest` fallback. Only the SMS URL and timeout are passed to the
child environment; Sub2API administrator credentials are not inherited, and
the URL is not placed in process arguments.

After both rounds fail, `PhoneStatusApi.markInvalid` receives only the normalized
phone, a stable reason, and the total attempt count. The default implementation
does not send a request. `inventory-import-next` injects the Workstation
inventory adapter at this boundary and sets only the claimed phone's
`unavailable` flag.

## Local queue

`LocalImportPoolStore` stores queued account and phone material only as a
current-user DPAPI ciphertext in `.runtime/import-pool.dpapi`. Import commands
read plaintext rows from stdin and never print them. Phone usage is recorded at
the successful OpenAI phone-submit action, not when the queue item is selected;
the same phone is ineligible for 45 minutes after that timestamp. Supplier
batches can disable resend per phone. The current pool import command does so by
default and continues polling for two minutes without clicking the resend UI.

## Workstation inventory queue

`inventory-sync-accounts` retrieves the Workstation account import lines and
merges them directly into the same current-user DPAPI ciphertext. The Bearer
token and plaintext response are never written to disk or status output.

`inventory-import-next` delays the atomic phone claim until the OpenAI
`/add-phone` page is visible. Before claiming, a read-only eligible lookup
confirms that the candidate phone has an existing local SMS URL mapping. The
idempotency key is saved in DPAPI before the POST. Transport-ambiguous failures
reuse that key; definitive client errors archive it in the encrypted account
audit and allow a later logical attempt to create a new key.

The remote service owns the binding limit and cooldown timestamp. The local
pool still owns SMS access URLs, per-phone resend policy, and attempt state.
Phone invalidation is written locally before the remote unavailable PATCH so a
failed status request remains recoverable on the next attempt.

## Workstation banned-account replacement

`inventory-ban-pool-status` retrieves only validated status counts. The client
strips account import lines and replacement lines from every ban-pool record
before returning data to the CLI.

`inventory-ban-and-replace -- --email ...` is the explicit bridge from an
OpenAI provider-ban classification to the Workstation account state machine.
The exact local email is the selector, while Workstation atomically validates
`pool/imported`, selects the oldest `pool/available` replacement, and copies
the machine and pool assignment. The local DPAPI record stores the idempotency
key before the request and reuses it after an unknown outcome.

`reauthorize-errors -- --replace-banned` uses this bridge only for an
`account_banned` result observed during that invocation. Without the flag,
reauthorization remains status-only. After a completed replacement the client
retrieves fresh import lines so the promoted account becomes locally pending;
no replacement credentials or ban-pool response bodies are printed.

The pending-replacement extraction endpoint is available only as a validated
library method with a required private `consume` callback. There is no CLI
because its response contains complete account material and must be handed
directly to an approved private destination before only redacted metadata is
returned to the caller.

Do not substitute the older Grok/Gemini OAuth endpoints, write PostgreSQL
directly, or infer account creation from exchange HTTP 200. Use the supported
administrator API and exact-email postcondition so the server applies its
current account policy, proxy handling, and workspace-409 rule.

The administrator API key is stored canonically in OpenBao at
`projects/sub2api/prod/bitbrowser-oauth` under `admin_api_key`. The
`ydy001` copy is an ACL-restricted, Git-ignored runtime file only; rotate it
from OpenBao and never commit or print its value.
