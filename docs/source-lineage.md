# Source lineage and deployment boundary

Curator recovery identified the BitBrowser implementation in the independent
`plus_paypal` repository:

- `src/browser/driver.js`
- `src/browser/bitbrowser-module/index.js`
- `src/browser/bitbrowser-module/browser-channel.js`

This project extracts the API/CDP ideas but removes the source module's
`ALWAYS_FRESH_MODE` random `bb-*` creation and cleanup behavior. The named
window is pre-created on workstation `ydy001` and is matched exactly.

The new repository is mounted under the upper ops workspace at
`repos/sub2api-bitbrowser-oauth`. Deployment to `ydy001` is source-only at
`D:\work\sub2api-bitbrowser-oauth` (or the configured target); it must not start
the OAuth flow automatically. The existing `D:\work\plus_paypal` checkout is
not modified or migrated.

Curator search keywords: `plus_paypal BitBrowser driver us001_codex`,
`Sub2API admin OpenAI OAuth generate-auth-url exchange-code`,
`ydy001 workstation repository mount`.
