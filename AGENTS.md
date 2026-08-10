# sub2api-bitbrowser-oauth

This repository is a focused Codex/Claude helper for one pre-created BitBrowser
profile and the Sub2API OpenAI OAuth account-import flow.

## Invariants

- The default BitBrowser profile is the exact name `us001_codex`.
- The controller must never create, delete, clear, refresh, or close a different
  profile. A missing or duplicate exact name is a hard error.
- Releasing a session disconnects Playwright only; the named BitBrowser window
  remains open unless an operator explicitly passes `--close-window`.
- Sub2API is called through the supported administrator endpoints:
  `POST /admin/accounts/generate-auth-url` and
  `POST /admin/accounts/exchange-code`.
- Administrator credentials are runtime-only (`SUB2API_ADMIN_TOKEN`,
  `SUB2API_ADMIN_API_KEY`, or `SUB2API_ADMIN_COOKIE`). Never commit, print, or
  persist tokens, callback codes, OAuth URLs, cookies, or account payloads.
- This tool does not change NewAPI channels, abilities, account rows, proxy
  bindings, DNS, Cloudflare, or production containers.

## Commands

```bash
npm ci
npm test
npm run syntax
npm run check                         # exact-name BitBrowser read-only check
npm run start                         # generate + open, leave window open
npm run run                           # generate, wait callback, exchange/import
```

Use a runtime environment or a secret manager injector for the administrator
credential. `.env.example` contains names only.

## Source lineage

The BitBrowser client/controller behavior was extracted from
`repos/plus_paypal/src/browser/driver.js` and
`repos/plus_paypal/src/browser/bitbrowser-module/`, then narrowed to a fixed
window controller. The original repository remains independent and unchanged.
