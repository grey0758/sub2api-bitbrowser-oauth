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
- one of `SUB2API_ADMIN_TOKEN`, `SUB2API_ADMIN_API_KEY`, or
  `SUB2API_ADMIN_COOKIE`

## Usage

First perform a read-only exact-name check:

```bash
npm run check
```

Generate the supported OpenAI OAuth URL through Sub2API and open it in
`us001_codex`:

```bash
npm run start
```

The URL is deliberately not printed. Complete login in the opened profile.
For the complete interactive flow, including callback detection at
`localhost:1455/auth/callback` and supported exchange/import:

```bash
npm run run
```

`run` leaves the named window open after disconnecting the CDP client. It does
not print callback codes or account data.

## Safety

The helper fails closed if `us001_codex` is absent or ambiguous. It never
creates/deletes profiles and does not touch Sub2API channels or database rows
directly. Account policy and workspace-409 handling remain server-side in
Sub2API's supported administrator API.

See [docs/oauth-flow.md](docs/oauth-flow.md) and
[docs/source-lineage.md](docs/source-lineage.md) for the durable workflow and
Curator context.
