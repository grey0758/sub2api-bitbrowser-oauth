# Workstation Inventory Automation

This document is the non-secret integration contract for the account and phone
inventory API served by Personal Workstation. It records route shapes,
idempotency, and state semantics. It does not contain the automation token,
account import lines, phone numbers, provider URLs, or private responses.

## Secret boundary

Production base URL:

```text
https://workstation.opencodex.uk
```

Every route in this document requires:

```text
Authorization: Bearer <managed automation token>
```

The canonical secret record is OpenBao KV v2
`projects/opencodex/prod/cliproxy-inventory-api`, field
`WORKSTATION_AUTOMATION_API_TOKEN`. The complete secret-bearing caller document
is stored separately on `ydy001` at:

```text
D:\work\sub2api-bitbrowser-oauth\WORKSTATION_AUTOMATION_API.md
```

That file and `.runtime/` are ignored by Git. Never add either with `git add
-f`, print their contents, or copy them into logs, issues, test fixtures, or
Curator records. API responses use `Cache-Control: private, no-store`.

## Account statuses

The schema uses these canonical business states:

| Status | Meaning |
| --- | --- |
| `available` | Ready for use or replacement |
| `sold` | Sold account |
| `imported` | Imported and assigned to a machine and pool |
| `banned` | Banned and waiting in the replacement queue |
| `banned_replaced` | Extracted or otherwise confirmed as replaced |
| `reauthorization_pending` | Active compatibility state waiting for OAuth reauthorization |

Legacy values normalize as follows:

| Legacy | Canonical |
| --- | --- |
| `unsold` | `available` |
| `pending` | `available` |
| `destroyed` | `banned_replaced` |

Every active or banned record has `status_changed_at` and ordered
`status_events`. Each event contains `from_status`, `to_status`, `changed_at`,
and an optional extraction `batch_id`. The current account format uses
`ban_pool_version=2`.

`reauthorization_pending` remains in the active inventory, but is not counted
as available, cannot be banned, and cannot be selected as a replacement.

## Account API

### Read complete import lines

```text
GET /api/v1/account-inventory/import-lines
```

The response includes all normalized `email|password|secret` lines. Treat the
entire response as private credential material and never log or persist it
outside the intended encrypted runtime store.

### Read the ban pool

```text
GET /api/v1/account-inventory/ban-pool
```

The response includes `count`, `banned_count`, `banned_replaced_count`,
`pending_replacement_count`, and retained account audit records.

### Ban and replace one account

```text
POST /api/v1/account-inventory/ban-and-replace
Idempotency-Key: <16-128 characters>
Content-Type: application/json

{"account":"email@example.invalid"}
```

`account` may be an exact email address or an exact `email|password|secret`
line. The operation accepts only a current `pool/imported` account. In one
locked write it moves that account into the ban pool, promotes the oldest
`pool/available` account to `imported`, and copies the old machine and pool
assignment to the replacement.

If no eligible replacement exists, neither the active inventory nor the ban
pool changes. Reusing the same idempotency key and selector returns the
original result; reusing the key for another selector is rejected.

### Mark one banned account as replaced

```text
PATCH /api/v1/account-inventory/ban-pool/<ban-id>
Content-Type: application/json

{"status":"banned_replaced"}
```

The legacy body `{"destroyed":true}` is accepted as a compatibility alias.
This operation is idempotent and retains the audit record.

### Extract the pending replacement queue once

```text
POST /api/v1/account-inventory/ban-pool/extract-pending-replacements
Idempotency-Key: <16-128 characters>
```

In one atomic write, this route returns every current `banned` record, assigns
one `batch_id` and `extracted_at`, and changes those records to
`banned_replaced`. The pending replacement view is then empty, but the records
and their timestamps remain available for audit.

Retry the same logical extraction with the same idempotency key. It returns the
same batch. A later key cannot extract those records again, so batches can be
sent to a supplier without duplicate replacement requests.

## Phone API

Phone usage is capped at three bindings. Every real increase records its UTC
time. Decreasing or retaining the count does not create a new increase event.
An unavailable phone is excluded from selection.

### Query eligible phones

```text
GET /api/v1/phone-inventory/eligible?min_age_minutes=45&limit=1
```

The defaults are `min_age_minutes=45` and `limit=1`. A phone is eligible only
when it is enabled, not unavailable, has `binding_count < 3`, and its latest
increase is old enough.

### Atomically claim one phone

```text
POST /api/v1/phone-inventory/claim
Idempotency-Key: <16-128 characters>
Content-Type: application/json

{"min_age_minutes":45}
```

The route selects one eligible phone, increments its count exactly once, and
records `claimed_at`. Retry uncertainty with the same key; a new key is a new
claim.

### Update count or availability

```text
PATCH /api/v1/phone-inventory/<phone-id>
Content-Type: application/json

{"binding_count":3,"unavailable":true}
```

`binding_count` must be in `0..3`. Either field may be supplied independently.
Setting `unavailable=true` removes the phone from future eligible queries.

## Windows caller pattern

Inject the token only into the current PowerShell process, then reuse one key
for retries of the same logical mutation:

```powershell
$headers = @{
  Authorization = "Bearer $env:WORKSTATION_AUTOMATION_TOKEN"
  "Idempotency-Key" = [guid]::NewGuid().ToString("N")
}

$body = @{ min_age_minutes = 45 } | ConvertTo-Json -Compress
Invoke-RestMethod `
  -Method Post `
  -Uri "https://workstation.opencodex.uk/api/v1/phone-inventory/claim" `
  -Headers $headers `
  -ContentType "application/json" `
  -Body $body
```

Do not generate a new idempotency key after a timeout until the original
request has been safely replayed or its result checked.

## Production baseline

The 2026-08-13 production deployment uses Workstation release
`20260813T081107Z`, Workstation commit
`539f32f95bbbcf1be5e217596aaf727ace7f56ac`, and management service commit
`60cde86b63c125b0bb4d1bcfc62e7e5c58b3db66`.

The post-migration read-only snapshot was `144` active accounts: `118`
`imported`, `26` `available`, and `0` `banned`. All active rows had timestamped
history. No production ban, replacement extraction, phone claim, or phone
mutation was used to establish that baseline.
