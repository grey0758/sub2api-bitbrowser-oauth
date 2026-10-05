'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const { BitBrowserClient, BitBrowserApiError } = require('../src/bitbrowser/client');
const { FixedWindowController, FixedWindowSession, exactWindowMatches, parseCallbackUrl } = require('../src/bitbrowser/window-controller');
const {
  Sub2ApiAdminClient,
  Sub2ApiError,
  buildGeminiCredentials,
  buildOpenAiCredentials,
  normalizeGeminiOAuthType,
  parseCodeInput,
} = require('../src/sub2api/admin-client');
const { OAuthFlow } = require('../src/oauth/flow');
const {
  OpenAiImportConfigError,
  OpenAiLoginError,
  OpenAiAccountImportFlow,
  PHONE_CODE_INPUT_SELECTOR,
  PhoneStatusApi,
  SmsCodeTimeoutError,
  classifyExchangeResult,
  detectOpenAiAuthRoute,
  directSmsRequest,
  extractSmsCode,
  generateTotp,
  isOpenAiRateLimitText,
  isOpenAiRouteErrorText,
  loadOpenAiAccountRuntime,
  normalizeTotpSecret,
  normalizeUsPhoneNumber,
  pollSmsCode,
  waitForSmsCodeWithResend,
  windowsSmsRequest,
} = require('../src/oauth/account-import');
const {
  GoogleGeminiOAuthImportFlow,
  GoogleLoginError,
  classifyGoogleChallengePath,
  detectGoogleOAuthPage,
  isAllowedGoogleOAuthLocation,
  readGoogleTwoFactor,
  safeGooglePageSnapshot,
  googleRequestCategory,
  typeAndSubmitGoogleField,
  withGoogleLoginHint,
} = require('../src/oauth/google-gemini-import');
const {
  GoogleAntigravityOAuthImportFlow,
} = require('../src/oauth/google-antigravity-import');
const { loadRuntimeEnv, parseRuntimeEnv } = require('../src/runtime-env');
const {
  WorkstationAutomationClient,
  WorkstationAutomationError,
  generateAccountReplacementKey,
  generatePhoneClaimKey,
} = require('../src/workstation/automation-client');
const { WorkstationInventoryImportCoordinator } = require('../src/workstation/inventory-import');
const {
  buildAccountHealthAudit,
  classifyAccountError,
} = require('../src/sub2api/account-health');
const {
  DEFAULT_GOOGLE_POOL_FILE,
  GOOGLE_INVALID_CREDENTIAL_BACKOFF_MS,
  LocalImportPoolStore,
  PHONE_COOLDOWN_MS,
  POOL_VERSION,
  parseAccountPoolSource,
  parseGoogleAccountPoolSource,
  parsePhonePoolSource,
} = require('../src/pool/local-import-pool');
const {
  parseArgs,
  recordGoogleAttemptFailure,
  safeError,
  usage,
} = require('../bin/sub2api-bitbrowser-oauth');

test('runtime environment parser only accepts allowlisted non-empty values', () => {
  assert.deepEqual(parseRuntimeEnv('\n# comment\nSUB2API_ADMIN_API_KEY=secret\nSUB2API_BASE_URL=https://sub2apipro.opencodex.uk\n'), {
    SUB2API_ADMIN_API_KEY: 'secret',
    SUB2API_BASE_URL: 'https://sub2apipro.opencodex.uk',
  });
  assert.throws(() => parseRuntimeEnv('UNSAFE=value'), /Unsupported runtime environment key/);
  assert.throws(
    () => parseRuntimeEnv('WORKSTATION_AUTOMATION_TOKEN=runtime-only'),
    /Unsupported runtime environment key/
  );
  assert.throws(() => parseRuntimeEnv('SUB2API_ADMIN_API_KEY='), /value is empty/);
});

test('account health audit classifies revoked OAuth records and matches only encrypted-pool emails', () => {
  assert.equal(classifyAccountError('Token revoked (401): invalidated oauth token'), 'oauth_token_invalid_or_revoked');
  assert.equal(classifyAccountError('Your account has been deactivated'), 'provider_banned_or_disabled');
  const audit = buildAccountHealthAudit([
    {
      id: 'account-1',
      platform: 'openai',
      status: 'error',
      error_message: 'Token revoked (401)',
      credentials: { email: 'one@example.com' },
    },
    {
      id: 'account-2',
      platform: 'openai',
      status: 'active',
      credentials: { email: 'two@example.com' },
    },
  ], [{ email: 'one@example.com' }]);
  assert.deepEqual(audit.entries.map((entry) => ({
    status: entry.status,
    category: entry.category,
    hasPoolLogin: entry.hasPoolLogin,
  })), [
    { status: 'error', category: 'oauth_token_invalid_or_revoked', hasPoolLogin: true },
    { status: 'active', category: 'healthy', hasPoolLogin: false },
  ]);
  assert.equal(audit.entries[0].errorFingerprint.length, 64);

  const preserved = buildAccountHealthAudit(
    [{ id: 'account-1', platform: 'openai', status: 'error', error_message: 'Token revoked (401)', credentials: { email: 'one@example.com' } }],
    [{ email: 'one@example.com' }],
    { entries: [{ accountId: 'account-1', outcome: 'account_banned', outcomeAt: 123, outcomeCode: 'account_banned' }] }
  );
  assert.equal(preserved.entries[0].outcome, 'account_banned');
  assert.equal(preserved.entries[0].outcomeCode, 'account_banned');

  const switched = buildAccountHealthAudit(
    [{ id: 'account-1', platform: 'openai', status: 'error', error_message: 'Token revoked (401)', credentials: { email: 'one@example.com' } }],
    [{ email: 'one@example.com' }],
    {
      sourceBaseUrl: 'https://sub2apipro.opencodex.uk',
      entries: [{ accountId: 'account-1', outcome: 'account_banned' }],
    },
    { sourceBaseUrl: 'https://sub2apiplus.opencodex.uk/' }
  );
  assert.equal(switched.sourceBaseUrl, 'https://sub2apiplus.opencodex.uk');
  assert.equal(switched.entries[0].outcome, 'pending');
});

test('runtime environment loader preserves explicit process values', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-runtime-'));
  const file = path.join(directory, 'admin.env');
  fs.writeFileSync(file, 'SUB2API_ADMIN_API_KEY=from-file\nSUB2API_BASE_URL=https://example.invalid\n', { mode: 0o600 });
  const env = { SUB2API_ADMIN_API_KEY: 'from-process' };
  try {
    const loaded = loadRuntimeEnv({ file, env });
    assert.equal(loaded.loaded, true);
    assert.deepEqual(loaded.keys, ['SUB2API_ADMIN_API_KEY', 'SUB2API_BASE_URL']);
    assert.equal(env.SUB2API_ADMIN_API_KEY, 'from-process');
    assert.equal(env.SUB2API_BASE_URL, 'https://example.invalid');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Workstation client validates inventory responses and sends runtime bearer authentication', async () => {
  const calls = [];
  const client = new WorkstationAutomationClient({
    token: 'runtime-only',
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      if (url.includes('/account-inventory/import-lines')) {
        return new Response(JSON.stringify({
          version: 1,
          source_version: 3,
          updated_at: '2026-08-12T07:39:51Z',
          count: 1,
          import_lines: ['operator@example.com|runtime-password|JBSWY3DPEHPK3PXP'],
        }), { status: 200 });
      }
      if (url.includes('/phone-inventory/eligible')) {
        return new Response(JSON.stringify({
          version: 1,
          queried_at: '2026-08-12T07:40:00Z',
          binding_limit: 3,
          min_age_minutes: 45,
          count: 1,
          phones: [{
            id: 'phone-example-01',
            number: '+14109824518',
            unavailable: false,
            binding_count: 1,
            binding_limit: 3,
            last_binding_at: '2026-08-12T06:00:00Z',
            binding_events: [],
          }],
        }), { status: 200 });
      }
      return new Response(JSON.stringify({ error: 'invalid_request' }), { status: 400 });
    },
  });
  const accounts = await client.getAccountImportLines();
  assert.equal(accounts.sourceVersion, 3);
  assert.equal(accounts.count, 1);
  const phones = await client.getEligiblePhones({ minAgeMinutes: 45, limit: 1 });
  assert.equal(phones[0].number, '+14109824518');
  assert.equal(calls[0].init.headers.authorization, 'Bearer runtime-only');
  assert.equal(new URL(calls[1].url).search, '?min_age_minutes=45&limit=1');
  assert.equal(JSON.stringify(accounts).includes('runtime-only'), false);
});

test('Workstation phone claim uses a stable key and sanitizes status-only errors', async () => {
  const idempotencyKey = generatePhoneClaimKey();
  const calls = [];
  const client = new WorkstationAutomationClient({
    token: 'runtime-only',
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return new Response(JSON.stringify({
        version: 1,
        claimed_at: '2026-08-12T07:41:00Z',
        replayed: false,
        phone: {
          id: 'phone-example-01',
          number: '+14109824518',
          unavailable: false,
          binding_count: 2,
          binding_limit: 3,
          last_binding_at: '2026-08-12T07:41:00Z',
          binding_events: [],
        },
      }), { status: 200 });
    },
  });
  const result = await client.claimPhone({ idempotencyKey });
  assert.equal(result.phone.bindingCount, 2);
  assert.equal(calls[0].init.headers['idempotency-key'], idempotencyKey);
  assert.deepEqual(JSON.parse(calls[0].init.body), { min_age_minutes: 45 });

  const rejected = new WorkstationAutomationClient({
    token: 'runtime-only',
    fetchImpl: async () => new Response(JSON.stringify({ error: 'eligible_phone_not_found' }), { status: 404 }),
  });
  await assert.rejects(
    () => rejected.claimPhone({ idempotencyKey }),
    (error) => (
      error instanceof WorkstationAutomationError &&
      error.status === 404 &&
      error.code === 'eligible_phone_not_found' &&
      safeError(error) === 'Workstation automation request failed (HTTP 404; code=eligible_phone_not_found)'
    )
  );
});

test('Workstation claim transport failures preserve unknown-outcome state without exposing secrets', async () => {
  const client = new WorkstationAutomationClient({
    token: 'sensitive-runtime-token',
    fetchImpl: async () => { throw new Error('transport failed with sensitive-runtime-token'); },
  });
  await assert.rejects(
    () => client.claimPhone({ idempotencyKey: generatePhoneClaimKey() }),
    (error) => (
      error instanceof WorkstationAutomationError &&
      error.outcomeUnknown === true &&
      error.retryable === true &&
      !error.message.includes('sensitive-runtime-token') &&
      !safeError(error).includes('sensitive-runtime-token')
    )
  );
});

test('Workstation malformed successful claim responses remain retryable with the same key', async () => {
  const client = new WorkstationAutomationClient({
    token: 'runtime-only',
    fetchImpl: async () => new Response(JSON.stringify({
      version: 1,
      claimed_at: '2026-08-12T07:41:00Z',
      replayed: false,
      phone: { id: 'invalid' },
    }), { status: 200 }),
  });
  await assert.rejects(
    () => client.claimPhone({ idempotencyKey: generatePhoneClaimKey() }),
    (error) => (
      error instanceof WorkstationAutomationError &&
      error.outcomeUnknown === true &&
      error.retryable === true
    )
  );
});

test('Workstation account inventory state APIs validate and redact secret-bearing records', async () => {
  const calls = [];
  const client = new WorkstationAutomationClient({
    token: 'runtime-only',
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      const parsed = new URL(url);
      if (init.method === 'GET' && parsed.pathname.endsWith('/account-inventory/ban-pool')) {
        return new Response(JSON.stringify({
          version: 2,
          updated_at: '2026-08-13T08:15:09Z',
          count: 1,
          banned_count: 1,
          banned_replaced_count: 0,
          pending_replacement_count: 1,
          accounts: [{
            id: 'ban-example-01',
            status: 'banned',
            banned_at: '2026-08-13T08:15:09Z',
            replaced_at: null,
            status_changed_at: '2026-08-13T08:15:09Z',
            account_import_line: 'secret@example.com|password|JBSWY3DPEHPK3PXP',
            replacement_import_line: 'replacement@example.com|password|JBSWY3DPEHPK3PXP',
          }],
        }), { status: 200 });
      }
      if (init.method === 'POST' && parsed.pathname.endsWith('/account-inventory/ban-and-replace')) {
        return new Response(JSON.stringify({
          version: 2,
          updated_at: '2026-08-13T08:15:09Z',
          replayed: false,
          banned_account: {
            id: 'ban-example-01',
            status: 'banned',
            account_import_line: 'secret@example.com|password|JBSWY3DPEHPK3PXP',
          },
        }), { status: 200 });
      }
      if (init.method === 'POST' && parsed.pathname.endsWith('/ban-pool/extract-pending-replacements')) {
        return new Response(JSON.stringify({
          version: 2,
          updated_at: '2026-08-13T08:16:09Z',
          replayed: false,
          batch_id: 'batch-example-01',
          extracted_at: '2026-08-13T08:16:09Z',
          count: 1,
          accounts: [{
            id: 'ban-example-01',
            status: 'banned_replaced',
            account_import_line: 'secret@example.com|password|JBSWY3DPEHPK3PXP',
          }],
        }), { status: 200 });
      }
      if (init.method === 'PATCH' && parsed.pathname.endsWith('/account-inventory/ban-pool/ban-example-01')) {
        return new Response(JSON.stringify({
          version: 2,
          updated_at: '2026-08-13T08:17:09Z',
          already_banned_replaced: false,
          banned_account: { id: 'ban-example-01', status: 'banned_replaced' },
        }), { status: 200 });
      }
      throw new Error('unexpected request');
    },
  });
  const replacementKey = generateAccountReplacementKey();
  const extractionKey = 'replacement-batch-example-0001';
  const pool = await client.getBanPool();
  const replacement = await client.banAndReplaceAccount({
    account: 'secret@example.com',
    idempotencyKey: replacementKey,
  });
  let consumedBatch;
  const extraction = await client.extractPendingReplacements({
    idempotencyKey: extractionKey,
    consume: async (batch) => { consumedBatch = batch; },
  });
  const updated = await client.markBanRecordReplaced('ban-example-01');
  assert.equal(pool.pendingReplacementCount, 1);
  assert.deepEqual(Object.keys(pool.accounts[0]).sort(), [
    'bannedAt', 'id', 'replacedAt', 'status', 'statusChangedAt',
  ]);
  assert.equal(replacement.bannedAccount.id, 'ban-example-01');
  assert.equal(extraction.batchId, 'batch-example-01');
  assert.equal(consumedBatch.accounts[0].account_import_line.includes('password'), true);
  assert.equal(updated.bannedAccount.status, 'banned_replaced');
  assert.equal(JSON.stringify({ pool, replacement, extraction, updated }).includes('password'), false);
  assert.equal(calls[1].init.headers['idempotency-key'], replacementKey);
  assert.deepEqual(JSON.parse(calls[1].init.body), { account: 'secret@example.com' });
  assert.equal(calls[2].init.headers['idempotency-key'], extractionKey);
  await assert.rejects(
    () => client.extractPendingReplacements({ idempotencyKey: extractionKey }),
    /consume callback is required/
  );
  await assert.rejects(
    () => client.extractPendingReplacements({
      idempotencyKey: extractionKey,
      consume: async () => { throw new Error('private sink unavailable'); },
    }),
    (error) => (
      error instanceof WorkstationAutomationError &&
      error.outcomeUnknown === true &&
      error.retryable === true &&
      !error.message.includes('private sink unavailable')
    )
  );
});

test('Workstation phone target-state update validates count and availability', async () => {
  const calls = [];
  const client = new WorkstationAutomationClient({
    token: 'runtime-only',
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return new Response(JSON.stringify({
        version: 1,
        updated_at: '2026-08-13T08:15:09Z',
        phone: {
          id: 'phone-example-01',
          number: '+14109824518',
          unavailable: true,
          binding_count: 3,
          binding_limit: 3,
          last_binding_at: '2026-08-13T08:15:09Z',
          binding_events: [],
        },
      }), { status: 200 });
    },
  });
  const result = await client.updatePhone('phone-example-01', { bindingCount: 3, unavailable: true });
  assert.equal(result.phone.bindingCount, 3);
  assert.deepEqual(JSON.parse(calls[0].init.body), { binding_count: 3, unavailable: true });
  await assert.rejects(() => client.updatePhone('phone-example-01', {}), /is required/);
  await assert.rejects(() => client.updatePhone('phone-example-01', { bindingCount: 4 }), /0 to 3/);
});

test('exact window matching does not select similar names or deleted windows', () => {
  const windows = [
    { id: 'one', name: 'us001_codex', status: 0, isDelete: 0 },
    { id: 'two', name: 'us001_codex-old', status: 1, isDelete: 0 },
    { id: 'three', name: 'us001_codex', status: 1, isDelete: 1 },
  ];
  assert.deepEqual(exactWindowMatches(windows, 'us001_codex').map((item) => item.id), ['one']);
});

test('callback parser accepts localhost callback and rejects unrelated URLs', () => {
  const callback = parseCallbackUrl('http://localhost:1455/auth/callback?code=one-time&state=s');
  assert.deepEqual({ code: callback.code, state: callback.state }, { code: 'one-time', state: 's' });
  assert.equal(parseCallbackUrl('https://auth.openai.com/oauth/authorize?code=x'), null);
  assert.deepEqual(
    parseCallbackUrl('https://codeassist.google.com/authcode?code=gemini-code&state=gemini-state', {
      allowCodeAssist: true,
    }),
    { code: 'gemini-code', state: 'gemini-state' }
  );
  assert.equal(parseCallbackUrl('https://codeassist.google.com/authcode?code=x'), null);
  assert.equal(parseCallbackUrl('http://localhost:1455/other?code=x'), null);
  assert.equal(parseCallbackUrl('http://localhost:8085/callback?code=x&state=y'), null);
  assert.deepEqual(
    parseCallbackUrl('http://localhost:8085/callback?code=x&state=y', { allowAntigravity: true }),
    { code: 'x', state: 'y' }
  );
});

test('Sub2API Gemini OAuth uses the supported endpoints and verifies account creation', async () => {
  const calls = [];
  let created = false;
  const fetchImpl = async (url, options) => {
    const parsed = new URL(url);
    const body = options.body ? JSON.parse(options.body) : null;
    calls.push([options.method, parsed.pathname, body]);
    if (parsed.pathname.endsWith('/admin/gemini/oauth/auth-url')) {
      return new Response(JSON.stringify({ code: 0, data: {
        auth_url: 'https://accounts.google.com/o/oauth2/v2/auth?state=gemini-state',
        session_id: 'gemini-session',
        state: 'gemini-state',
      } }), { status: 200 });
    }
    if (parsed.pathname.endsWith('/admin/gemini/oauth/exchange-code')) {
      return new Response(JSON.stringify({ code: 0, data: {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_at: 1_700_000_000,
        oauth_type: 'google_one',
      } }), { status: 200 });
    }
    if (parsed.pathname.endsWith('/admin/accounts') && options.method === 'GET') {
      const accounts = created ? [{ id: 11, name: 'google@example.com', platform: 'gemini', type: 'oauth' }] : [];
      return new Response(JSON.stringify({ code: 0, data: { items: accounts, total: accounts.length } }), { status: 200 });
    }
    if (parsed.pathname.endsWith('/admin/accounts') && options.method === 'POST') {
      created = true;
      return new Response(JSON.stringify({ code: 0, data: { id: 11 } }), { status: 200 });
    }
    throw new Error(`unexpected request: ${options.method} ${parsed.pathname}`);
  };
  const client = new Sub2ApiAdminClient({ apiKey: 'runtime-only', fetchImpl });
  const authorization = await client.generateGeminiAuthUrl({ oauthType: 'google_one', proxyId: 7 });
  assert.equal(authorization.oauthType, 'google_one');
  const exchanged = await client.exchangeGeminiCode({
    sessionId: authorization.sessionId,
    code: 'callback-code',
    state: authorization.state,
    oauthType: authorization.oauthType,
    proxyId: 7,
  });
  assert.deepEqual(await client.importGeminiOAuthAccount({
    email: 'google@example.com',
    exchangeResult: exchanged,
    proxyId: 7,
  }), { action: 'created', accountId: 11 });
  assert.equal(calls.find((item) => item[1].endsWith('/oauth/auth-url'))[2].oauth_type, 'google_one');
  assert.equal(calls.find((item) => item[1].endsWith('/oauth/auth-url'))[2].proxy_id, 7);
  assert.equal(calls.find((item) => item[1].endsWith('/oauth/exchange-code'))[2].state, 'gemini-state');
  assert.equal(calls.find((item) => item[1].endsWith('/oauth/exchange-code'))[2].proxy_id, 7);
  const createBody = calls.find((item) => item[0] === 'POST' && item[1].endsWith('/admin/accounts'))[2];
  assert.equal(createBody.platform, 'gemini');
  assert.equal(createBody.type, 'oauth');
  assert.equal(createBody.proxy_id, 7);
  assert.equal(createBody.credentials.expires_at, '1700000000');
});

test('Sub2API Antigravity OAuth uses its dedicated endpoints and verifies platform-specific creation', async () => {
  const calls = [];
  let created = false;
  const fetchImpl = async (url, options) => {
    const parsed = new URL(url);
    const body = options.body ? JSON.parse(options.body) : null;
    calls.push([options.method, parsed.pathname, body]);
    if (parsed.pathname.endsWith('/admin/antigravity/oauth/auth-url')) {
      return new Response(JSON.stringify({ code: 0, data: {
        auth_url: 'https://accounts.google.com/o/oauth2/v2/auth?state=ag-state',
        session_id: 'ag-session',
        state: 'ag-state',
      } }), { status: 200 });
    }
    if (parsed.pathname.endsWith('/admin/antigravity/oauth/exchange-code')) {
      return new Response(JSON.stringify({ code: 0, data: {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_at: 1_700_000_000,
        email: 'google@example.com',
      } }), { status: 200 });
    }
    if (parsed.pathname.endsWith('/admin/accounts') && options.method === 'GET') {
      const accounts = created
        ? [{
          id: 12,
          name: 'google@example.com',
          platform: 'antigravity',
          type: 'oauth',
          proxy_id: 7,
          priority: 1000,
          rate_multiplier: 1,
        }]
        : [];
      return new Response(JSON.stringify({ code: 0, data: { items: accounts, total: accounts.length } }), { status: 200 });
    }
    if (parsed.pathname.endsWith('/admin/accounts') && options.method === 'POST') {
      created = true;
      return new Response(JSON.stringify({ code: 0, data: { id: 12 } }), { status: 200 });
    }
    throw new Error(`unexpected request: ${options.method} ${parsed.pathname}`);
  };
  const client = new Sub2ApiAdminClient({ apiKey: 'runtime-only', fetchImpl });
  const authorization = await client.generateAntigravityAuthUrl({ proxyId: 7 });
  const exchanged = await client.exchangeAntigravityCode({
    sessionId: authorization.sessionId,
    code: 'callback-code',
    state: authorization.state,
    proxyId: 7,
  });
  assert.deepEqual(await client.importAntigravityOAuthAccount({
    email: 'google@example.com',
    exchangeResult: exchanged,
    proxyId: 7,
  }), { action: 'created', accountId: 12 });
  const createBody = calls.find((item) => item[0] === 'POST' && item[1].endsWith('/admin/accounts'))[2];
  assert.equal(createBody.platform, 'antigravity');
  assert.equal(createBody.type, 'oauth');
  assert.equal(createBody.proxy_id, 7);
  assert.equal(createBody.priority, 1000);
  assert.equal(createBody.rate_multiplier, 1);
});

test('Gemini credential validation and Google HTTPS two-factor retrieval are bounded', async () => {
  assert.equal(normalizeGeminiOAuthType(), 'google_one');
  assert.throws(() => normalizeGeminiOAuthType('invalid'), /oauthType/);
  assert.deepEqual(buildGeminiCredentials({
    access_token: 'access-token',
    expires_at: 1_700_000_000,
    oauth_type: 'google_one',
  }), {
    access_token: 'access-token',
    expires_at: '1700000000',
    oauth_type: 'google_one',
  });
  let attempts = 0;
  const page = { async waitForTimeout() {} };
  assert.equal(await readGoogleTwoFactor({
    kind: 'https-url',
    value: 'https://two-factor.example.invalid/access?id=runtime-only',
  }, page, {
    requestText: async () => {
      attempts += 1;
      return attempts === 2 ? 'verification code: 123456' : '';
    },
    attempts: 2,
    intervalMs: 0,
  }), '123456');
  await assert.rejects(
    () => readGoogleTwoFactor({ kind: 'unsupported', value: 'runtime-only' }, page),
    (error) => error instanceof GoogleLoginError && error.code === 'two_factor_unavailable'
  );
});

test('Google OAuth classifies authenticator selection and manual challenge routes without page data', () => {
  assert.equal(classifyGoogleChallengePath('https://accounts.google.com/signin/v2/challenge/totp'), 'totp');
  assert.equal(classifyGoogleChallengePath('https://accounts.google.com/signin/v2/challenge/selection'), 'challenge_selection');
  assert.equal(classifyGoogleChallengePath('https://accounts.google.com/signin/v2/challenge/recaptcha'), 'manual_challenge');
  assert.equal(classifyGoogleChallengePath('https://accounts.google.com/signin/v2/challenge/ipp'), 'challenge');
  assert.equal(classifyGoogleChallengePath('https://accounts.google.com/signin/v2/challenge/pwd'), '');
});

test('Google OAuth safe state snapshot contains only structural categories', async () => {
  const page = {
    url: () => 'https://accounts.google.com/signin/oauth?state=must-not-leak',
    async evaluate() {
      return {
        readyState: 'complete', bodyLength: 'short', bodyChildren: 1,
        visibleInputs: [], visibleButtons: 0, visibleLinks: 0,
        identifierTiles: 0, scripts: 2, frames: 0,
        markers: { genericError: true },
      };
    },
    frames: () => [],
  };
  const snapshot = await safeGooglePageSnapshot(page, { allowAntigravity: true, route: 'waiting' });
  assert.deepEqual(snapshot, {
    route: 'waiting', location: 'signin_oauth', readyState: 'complete',
    bodyLength: 'short', bodyChildren: 1, visibleInputs: [], visibleButtons: 0,
    visibleLinks: 0, identifierTiles: 0, scripts: 2, frames: 0,
    markers: { genericError: true }, frameCategories: [],
  });
  assert.equal(JSON.stringify(snapshot).includes('must-not-leak'), false);
});

test('Google OAuth types sequentially and clicks the visible Next control', async () => {
  const calls = [];
  const input = {
    value: '',
    async click() { calls.push('click-input'); },
    async fill(value) { this.value = value; calls.push(['fill', value]); },
    async pressSequentially(value, options) { this.value = value; calls.push(['type', value, options.delay]); },
    async inputValue() { return this.value; },
    async press() { calls.push('unexpected-enter'); },
  };
  const next = {
    async isVisible() { return true; },
    async click() { calls.push('click-next'); },
  };
  await typeAndSubmitGoogleField({
    getByRole() { return { last: () => next }; },
    async waitForTimeout(ms) { calls.push(['wait', ms]); },
  }, input, 'runtime-only');
  assert.deepEqual(calls, [
    'click-input', ['fill', ''], ['type', 'runtime-only', 85], ['wait', 600], 'click-next',
  ]);
});

test('Google OAuth corrects keyboard-layout drift before submitting a field', async () => {
  const calls = [];
  const input = {
    value: '',
    async click() {},
    async fill(value) { this.value = value; calls.push(['fill', value]); },
    async pressSequentially(value) { this.value = `wrong-${value}`; },
    async inputValue() { return this.value; },
  };
  const next = { async isVisible() { return true; }, async click() { calls.push('submit'); } };
  await typeAndSubmitGoogleField({
    getByRole() { return { last: () => next }; },
    async waitForTimeout() {},
  }, input, 'runtime-only');
  assert.deepEqual(calls, [['fill', ''], ['fill', 'runtime-only'], 'submit']);
});

test('Google OAuth network diagnostics expose only endpoint categories', () => {
  assert.equal(googleRequestCategory('https://accounts.google.com/_/signin/sl/lookup?email=secret'), 'accounts_lookup');
  assert.equal(googleRequestCategory('https://accounts.google.com/v3/signin/challenge/pwd'), 'accounts_challenge');
  assert.equal(googleRequestCategory('https://ssl.gstatic.com/accounts/static.js'), 'google_static');
  assert.equal(googleRequestCategory('https://attacker.example/?secret=value'), 'other');
});

test('Google OAuth login hint preserves authorization state without accepting another host', () => {
  const hinted = new URL(withGoogleLoginHint(
    'https://accounts.google.com/o/oauth2/v2/auth?state=runtime-state&client_id=client',
    'google@example.com'
  ));
  assert.equal(hinted.searchParams.get('login_hint'), 'google@example.com');
  assert.equal(hinted.searchParams.get('state'), 'runtime-state');
  assert.throws(
    () => withGoogleLoginHint('https://attacker.example/oauth?state=runtime-state', 'google@example.com'),
    (error) => error instanceof GoogleLoginError && error.code === 'navigation_failed'
  );
});

test('Google OAuth recognizes localized account chooser and bounded authenticator alternatives', async () => {
  const hidden = { async isVisible() { return false; } };
  const text = '使用其他账号';
  const page = {
    url: () => 'https://accounts.google.com/signin/v2/identifier',
    locator() {
      return { first: () => hidden, async innerText() { return ''; } };
    },
    getByText(pattern) {
      return { last: () => ({ async isVisible() { return pattern.test(text); } }) };
    },
    getByRole() { return { last: () => hidden }; },
    frames() { return []; },
  };
  assert.equal(await detectGoogleOAuthPage(page), 'choose_account');

  page.url = () => 'https://accounts.google.com/signin/v2/challenge/ipp';
  const alternative = 'Try another way';
  page.getByText = (pattern) => ({ last: () => ({ async isVisible() { return pattern.test(alternative); } }) });
  assert.equal(await detectGoogleOAuthPage(page), 'challenge_alternatives');

  page.url = () => 'https://accounts.google.com/signin/oauth/consent';
  page.getByText = () => ({ last: () => hidden });
  page.getByRole = (_role, { name }) => ({
    last: () => ({ async isVisible() { return name.test('Sign in'); } }),
  });
  assert.equal(await detectGoogleOAuthPage(page, { allowAntigravity: true }), 'consent');
});

test('Google OAuth stops instead of entering TOTP on CAPTCHA routes', async () => {
  const flow = new GoogleGeminiOAuthImportFlow({
    sub2api: {},
    browser: {},
    account: {
      email: 'google@example.com',
      password: 'runtime-only',
      twoFactor: { kind: 'totp-secret', value: 'JBSWY3DPEHPK3PXP' },
    },
  });
  const page = {
    url: () => 'https://accounts.google.com/signin/v2/challenge/recaptcha',
    locator() {
      return {
        first: () => ({ async isVisible() { return false; } }),
        async innerText() { return ''; },
      };
    },
    getByText() { return { last: () => ({ async isVisible() { return false; } }) }; },
    getByRole() { return { last: () => ({ async isVisible() { return false; } }) }; },
    frames() { return []; },
    async waitForTimeout() {},
  };
  await assert.rejects(
    () => flow.completeLogin(page, { timeoutMs: 1_000 }),
    (error) => error instanceof GoogleLoginError && error.code === 'manual_challenge'
  );
});

test('Google OAuth navigation failures are sanitized before reaching the CLI', async () => {
  let released = false;
  const flow = new GoogleGeminiOAuthImportFlow({
    sub2api: {
      async generateGeminiAuthUrl() {
        return {
          authUrl: 'https://accounts.google.com/o/oauth2/v2/auth?state=secret-state',
          sessionId: 'session',
          state: 'secret-state',
          oauthType: 'google_one',
        };
      },
    },
    browser: {
      async open() {
        return {
          page: { url: () => 'about:blank' },
          async goto() {
            throw new Error('page.goto failed at https://accounts.google.com/?state=secret-state');
          },
        };
      },
      async release() { released = true; },
    },
    account: {
      email: 'google@example.com',
      password: 'runtime-only',
      twoFactor: { kind: 'totp-secret', value: 'JBSWY3DPEHPK3PXP' },
    },
  });
  await assert.rejects(
    () => flow.run(),
    (error) => error instanceof GoogleLoginError &&
      error.code === 'navigation_failed' &&
      !error.message.includes('accounts.google.com') &&
      !error.message.includes('secret-state')
  );
  assert.equal(released, true);
});

test('Google OAuth tolerates ERR_ABORTED only on an allowlisted Google location', async () => {
  assert.equal(isAllowedGoogleOAuthLocation('https://accounts.google.com/signin'), true);
  assert.equal(isAllowedGoogleOAuthLocation('https://codeassist.google.com/authcode'), true);
  assert.equal(isAllowedGoogleOAuthLocation('https://accounts.google.example/signin'), false);

  let pageUrl = 'https://accounts.google.com/signin';
  let released = false;
  const session = {
    page: { url: () => pageUrl },
    async goto() { throw new Error('page.goto: net::ERR_ABORTED at a redacted URL'); },
  };
  const flow = new GoogleGeminiOAuthImportFlow({
    sub2api: {
      async generateGeminiAuthUrl() {
        return {
          authUrl: 'https://accounts.google.com/o/oauth2/v2/auth?state=secret-state',
          sessionId: 'session',
          state: 'secret-state',
          oauthType: 'google_one',
        };
      },
    },
    browser: {
      async open() { return session; },
      async release() { released = true; },
    },
    account: {
      email: 'google@example.com',
      password: 'runtime-only',
      twoFactor: { kind: 'totp-secret', value: 'JBSWY3DPEHPK3PXP' },
    },
  });
  flow.completeLogin = async () => { throw new GoogleLoginError('stop after navigation proof', 'manual_challenge'); };
  await assert.rejects(() => flow.run(), (error) => error.code === 'manual_challenge');
  assert.equal(released, true);

  pageUrl = 'https://attacker.example/';
  await assert.rejects(() => flow.run(), (error) => error.code === 'navigation_failed');
});

test('callback waiter captures the localhost request before Chrome replaces the URL', async () => {
  const page = new EventEmitter();
  const mainFrame = {};
  page.url = () => 'chrome-error://chromewebdata/';
  page.mainFrame = () => mainFrame;
  const context = { pages: () => [page] };
  const session = new FixedWindowSession({
    browser: { close: async () => {} },
    context,
    page,
    window: { id: 'w', name: 'us001_codex' },
  });
  const pending = session.waitForCallback({ timeoutMs: 250, pollMs: 5 });
  setTimeout(() => {
    page.emit('request', { url: () => 'http://localhost:1455/auth/callback?code=one-time&state=expected' });
  }, 10);
  const callback = await pending;
  assert.deepEqual({ code: callback.code, state: callback.state }, { code: 'one-time', state: 'expected' });
  assert.equal(page.listenerCount('request'), 0);
  assert.equal(page.listenerCount('framenavigated'), 0);
});

test('BitBrowser client posts list/open without exposing window mutation helpers', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    const body = JSON.parse(init.body);
    if (url.endsWith('/browser/list')) return new Response(JSON.stringify({ data: { list: [{ id: 'w', name: 'us001_codex' }] } }), { status: 200 });
    assert.equal(body.id, 'w');
    return new Response(JSON.stringify({ data: { ws: 'ws://127.0.0.1:1234/devtools/browser/x' } }), { status: 200 });
  };
  const client = new BitBrowserClient({ baseUrl: 'http://127.0.0.1:54345', fetchImpl });
  assert.equal((await client.listWindows())[0].name, 'us001_codex');
  assert.equal((await client.openWindow('w')).ws.startsWith('ws://'), true);
  assert.deepEqual(calls.map((call) => new URL(call.url).pathname), ['/browser/list', '/browser/open']);
});

test('BitBrowser client passes optional launch arguments to browser/open', async () => {
  let requestBody;
  const client = new BitBrowserClient({
    baseUrl: 'http://127.0.0.1:54345',
    fetchImpl: async (url, init) => {
      requestBody = JSON.parse(init.body);
      return new Response(JSON.stringify({ data: { ws: 'ws://127.0.0.1:1234/devtools/browser/x' } }), { status: 200 });
    },
  });
  await client.openWindow('w', { args: ['--incognito'] });
  assert.deepEqual(requestBody, { id: 'w', args: ['--incognito'] });
});

test('BitBrowser close treats an already-stopped ESRCH process as closed', async () => {
  const client = new BitBrowserClient({
    baseUrl: 'http://127.0.0.1:54345',
    fetchImpl: async () => new Response(JSON.stringify({ success: false, msg: 'kill ESRCH' }), { status: 500 }),
  });
  await assert.doesNotReject(() => client.closeWindow('w'));
  const other = new BitBrowserClient({
    baseUrl: 'http://127.0.0.1:54345',
    fetchImpl: async () => new Response(JSON.stringify({ success: false, msg: 'permission denied' }), { status: 500 }),
  });
  await assert.rejects(() => other.closeWindow('w'), BitBrowserApiError);
});

test('Sub2API client fails closed when administrator credential is absent', async () => {
  const client = new Sub2ApiAdminClient({ fetchImpl: async () => { throw new Error('must not call network'); } });
  assert.equal(client.baseUrl, 'https://sub2apiplus.opencodex.uk');
  await assert.rejects(() => client.generateOpenAiAuthUrl(), /administrator credentials are missing/);
});

test('Sub2API OpenAI OAuth endpoint payload and callback parsing', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body), authorization: init.headers.authorization });
    if (url.endsWith('/generate-auth-url')) return new Response(JSON.stringify({ code: 0, data: { auth_url: 'https://auth.openai.com/oauth/authorize?state=expected', session_id: 'session' } }), { status: 200 });
    return new Response(JSON.stringify({ code: 0, data: { ok: true } }), { status: 200 });
  };
  const client = new Sub2ApiAdminClient({ token: 'runtime-only', fetchImpl });
  const authorization = await client.generateOpenAiAuthUrl();
  assert.deepEqual(authorization, { authUrl: 'https://auth.openai.com/oauth/authorize?state=expected', sessionId: 'session', state: 'expected' });
  assert.equal(new URL(calls[0].url).pathname, '/api/v1/admin/openai/generate-auth-url');
  await client.exchangeOpenAiCode({ sessionId: authorization.sessionId, code: 'code', state: authorization.state });
  assert.equal(calls[0].body.proxy_id, undefined);
  assert.deepEqual(calls[1].body, { session_id: 'session', code: 'code', state: 'expected' });
  assert.equal(new URL(calls[1].url).pathname, '/api/v1/admin/openai/exchange-code');
  assert.equal(parseCodeInput('http://localhost:1455/auth/callback?code=code&state=expected').code, 'code');
});

test('OpenAI import creates a missing account and verifies it in the account list', async () => {
  const calls = [];
  let created;
  const fetchImpl = async (url, init) => {
    const parsed = new URL(url);
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method: init.method, path: parsed.pathname, query: parsed.search, body });
    if (init.method === 'GET') {
      return new Response(JSON.stringify({ code: 0, data: created ? { items: [created], total: 1 } : { items: [], total: 0 } }), { status: 200 });
    }
    assert.equal(parsed.pathname, '/api/v1/admin/accounts');
    assert.equal(body.platform, 'openai');
    assert.equal(body.type, 'oauth');
    assert.equal(body.name, 'operator@example.com');
    assert.equal(body.credentials.access_token, 'access-token');
    assert.equal(body.extra.email, 'operator@example.com');
    created = { id: 'account-1', platform: 'openai', extra: { email: 'operator@example.com' } };
    return new Response(JSON.stringify({ code: 0, data: created }), { status: 200 });
  };
  const client = new Sub2ApiAdminClient({ token: 'runtime-only', fetchImpl });
  const result = await client.importOpenAiOAuthAccount({
    email: 'operator@example.com',
    exchangeResult: { access_token: 'access-token', expires_at: 123, email: 'operator@example.com' },
    verifyAttempts: 1,
  });
  assert.deepEqual(result, { action: 'created', accountId: 'account-1' });
  assert.deepEqual(calls.map(({ method, path }) => [method, path]), [
    ['GET', '/api/v1/admin/accounts'],
    ['POST', '/api/v1/admin/accounts'],
    ['GET', '/api/v1/admin/accounts'],
  ]);
});

test('OpenAI import updates an existing exact email through the OAuth credentials endpoint', async () => {
  const calls = [];
  const existing = { id: 'account-9', platform: 'openai', credentials: { email: 'operator@example.com' } };
  const fetchImpl = async (url, init) => {
    const parsed = new URL(url);
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method: init.method, path: parsed.pathname, body });
    if (init.method === 'GET') return new Response(JSON.stringify({ code: 0, data: { items: [existing], total: 1 } }), { status: 200 });
    assert.equal(parsed.pathname, '/api/v1/admin/accounts/account-9/apply-oauth-credentials');
    assert.deepEqual(body, {
      type: 'oauth',
      credentials: { access_token: 'new-token', expires_at: '456', email: 'operator@example.com' },
      extra: { email: 'operator@example.com' },
    });
    return new Response(JSON.stringify({ code: 0, data: existing }), { status: 200 });
  };
  const client = new Sub2ApiAdminClient({ token: 'runtime-only', fetchImpl });
  const result = await client.importOpenAiOAuthAccount({
    email: 'operator@example.com',
    exchangeResult: { access_token: 'new-token', expires_at: '456', email: 'operator@example.com' },
    verifyAttempts: 1,
  });
  assert.deepEqual(result, { action: 'updated', accountId: 'account-9' });
  assert.deepEqual(calls.map(({ method, path }) => [method, path]), [
    ['GET', '/api/v1/admin/accounts'],
    ['POST', '/api/v1/admin/accounts/account-9/apply-oauth-credentials'],
    ['GET', '/api/v1/admin/accounts'],
  ]);
});

test('OpenAI import rejects an exchange for a different email without exposing credentials', async () => {
  assert.throws(
    () => buildOpenAiCredentials({ access_token: 'sensitive-access-token' }),
    (error) => error instanceof Sub2ApiError && !error.message.includes('sensitive-access-token')
  );
  const client = new Sub2ApiAdminClient({ token: 'runtime-only', fetchImpl: async () => { throw new Error('network must not be called'); } });
  await assert.rejects(
    () => client.importOpenAiOAuthAccount({
      email: 'operator@example.com',
      exchangeResult: { access_token: 'sensitive-access-token', expires_at: 123, email: 'other@example.com' },
    }),
    (error) => error instanceof Sub2ApiError && !error.message.includes('sensitive-access-token')
  );
  assert.equal(safeError(new Sub2ApiError('failure', { status: 422, data: { access_token: 'sensitive-access-token' } })), 'Sub2API administrator request failed (HTTP 422)');
});

test('fixed controller opens only exact window and leaves it open on release', async () => {
  const calls = [];
  const fakeClient = {
    async listWindows() { return [{ id: 'w', name: 'us001_codex', status: 0, isDelete: 0 }, { id: 'other', name: 'us001', status: 1, isDelete: 0 }]; },
    async openWindow(id) { calls.push(['open', id]); return { id, ws: 'ws://fake' }; },
  };
  const fakeBrowser = {
    contexts() { return [{ pages: () => [], newContext: undefined, newPage: async () => ({ goto: async () => {} }) }]; },
    async close() { calls.push(['disconnect']); },
  };
  const controller = new FixedWindowController({ client: fakeClient, chromiumImpl: { connectOverCDP: async () => fakeBrowser } });
  const session = await controller.open({ url: 'https://auth.openai.com/oauth/authorize?state=x' });
  assert.equal(session.window.name, 'us001_codex');
  await controller.release();
  assert.deepEqual(calls, [['open', 'w'], ['disconnect']]);
});

test('incognito mode passes the launch argument and creates an isolated context', async () => {
  const calls = [];
  const persistentContext = { pages: () => [], newPage: async () => ({ goto: async () => { calls.push(['goto']); } }) };
  const isolatedContext = {
    pages: () => [],
    newPage: async () => ({ goto: async () => { calls.push(['goto']); } }),
    async close() { calls.push(['context-close']); },
  };
  const fakeClient = {
    async listWindows() { return [{ id: 'w', name: 'us001_codex', status: 0, isDelete: 0 }]; },
    async openWindow(id, options) { calls.push(['open', id, options]); return { id, ws: 'ws://fake' }; },
  };
  const fakeBrowser = {
    contexts() { calls.push(['contexts']); return [persistentContext]; },
    async newContext() { calls.push(['new-context']); return isolatedContext; },
    async close() { calls.push(['disconnect']); },
  };
  const controller = new FixedWindowController({ client: fakeClient, chromiumImpl: { connectOverCDP: async () => fakeBrowser } });
  const session = await controller.open({ url: 'https://auth.openai.com/oauth/authorize?state=x', incognito: true });
  assert.equal(session.context, isolatedContext);
  assert.equal(session.incognito, true);
  await controller.release();
  assert.deepEqual(calls, [
    ['open', 'w', { args: ['--incognito'] }],
    ['new-context'],
    ['goto'],
    ['context-close'],
    ['disconnect'],
  ]);
});

test('BitBrowser launch-level incognito can restart exact window and retain its default context', async () => {
  const calls = [];
  const persistentContext = {
    pages: () => [],
    newPage: async () => ({ goto: async () => { calls.push(['goto']); } }),
    async close() { calls.push(['unexpected-context-close']); },
  };
  const fakeClient = {
    async listWindows() { return [{ id: 'w', name: 'us001_codex', status: 1, isDelete: 0 }]; },
    async closeWindow(id) { calls.push(['close-window', id]); },
    async openWindow(id, options) { calls.push(['open', id, options]); return { id, ws: 'ws://fake' }; },
  };
  const fakeBrowser = {
    contexts() { calls.push(['contexts']); return [persistentContext]; },
    async newContext() { calls.push(['unexpected-new-context']); return persistentContext; },
    async close() { calls.push(['disconnect']); },
  };
  const controller = new FixedWindowController({ client: fakeClient, chromiumImpl: { connectOverCDP: async () => fakeBrowser } });
  const session = await controller.open({
    url: 'https://accounts.google.com/', incognito: true,
    restartForLaunchArgs: true, useDefaultContext: true,
  });
  assert.equal(session.context, persistentContext);
  assert.equal(session.ownsContext, false);
  await controller.release();
  assert.deepEqual(calls, [
    ['close-window', 'w'],
    ['open', 'w', { args: ['--incognito'] }],
    ['contexts'],
    ['goto'],
    ['disconnect'],
  ]);
});

test('BitBrowser can restart exact window into the saved persistent context', async () => {
  const calls = [];
  const context = { pages: () => [{}] };
  const browser = { contexts: () => [context], async close() { calls.push(['disconnect']); } };
  const controller = new FixedWindowController({
    client: {
      async listWindows() { return [{ id: 'w', name: 'us001_codex', status: 1 }]; },
      async closeWindow(id) { calls.push(['close-window', id]); },
      async openWindow(id, options) { calls.push(['open', id, options]); return { ws: 'ws://fake' }; },
    },
    chromiumImpl: { connectOverCDP: async () => browser },
  });
  const session = await controller.open({ restartWindow: true, useDefaultContext: true });
  assert.equal(session.context, context);
  assert.equal(session.ownsContext, false);
  await controller.release();
  assert.deepEqual(calls, [
    ['close-window', 'w'], ['open', 'w', {}], ['disconnect'],
  ]);
});

test('direct browser egress is an explicit launch-only option on the exact profile', async () => {
  const calls = [];
  const context = {
    pages: () => [{ goto: async () => {} }],
    close: async () => {},
  };
  const browser = {
    newContext: async () => context,
    contexts: () => [],
    close: async () => {},
  };
  const controller = new FixedWindowController({
    client: {
      listWindows: async () => [{ id: 'fixed', name: 'us001_codex', status: 0 }],
      openWindow: async (id, options) => {
        calls.push({ id, options });
        return { ws: 'ws://fixed' };
      },
    },
    chromiumImpl: { connectOverCDP: async () => browser },
  });
  await controller.open({ incognito: true, directEgress: true });
  assert.deepEqual(calls, [{
    id: 'fixed',
    options: { args: ['--incognito', '--no-proxy-server'] },
  }]);
  await controller.release();
});

test('CLI accepts and documents incognito mode', () => {
  assert.deepEqual(parseArgs(['start', '--incognito', '--proxy-id', '7']), {
    command: 'start',
    incognito: true,
    proxyId: 7,
  });
  assert.match(usage(), /--incognito/);
  assert.match(usage(), /import-account/);
  assert.match(usage(), /probe-accounts/);
  assert.match(usage(), /import-next/);
  assert.match(usage(), /inventory-sync-accounts/);
  assert.match(usage(), /inventory-ban-pool-status/);
  assert.match(usage(), /inventory-ban-and-replace/);
  assert.match(usage(), /inventory-import-next/);
  assert.match(usage(), /account-health-audit/);
  assert.match(usage(), /reauthorize-errors/);
  assert.match(usage(), /pool-import-phones/);
  assert.match(usage(), /pool-reset-phone-cooldowns/);
  assert.match(usage(), /pool-correct-invalid-phone/);
  assert.match(usage(), /pool-enable-resend/);
  assert.deepEqual(parseArgs(['reauthorize-errors', '--email', 'account@example.com', '--replace-banned']), {
    command: 'reauthorize-errors',
    email: 'account@example.com',
    replaceBanned: true,
  });
  assert.deepEqual(parseArgs(['reauthorize-errors', '--retry-banned']), {
    command: 'reauthorize-errors',
    retryBanned: true,
  });
});

test('CLI accepts explicit sanitized Google state tracing', () => {
  assert.deepEqual(parseArgs(['antigravity-oauth-import-next', '--proxy-id', '1', '--trace-google-state']), {
    command: 'antigravity-oauth-import-next', proxyId: 1, traceGoogleState: true,
  });
});

test('CLI rejects non-numeric proxy IDs before any API call', () => {
  assert.throws(() => parseArgs(['start', '--proxy-id', 'proxy']), /positive integer/);
  assert.throws(() => parseArgs(['start', '--proxy-id', '0']), /positive integer/);
});

test('OpenAI account runtime values stay process-only and phone fields are lazy', () => {
  assert.deepEqual(loadOpenAiAccountRuntime({
    OPENAI_ACCOUNT_EMAIL: 'operator@example.com',
    OPENAI_ACCOUNT_PASSWORD: 'runtime-password',
    OPENAI_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
  }), {
    email: 'operator@example.com',
    password: 'runtime-password',
    totpSecret: 'JBSWY3DPEHPK3PXP',
    phone: '',
    smsAccessUrl: '',
  });
  assert.throws(() => loadOpenAiAccountRuntime({}), OpenAiImportConfigError);
});

test('OpenAI import normalizes US phones and detects the optional phone branch', () => {
  assert.equal(normalizeUsPhoneNumber('1 (443) 750-9348'), '4437509348');
  assert.equal(normalizeUsPhoneNumber('4437509348'), '4437509348');
  assert.throws(() => normalizeUsPhoneNumber('123'), OpenAiImportConfigError);
  assert.equal(detectOpenAiAuthRoute('https://auth.openai.com/add-phone'), 'add_phone');
  assert.equal(detectOpenAiAuthRoute('https://auth.openai.com/phone-verification'), 'phone_verification');
  assert.equal(detectOpenAiAuthRoute('https://auth.openai.com/sign-in-with-chatgpt/codex/consent'), 'consent');
});

test('OpenAI password state submits once and reports a rate limit without retrying', async () => {
  let fills = 0;
  let clicks = 0;
  const password = {
    async waitFor() {},
    async isEditable() { return true; },
    async fill() { fills += 1; },
  };
  const page = {
    url: () => 'https://auth.openai.com/log-in/password',
    locator: (selector) => {
      if (selector === 'body') {
        return { innerText: async () => clicks > 0 ? 'Too many attempts. Try again later.' : '' };
      }
      if (selector === 'input[type="password"]') return password;
      throw new Error(`unexpected selector: ${selector}`);
    },
    getByRole: () => ({ click: async () => { clicks += 1; } }),
    waitForTimeout: async () => {},
  };
  const flow = new OpenAiAccountImportFlow({
    sub2api: {},
    browser: {},
    account: { password: 'runtime-only' },
  });
  await assert.rejects(
    () => flow.completeLogin(page, { timeoutMs: 1_000 }),
    (error) => error instanceof OpenAiLoginError && error.code === 'rate_limited'
  );
  assert.equal(fills, 1);
  assert.equal(clicks, 1);
  assert.equal(safeError(new OpenAiLoginError('sensitive', 'rate_limited')), 'OpenAI login is temporarily rate limited; the account was deferred');
});

test('Codex rate-limit footer is informational, not an active login limit', () => {
  assert.equal(isOpenAiRateLimitText('Your ChatGPT rate limits apply to Codex.'), false);
  assert.equal(isOpenAiRateLimitText('Too many attempts. Try again later.'), true);
  assert.equal(isOpenAiRateLimitText('Rate-limited request'), true);
});

test('OpenAI route 500 regenerates OAuth authorization before retrying login', async () => {
  assert.equal(isOpenAiRouteErrorText('Oops, an error occurred! Route Error (500 Internal Server Error): {"isTrusted":true}'), true);
  assert.equal(isOpenAiRouteErrorText('Oops, an error occurred! Unexpected token \'<\', "<!DOCTYPE "... is not valid JSON'), true);
  let generated = 0;
  let opened = 0;
  let released = 0;
  const fakeSub2Api = {
    async generateOpenAiAuthUrl() {
      generated += 1;
      return {
        authUrl: `https://auth.openai.com/oauth/authorize?state=state-${generated}`,
        sessionId: `session-${generated}`,
        state: `state-${generated}`,
      };
    },
    async exchangeOpenAiCode() {
      return { access_token: 'runtime-only', expires_at: 1, email: 'account@example.com' };
    },
    async importOpenAiOAuthAccount() { return { action: 'updated', accountId: 'account-id' }; },
  };
  const routeErrorPage = {
    url: () => 'https://auth.openai.com/oauth/authorize',
    locator: (selector) => selector === 'body'
      ? { innerText: async () => 'Oops, an error occurred! Route Error (500 Internal Server Error)' }
      : { waitFor: async () => {}, isEditable: async () => false },
  };
  const successPage = {
    url: () => 'https://auth.openai.com/sign-in-with-chatgpt/codex/consent',
    locator: (selector) => selector === 'body'
      ? { innerText: async () => '' }
      : { waitFor: async () => {}, isEditable: async () => false },
    getByRole: () => ({ click: async () => {} }),
  };
  const fakeBrowser = {
    async open() {
      opened += 1;
      return {
        page: opened === 1 ? routeErrorPage : successPage,
        async waitForCallback() { return { code: 'code', state: 'state-2' }; },
      };
    },
    async release() { released += 1; },
  };
  const flow = new OpenAiAccountImportFlow({
    sub2api: fakeSub2Api,
    browser: fakeBrowser,
    account: { email: 'account@example.com', password: 'runtime-only', totpSecret: 'JBSWY3DPEHPK3PXP' },
  });
  const result = await flow.run({ incognito: false, timeoutMs: 1_000, maxRouteRetries: 1 });
  assert.equal(result.outcome.action, 'updated');
  assert.equal(generated, 2);
  assert.equal(opened, 2);
  assert.equal(released, 2);
});

test('OpenAI login probe stops before phone allocation or OAuth consent', async () => {
  let generated = 0;
  let preparedPhones = 0;
  let released = 0;
  const fakeSub2Api = {
    async generateOpenAiAuthUrl() {
      generated += 1;
      return {
        authUrl: 'https://auth.openai.com/oauth/authorize?state=runtime-only',
        sessionId: 'runtime-only',
        state: 'runtime-only',
      };
    },
  };
  const page = {
    url: () => 'https://auth.openai.com/add-phone',
    locator: (selector) => selector === 'body'
      ? { innerText: async () => '' }
      : { waitFor: async () => {}, isEditable: async () => true },
  };
  const fakeBrowser = {
    async open() { return { page }; },
    async release({ closeWindow }) {
      assert.equal(closeWindow, false);
      released += 1;
    },
  };
  const flow = new OpenAiAccountImportFlow({
    sub2api: fakeSub2Api,
    browser: fakeBrowser,
    account: { email: 'account@example.com', password: 'runtime-only', totpSecret: 'JBSWY3DPEHPK3PXP' },
    preparePhone: async () => { preparedPhones += 1; },
  });
  const result = await flow.probe({ incognito: true, timeoutMs: 1_000 });
  assert.equal(result.login.reached, 'phone_verification');
  assert.equal(result.login.phoneVerification, 'required');
  assert.equal(generated, 1);
  assert.equal(preparedPhones, 0);
  assert.equal(released, 1);
});

test('OpenAI banned-account text becomes a terminal sanitized login classification', async () => {
  const page = {
    url: () => 'https://auth.openai.com/log-in/password',
    locator: (selector) => selector === 'body'
      ? { innerText: async () => 'Your account has been deactivated.' }
      : { waitFor: async () => {}, isEditable: async () => true },
    waitForTimeout: async () => {},
  };
  const flow = new OpenAiAccountImportFlow({ sub2api: {}, browser: {}, account: {} });
  await assert.rejects(
    () => flow.completeLogin(page, { timeoutMs: 1_000 }),
    (error) => error instanceof OpenAiLoginError && error.code === 'account_banned'
  );
  assert.equal(
    safeError(new OpenAiLoginError('sensitive account identifier', 'account_banned')),
    'OpenAI account is banned or deactivated; it was not reauthorized'
  );
});

test('OpenAI account_deactivated error code becomes a terminal banned classification', async () => {
  const page = {
    url: () => 'https://auth.openai.com/log-in/password',
    locator: (selector) => selector === 'body'
      ? { innerText: async () => 'Authentication Error. You do not have an account because it has been deleted or deactivated. error_code: account_deactivated' }
      : { waitFor: async () => {}, isEditable: async () => true },
    waitForTimeout: async () => {},
  };
  const flow = new OpenAiAccountImportFlow({ sub2api: {}, browser: {}, account: {} });
  await assert.rejects(
    () => flow.completeLogin(page, { timeoutMs: 1_000 }),
    (error) => error instanceof OpenAiLoginError && error.code === 'account_banned'
  );
});

test('OpenAI login recognizes the new Welcome back email page without a legacy URL route', async () => {
  let submittedEmail = '';
  let submitted = false;
  const hiddenLocator = {
    isVisible: async () => false,
    first() { return this; },
  };
  const page = {
    url: () => 'https://auth.openai.com/log-in',
    locator: (selector) => selector === 'body'
      ? { innerText: async () => 'Welcome back Email address Continue' }
      : hiddenLocator,
    getByText: () => ({ isVisible: async () => false }),
    getByPlaceholder: (name) => ({
      isVisible: async () => name === 'Email address' && !submitted,
      waitFor: async () => {},
      isEditable: async () => true,
      fill: async (value) => { submittedEmail = value; },
      press: async () => { submitted = true; },
    }),
    getByRole: () => ({ isVisible: async () => submitted }),
    waitForTimeout: async () => {},
  };
  const flow = new OpenAiAccountImportFlow({
    sub2api: {},
    browser: {},
    account: { email: 'account@example.com' },
  });
  const result = await flow.completeLogin(page, { timeoutMs: 1_000 });
  assert.equal(submittedEmail, 'account@example.com');
  assert.equal(result.phoneVerification, 'not_required');
});

test('local TOTP matches RFC 6238 six-digit vectors', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal(generateTotp(secret, 59_000), '287082');
  assert.equal(generateTotp(secret, 1_111_111_109_000), '081804');
  assert.equal(generateTotp(secret, 1_234_567_890_000), '005924');
  assert.equal(normalizeTotpSecret('jbsw y3dp-ehpk3pxp==='), 'JBSWY3DPEHPK3PXP');
});

test('SMS polling extracts one six-digit code and retries without browser access', async () => {
  let calls = 0;
  const result = await pollSmsCode({
    url: 'https://sms.example.invalid/access',
    attempts: 3,
    intervalMs: 0,
    requestText: async () => {
      calls += 1;
      return calls < 3 ? 'yes|waiting' : 'yes|Your verification code is: 266177 - done';
    },
    sleep: async () => {},
  });
  assert.deepEqual(result, { code: '266177', attempt: 3 });
  assert.equal(extractSmsCode('id 12345 and value 1234567'), '');
});

test('direct SMS request uses the Windows native fallback after a Node TLS failure', async () => {
  const requestImpl = () => {
    const request = new EventEmitter();
    request.end = () => queueMicrotask(() => request.emit('error', Object.assign(new Error('reset'), { code: 'ECONNRESET' })));
    request.destroy = () => {};
    return request;
  };
  let fallbackCalls = 0;
  const body = await directSmsRequest('https://sms.example.invalid/access?token=runtime-only', {
    platform: 'win32',
    requestImpl,
    windowsRequest: async () => {
      fallbackCalls += 1;
      return 'yes|Your verification code is: 654321';
    },
  });
  assert.equal(fallbackCalls, 1);
  assert.equal(extractSmsCode(body), '654321');
});

test('Windows SMS fallback keeps the URL out of process arguments and does not inherit admin secrets', async () => {
  let captured;
  const body = await windowsSmsRequest('https://sms.example.invalid/access?token=runtime-only', {
    timeoutMs: 1_000,
    execFileImpl: (executable, args, options, callback) => {
      captured = { executable, args, options };
      callback(null, 'yes|654321');
    },
  });
  assert.equal(body, 'yes|654321');
  assert.equal(captured.args.join(' ').includes('runtime-only'), false);
  assert.equal(captured.options.env.SUB2API_SMS_ACCESS_URL.endsWith('runtime-only'), true);
  assert.equal(captured.options.env.SUB2API_ADMIN_API_KEY, undefined);
  assert.equal(Object.keys(captured.options.env).some((key) => /TOKEN|COOKIE|API_KEY/.test(key)), false);
});

test('phone verification polls six times, clicks resend once, then accepts the second round', async () => {
  let clock = 0;
  let rounds = 0;
  let resendClicks = 0;
  const result = await waitForSmsCodeWithResend({
    url: 'https://sms.example.invalid/access',
    phone: '14437509348',
    smsPoller: async ({ attempts }) => {
      assert.equal(attempts, 6);
      rounds += 1;
      clock += 50_000;
      if (rounds === 1) throw new SmsCodeTimeoutError(attempts);
      return { code: '654321', attempt: 2 };
    },
    resend: async () => { resendClicks += 1; },
    now: () => clock,
    sleep: async (ms) => { clock += ms; },
  });
  assert.deepEqual(result, { code: '654321', attempt: 2, round: 2, resent: true });
  assert.equal(resendClicks, 1);
  assert.equal(clock, 110_000);
});

test('phone verification reserves invalid-number reporting after two full failed rounds', async () => {
  let clock = 0;
  let rounds = 0;
  let resendClicks = 0;
  const invalidReports = [];
  await assert.rejects(
    () => waitForSmsCodeWithResend({
      url: 'https://sms.example.invalid/access',
      phone: '1 (443) 750-9348',
      smsPoller: async ({ attempts }) => {
        rounds += 1;
        clock += 50_000;
        throw new SmsCodeTimeoutError(attempts);
      },
      resend: async () => { resendClicks += 1; },
      phoneStatusApi: { markInvalid: async (details) => { invalidReports.push(details); } },
      now: () => clock,
      sleep: async (ms) => { clock += ms; },
    }),
    (error) => error instanceof SmsCodeTimeoutError && error.attempts === 12 && error.resendAttempted
  );
  assert.equal(rounds, 2);
  assert.equal(resendClicks, 1);
  assert.equal(clock, 120_000);
  assert.deepEqual(invalidReports, [{
    phone: '4437509348',
    reason: 'sms_code_unavailable_after_resend',
    attempts: 12,
  }]);
  assert.deepEqual(await new PhoneStatusApi().markInvalid({}), { submitted: false });
});

test('phone policy can poll for two minutes without clicking resend', async () => {
  let clock = 0;
  let resendClicks = 0;
  const invalidReports = [];
  await assert.rejects(
    () => waitForSmsCodeWithResend({
      url: 'https://sms.example.invalid/access',
      phone: '14109824518',
      allowResend: false,
      smsPoller: async ({ attempts }) => {
        clock += 50_000;
        throw new SmsCodeTimeoutError(attempts);
      },
      resend: async () => { resendClicks += 1; },
      phoneStatusApi: { markInvalid: async (details) => invalidReports.push(details) },
      now: () => clock,
      sleep: async (ms) => { clock += ms; },
    }),
    (error) => error instanceof SmsCodeTimeoutError && !error.resendAttempted
  );
  assert.equal(clock, 120_000);
  assert.equal(resendClicks, 0);
  assert.equal(invalidReports[0].reason, 'sms_code_unavailable_without_resend');
});

test('phone verification rechecks the route after polling instead of waiting on a stale input', async () => {
  let route = 'https://auth.openai.com/phone-verification';
  let nonBodyLocatorCalls = 0;
  const page = {
    url: () => route,
    locator: (selector) => {
      if (selector === 'body') return { innerText: async () => '' };
      nonBodyLocatorCalls += 1;
      throw new Error('stale phone input must not be queried after consent navigation');
    },
    waitForTimeout: async () => {},
  };
  const flow = new OpenAiAccountImportFlow({
    sub2api: {},
    browser: {},
    account: { phone: '14437509348', smsAccessUrl: 'https://sms.example.invalid/access' },
    smsPoller: async () => {
      route = 'https://auth.openai.com/sign-in-with-chatgpt/codex/consent';
      return { code: '654321', attempt: 1 };
    },
  });
  assert.deepEqual(await flow.completeLogin(page, { timeoutMs: 1_000 }), { phoneVerification: 'completed' });
  assert.equal(nonBodyLocatorCalls, 0);
  assert.match(PHONE_CODE_INPUT_SELECTOR, /input\[name="code"\]/);
  assert.match(PHONE_CODE_INPUT_SELECTOR, /input\[placeholder="Code" i\]/);
});

test('exchange result classification rejects explicit application-level false flags', () => {
  assert.deepEqual(classifyExchangeResult(null), { accepted: false, reason: 'empty_result' });
  assert.deepEqual(classifyExchangeResult({ imported: false }), { accepted: false, reason: 'imported_false' });
  assert.equal(classifyExchangeResult({ ok: true, status: 'created' }).accepted, true);
});

test('OAuth flow enforces callback state before exchange', async () => {
  const fakeSub2Api = {
    async generateOpenAiAuthUrl() { return { authUrl: 'https://auth.openai.com/oauth/authorize?state=expected', sessionId: 'session', state: 'expected' }; },
    async exchangeOpenAiCode() { return { ok: true }; },
  };
  const fakeSession = { window: { name: 'us001_codex' }, async waitForCallback() { return { code: 'code', state: 'wrong' }; } };
  const fakeBrowser = { async open() { return fakeSession; }, async release() {} };
  const flow = new OAuthFlow({ sub2api: fakeSub2Api, browser: fakeBrowser });
  await assert.rejects(() => flow.run({ timeoutMs: 1 }), /state does not match/);
});

test('local pool parsers validate phone URLs, TOTP secrets, and no-resend policy', () => {
  assert.match(DEFAULT_GOOGLE_POOL_FILE, /google-account-pool\.dpapi$/);
  const phones = parsePhonePoolSource([
    '14109824518|https://sms.example.invalid/access?token=runtime-only',
    'bad-line',
  ].join('\n'));
  assert.equal(phones.phones.length, 1);
  assert.equal(phones.phones[0].phone, '4109824518');
  assert.equal(phones.phones[0].allowResend, false);
  assert.equal(phones.issues.length, 1);

  const accounts = parseAccountPoolSource([
    'operator@example.com|runtime-password|JBSWY3DPEHPK3PXP',
    'invalid@example.com|runtime-password|not-base32!',
  ].join('\n'));
  assert.equal(accounts.accounts.length, 1);
  assert.equal(accounts.issues.length, 1);

  const googleAccounts = parseGoogleAccountPoolSource([
    'google-url@example.com|runtime-password|https://two-factor.example.invalid/access?id=runtime-only',
    'google-totp@example.com|runtime-password|JBSWY3DPEHPK3PXP',
    'invalid@example.com|runtime-password|http://two-factor.example.invalid/access',
  ].join('\n'));
  assert.equal(googleAccounts.accounts.length, 2);
  assert.deepEqual(
    googleAccounts.accounts.map((item) => item.twoFactor.kind),
    ['https-url', 'totp-secret']
  );
  assert.equal(googleAccounts.issues.length, 1);
});

test('local pool encrypts its file and enforces the 45-minute phone cooldown', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-pool-'));
  const file = path.join(directory, 'pool.dpapi');
  let clock = 1_000_000;
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  const store = new LocalImportPoolStore({ file, protect, unprotect, now: () => clock });
  try {
    assert.deepEqual(
      await store.importPhones('14109824518|https://sms.example.invalid/access?token=runtime-only'),
      { added: 1, rejected: 0, total: 1 }
    );
    assert.deepEqual(
      await store.importAccounts('operator@example.com|runtime-password|JBSWY3DPEHPK3PXP'),
      { added: 1, rejected: 0, total: 1 }
    );
    const stored = fs.readFileSync(file, 'utf8');
    assert.equal(stored.includes('operator@example.com'), false);
    assert.equal(stored.includes('runtime-only'), false);

    const selected = await store.beginNextAttempt();
    assert.equal(selected.account.email, 'operator@example.com');
    assert.equal(selected.phone.phone, '4109824518');
    await store.markPhoneUsed(selected.phone.id);
    assert.deepEqual((await store.summary()).phones, {
      total: 1,
      available: 0,
      cooldown: 1,
      invalid: 0,
    });
    assert.deepEqual(await store.resetPhoneCooldowns(), { reset: 1, total: 1 });
    assert.equal((await store.summary()).phones.available, 1);
    const resetPhone = (await store.load()).phones[0];
    assert.equal(resetPhone.lastCooldownResetPreviousUsedAt, 1_000_000);
    assert.equal(resetPhone.lastCooldownResetAt, 1_000_000);
    assert.equal(resetPhone.manualResetCount, 1);
    await store.markPhoneUsed(selected.phone.id);
    await store.markPhoneInvalid(selected.phone.id, 'sms_unavailable');
    assert.deepEqual(await store.correctInvalidPhoneToCooldown({ allowResend: true }), {
      corrected: 1,
      total: 1,
    });
    const correctedPhone = (await store.load()).phones[0];
    assert.equal(correctedPhone.status, 'available');
    assert.equal(correctedPhone.allowResend, true);
    assert.equal(correctedPhone.lastUsedAt, 1_000_000);
    assert.equal(correctedPhone.correctionCount, 1);
    assert.deepEqual(await store.setAvailablePhonesAllowResend(false), {
      updated: 1,
      total: 1,
      allowResend: false,
    });
    clock += PHONE_COOLDOWN_MS;
    assert.equal((await store.summary()).phones.available, 1);
    await store.markAccountImported(selected.account.id);
    assert.deepEqual((await store.summary()).accounts, {
      total: 1,
      openai: { total: 1, pending: 0, imported: 1 },
      google: {
        total: 0,
        stored: 0,
        imported: 0,
        reviewRequired: 0,
        reviewReasons: {
          account_risk: 0,
          browser_rejected: 0,
          invalid_credentials: 0,
          invalid_two_factor: 0,
          rate_limited: 0,
        },
      },
    });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Workstation inventory sync keeps account secrets encrypted and retires removed pending rows', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-inventory-'));
  const file = path.join(directory, 'pool.dpapi');
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  const store = new LocalImportPoolStore({ file, protect, unprotect, now: () => 1_000_000 });
  try {
    assert.deepEqual(await store.syncInventoryAccounts({
      importLines: ['first@example.com|password-one|JBSWY3DPEHPK3PXP'],
      sourceVersion: 3,
      updatedAt: '2026-08-12T07:39:51Z',
    }), { added: 1, updated: 0, total: 1, sourceVersion: 3 });
    assert.equal(fs.readFileSync(file, 'utf8').includes('password-one'), false);
    await store.syncInventoryAccounts({
      importLines: ['second@example.com|password-two|JBSWY3DPEHPK3PXP'],
      sourceVersion: 4,
      updatedAt: '2026-08-12T08:00:00Z',
    });
    const selected = await store.beginNextAccountAttempt();
    assert.equal(selected.email, 'second@example.com');
    assert.equal((await store.summary()).accounts.openai.pending, 1);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('local pool isolates Google credentials from OpenAI selection and permits cross-provider emails', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-provider-pool-'));
  const file = path.join(directory, 'pool.dpapi');
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  const store = new LocalImportPoolStore({ file, protect, unprotect });
  const openAiRow = 'shared@example.com|runtime-password|JBSWY3DPEHPK3PXP';
  const googleRow = 'shared@example.com|runtime-password|https://two-factor.example.invalid/access?id=runtime-only';
  try {
    assert.deepEqual(await store.importAccounts(openAiRow), { added: 1, rejected: 0, total: 1 });
    assert.deepEqual(await store.importGoogleAccounts(googleRow), { added: 1, rejected: 0, total: 1 });
    assert.deepEqual(await store.importGoogleAccounts(googleRow), { added: 0, rejected: 0, total: 1 });

    const snapshot = await store.load();
    assert.equal(snapshot.version, POOL_VERSION);
    assert.equal(snapshot.accounts.length, 2);
    assert.deepEqual(
      snapshot.accounts.map((item) => [item.provider, item.status]).sort(),
      [['google', 'stored'], ['openai', 'pending']]
    );
    assert.equal(snapshot.accounts.find((item) => item.provider === 'google').twoFactor.kind, 'https-url');
    assert.equal(fs.readFileSync(file, 'utf8').includes('runtime-password'), false);

    const selected = await store.beginNextAccountAttempt();
    assert.equal(selected.provider, 'openai');
    const google = await store.findAccountByEmail('shared@example.com', { provider: 'google' });
    await assert.rejects(
      () => store.markAccountPending(google.id),
      (error) => error.code === 'account_provider_mismatch'
    );
    const googleSelected = await store.beginNextGoogleAttempt();
    assert.equal(googleSelected.id, google.id);
    assert.equal(googleSelected.twoFactor.kind, 'https-url');
    await store.markGoogleImported(google.id);
    assert.deepEqual((await store.summary()).accounts, {
      total: 2,
      openai: { total: 1, pending: 1, imported: 0 },
      google: {
        total: 1,
        stored: 0,
        imported: 1,
        reviewRequired: 0,
        reviewReasons: {
          account_risk: 0,
          browser_rejected: 0,
          invalid_credentials: 0,
          invalid_two_factor: 0,
          rate_limited: 0,
        },
      },
    });
    await assert.rejects(() => store.beginNextGoogleAttempt(), /No stored Google account/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('local pool defers rejected Google credentials for 24 hours', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-google-backoff-'));
  const file = path.join(directory, 'pool.dpapi');
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  let clock = Date.parse('2026-10-04T00:00:00Z');
  const store = new LocalImportPoolStore({ file, protect, unprotect, now: () => clock });
  try {
    await store.importGoogleAccounts([
      'first@example.com|runtime-password|JBSWY3DPEHPK3PXP',
      'second@example.com|runtime-password|JBSWY3DPEHPK3PXP',
    ].join('\n'));

    const first = await store.beginNextGoogleAttempt();
    assert.equal(first.email, 'first@example.com');
    await store.markGoogleStored(first.id, 'invalid_credentials');

    const second = await store.beginNextGoogleAttempt();
    assert.equal(second.email, 'second@example.com');

    clock += GOOGLE_INVALID_CREDENTIAL_BACKOFF_MS + 1;
    const retried = await store.beginNextGoogleAttempt();
    assert.equal(retried.id, first.id);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('local Google pool retains review status and sanitized note while skipping selection', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-google-review-'));
  const file = path.join(directory, 'google.dpapi');
  const store = new LocalImportPoolStore({
    file,
    protect: async (value) => Buffer.from(value).toString('base64'),
    unprotect: async (value) => Buffer.from(value, 'base64').toString('utf8'),
    now: () => 1_700_000_000_000,
  });
  await store.importGoogleAccounts([
    'first@example.com|password|JBSWY3DPEHPK3PXP',
    'second@example.com|password|JBSWY3DPEHPK3PXP',
  ].join('\n'));
  const first = await store.beginNextGoogleAttempt();
  await store.markGoogleReviewRequired(
    first.id,
    'account_risk',
    'Automatic OAuth stopped after sanitized outcome: account_risk. Owner review required.'
  );
  const second = await store.beginNextGoogleAttempt();
  assert.equal(second.email, 'second@example.com');
  const snapshot = await store.load();
  const reviewed = snapshot.accounts.find((item) => item.id === first.id);
  assert.equal(reviewed.status, 'review_required');
  assert.equal(reviewed.reviewReason, 'account_risk');
  assert.equal(reviewed.reviewRequiredAt, 1_700_000_000_000);
  const summary = await store.summary();
  assert.equal(summary.accounts.google.reviewRequired, 1);
  assert.equal(summary.accounts.google.reviewReasons.account_risk, 1);
});

test('Google OAuth terminal account outcomes require review while infrastructure failures remain selectable', async () => {
  const calls = [];
  const pool = {
    async markGoogleReviewRequired(...args) { calls.push(['review', ...args]); },
    async markGoogleStored(...args) { calls.push(['stored', ...args]); },
  };
  await recordGoogleAttemptFailure(pool, 'first-id', new GoogleLoginError('sanitized', 'manual_challenge'));
  await recordGoogleAttemptFailure(pool, 'second-id', new GoogleLoginError('sanitized', 'navigation_failed'));
  assert.equal(calls[0][0], 'review');
  assert.equal(calls[0][1], 'first-id');
  assert.equal(calls[0][2], 'account_risk');
  assert.match(calls[0][3], /account_risk/);
  assert.deepEqual(calls[1], ['stored', 'second-id', 'navigation_failed']);
});

test('local pool atomically replaces old Google rows and accepts dashed private input', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-google-replace-'));
  const file = path.join(directory, 'pool.dpapi');
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  const store = new LocalImportPoolStore({ file, protect, unprotect });
  try {
    await store.importGoogleAccounts('old@example.com|old-password|JBSWY3DPEHPK3PXP');
    assert.deepEqual(await store.replaceGoogleAccounts([
      'first@example.com----new-password----JBSWY3DPEHPK3PXP',
      'second@example.com----new-password----KRSXG5DSNFXGOIDB',
    ].join('\n')), { removed: 1, added: 2, total: 2 });
    const snapshot = await store.load();
    assert.deepEqual(snapshot.accounts.map((item) => item.email), [
      'first@example.com',
      'second@example.com',
    ]);
    assert.equal(fs.readFileSync(file, 'utf8').includes('new-password'), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('local pool migrates version 1 account rows to the OpenAI provider', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-provider-migration-'));
  const file = path.join(directory, 'pool.dpapi');
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  const legacy = {
    version: 1,
    phones: [],
    accounts: [{
      id: 'legacy-account',
      email: 'legacy@example.com',
      password: 'runtime-password',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      status: 'pending',
      attempts: 0,
      lastAttemptAt: null,
      lastOutcome: '',
      importedAt: null,
    }],
    accountHealthAudit: null,
  };
  fs.writeFileSync(file, `dpapi-v1:${Buffer.from(JSON.stringify(legacy), 'utf8').toString('base64')}`);
  const store = new LocalImportPoolStore({ file, protect, unprotect });
  try {
    const migrated = await store.load();
    assert.equal(migrated.version, POOL_VERSION);
    assert.equal(migrated.accounts[0].provider, 'openai');
    assert.equal((await store.beginNextAccountAttempt()).provider, 'openai');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Workstation inventory selection skips legacy local-only pending accounts', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-inventory-only-'));
  const file = path.join(directory, 'pool.dpapi');
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  const store = new LocalImportPoolStore({ file, protect, unprotect });
  const client = {
    async getAccountImportLines() {
      return {
        importLines: ['remote@example.com|remote-password|JBSWY3DPEHPK3PXP'],
        sourceVersion: 3,
        updatedAt: '2026-08-12T07:39:51Z',
      };
    },
  };
  try {
    await store.importAccounts('legacy@example.com|legacy-password|JBSWY3DPEHPK3PXP');
    const coordinator = new WorkstationInventoryImportCoordinator({ client, pool: store });
    const selected = await coordinator.beginNextAccountAttempt();
    assert.equal(selected.account.email, 'remote@example.com');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Workstation inventory selection skips accounts under retry backoff', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-inventory-backoff-'));
  const file = path.join(directory, 'pool.dpapi');
  let clock = 1_000_000;
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  const store = new LocalImportPoolStore({ file, protect, unprotect, now: () => clock });
  try {
    await store.syncInventoryAccounts({
      importLines: [
        'first@example.com|first-password|JBSWY3DPEHPK3PXP',
        'second@example.com|second-password|JBSWY3DPEHPK3PXP',
      ],
      sourceVersion: 3,
      updatedAt: '2026-08-12T07:39:51Z',
    });
    const first = await store.beginNextAccountAttempt({ inventoryOnly: true });
    assert.equal(first.email, 'first@example.com');
    await store.markAccountPending(first.id, 'rate_limited', { retryAfterMs: 15 * 60_000 });
    const second = await store.beginNextAccountAttempt({ inventoryOnly: true });
    assert.equal(second.email, 'second@example.com');
    await store.markAccountPending(second.id, 'failed');
    clock += 15 * 60_000;
    const retried = await store.beginNextAccountAttempt({ inventoryOnly: true });
    assert.equal(retried.email, 'first@example.com');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Workstation inventory coordinator reuses a persisted claim key after an unknown result', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-inventory-claim-'));
  const file = path.join(directory, 'pool.dpapi');
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  const store = new LocalImportPoolStore({ file, protect, unprotect, now: () => 1_000_000 });
  const claimKeys = [];
  let claimAttempts = 0;
  const client = {
    async getAccountImportLines() {
      return {
        importLines: ['operator@example.com|runtime-password|JBSWY3DPEHPK3PXP'],
        sourceVersion: 3,
        updatedAt: '2026-08-12T07:39:51Z',
      };
    },
    async getEligiblePhones() {
      return [{ id: 'phone-example-01', number: '+14109824518' }];
    },
    async claimPhone({ idempotencyKey }) {
      claimKeys.push(idempotencyKey);
      claimAttempts += 1;
      if (claimAttempts === 1) {
        throw new WorkstationAutomationError('unknown result', {
          retryable: true,
          outcomeUnknown: true,
        });
      }
      return {
        claimedAt: '2026-08-12T07:41:00Z',
        replayed: true,
        phone: { id: 'phone-example-01', number: '+14109824518' },
      };
    },
    async setPhoneUnavailable() {},
  };
  const coordinator = new WorkstationInventoryImportCoordinator({ client, pool: store });
  try {
    await store.importPhones('14109824518|https://sms.example.invalid/access?token=runtime-only');
    const selected = await coordinator.beginNextAccountAttempt();
    await assert.rejects(() => coordinator.preparePhone(selected.account.id), WorkstationAutomationError);
    const pendingClaim = await store.getAccountPhoneClaim(selected.account.id);
    assert.equal(pendingClaim.status, 'pending');
    const prepared = await coordinator.preparePhone(selected.account.id);
    assert.equal(prepared.phone, '4109824518');
    assert.equal(prepared.allowSmsResend, false);
    assert.equal(claimKeys[0], claimKeys[1]);
    assert.equal((await store.getAccountPhoneClaim(selected.account.id)).status, 'claimed');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Workstation replacement coordinator reuses a DPAPI idempotency key and syncs the promoted account', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-inventory-replacement-'));
  const file = path.join(directory, 'pool.dpapi');
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  const store = new LocalImportPoolStore({ file, protect, unprotect, now: () => 1_000_000 });
  const replacementKeys = [];
  let attempts = 0;
  const client = {
    async getAccountImportLines() {
      return {
        importLines: ['replacement@example.com|new-password|JBSWY3DPEHPK3PXP'],
        sourceVersion: 4,
        updatedAt: '2026-08-13T08:15:09Z',
      };
    },
    async banAndReplaceAccount({ account, idempotencyKey }) {
      assert.equal(account, 'banned@example.com');
      replacementKeys.push(idempotencyKey);
      attempts += 1;
      if (attempts === 1) {
        throw new WorkstationAutomationError('unknown result', {
          retryable: true,
          outcomeUnknown: true,
        });
      }
      return {
        replayed: true,
        bannedAccount: { id: 'ban-example-01', status: 'banned' },
      };
    },
  };
  const coordinator = new WorkstationInventoryImportCoordinator({ client, pool: store });
  try {
    await store.syncInventoryAccounts({
      importLines: ['banned@example.com|old-password|JBSWY3DPEHPK3PXP'],
      sourceVersion: 3,
      updatedAt: '2026-08-13T08:00:00Z',
    });
    const account = await store.findAccountByEmail('banned@example.com');
    await assert.rejects(() => coordinator.replaceBannedAccount(account.id), WorkstationAutomationError);
    const pending = (await store.load()).accounts[0].accountReplacement;
    assert.equal(pending.status, 'pending');
    const result = await coordinator.replaceBannedAccount(account.id);
    assert.equal(result.replayed, true);
    assert.equal(replacementKeys[0], replacementKeys[1]);
    const snapshot = await store.load();
    const banned = snapshot.accounts.find((item) => item.email === 'banned@example.com');
    const replacement = snapshot.accounts.find((item) => item.email === 'replacement@example.com');
    assert.equal(banned.accountReplacement.status, 'completed');
    assert.equal(banned.accountReplacement.banId, 'ban-example-01');
    assert.equal(banned.inventoryPresent, false);
    assert.equal(replacement.status, 'pending');
    assert.equal(replacement.inventoryPresent, true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Workstation replacement coordinator retires a definitively rejected key', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-inventory-replacement-reject-'));
  const file = path.join(directory, 'pool.dpapi');
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  const store = new LocalImportPoolStore({ file, protect, unprotect, now: () => 1_000_000 });
  const client = {
    async banAndReplaceAccount() {
      throw new WorkstationAutomationError('replacement unavailable', {
        status: 409,
        code: 'replacement_account_unavailable',
      });
    },
  };
  const coordinator = new WorkstationInventoryImportCoordinator({ client, pool: store });
  try {
    await store.syncInventoryAccounts({
      importLines: ['banned@example.com|old-password|JBSWY3DPEHPK3PXP'],
      sourceVersion: 3,
      updatedAt: '2026-08-13T08:00:00Z',
    });
    const account = await store.findAccountByEmail('banned@example.com');
    await assert.rejects(() => coordinator.replaceBannedAccount(account.id), WorkstationAutomationError);
    const stored = (await store.load()).accounts[0];
    assert.equal(stored.accountReplacement, null);
    assert.equal(stored.accountReplacementHistory.length, 1);
    assert.equal(stored.accountReplacementHistory[0].reason, 'replacement_account_unavailable');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Workstation replacement state rejects malformed identifiers before DPAPI persistence', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-inventory-replacement-validation-'));
  const file = path.join(directory, 'pool.dpapi');
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  const store = new LocalImportPoolStore({ file, protect, unprotect });
  try {
    await store.importAccounts('operator@example.com|runtime-password|JBSWY3DPEHPK3PXP');
    const account = await store.findAccountByEmail('operator@example.com');
    await assert.rejects(() => store.ensureAccountReplacement(account.id, 'short'), /16 to 128/);
    await store.ensureAccountReplacement(account.id, generateAccountReplacementKey());
    await assert.rejects(
      () => store.recordAccountReplacement(account.id, {
        idempotencyKey: generateAccountReplacementKey(),
        banId: 'invalid/id',
        replayed: false,
      }),
      /banId is invalid/
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Workstation coordinator does not claim an eligible phone without a local SMS mapping', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-inventory-mapping-'));
  const file = path.join(directory, 'pool.dpapi');
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  const store = new LocalImportPoolStore({ file, protect, unprotect });
  let claimCalls = 0;
  const client = {
    async getEligiblePhones() { return [{ id: 'phone-example-01', number: '+14109824518' }]; },
    async claimPhone() { claimCalls += 1; },
  };
  const coordinator = new WorkstationInventoryImportCoordinator({ client, pool: store });
  try {
    await store.syncInventoryAccounts({
      importLines: ['operator@example.com|runtime-password|JBSWY3DPEHPK3PXP'],
      sourceVersion: 3,
      updatedAt: '2026-08-12T07:39:51Z',
    });
    const account = await store.beginNextAccountAttempt();
    await assert.rejects(
      () => coordinator.preparePhone(account.id),
      (error) => error instanceof Error && error.code === 'phone_mapping_missing'
    );
    assert.equal(claimCalls, 0);
    assert.equal(await store.getAccountPhoneClaim(account.id), null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Workstation coordinator abandons a definitively rejected key and audits phone invalidation', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sub2api-inventory-reject-'));
  const file = path.join(directory, 'pool.dpapi');
  const protect = async (plainText) => Buffer.from(plainText, 'utf8').toString('base64');
  const unprotect = async (cipherText) => Buffer.from(cipherText, 'base64').toString('utf8');
  const store = new LocalImportPoolStore({ file, protect, unprotect, now: () => 1_000_000 });
  let unavailableCalls = 0;
  const client = {
    async getEligiblePhones() { return [{ id: 'phone-example-01', number: '+14109824518' }]; },
    async claimPhone() {
      throw new WorkstationAutomationError('not found', {
        status: 404,
        code: 'eligible_phone_not_found',
      });
    },
    async setPhoneUnavailable(id, unavailable) {
      assert.equal(id, 'phone-example-01');
      assert.equal(unavailable, true);
      unavailableCalls += 1;
    },
  };
  const coordinator = new WorkstationInventoryImportCoordinator({ client, pool: store });
  try {
    await store.importPhones('14109824518|https://sms.example.invalid/access?token=runtime-only');
    await store.syncInventoryAccounts({
      importLines: ['operator@example.com|runtime-password|JBSWY3DPEHPK3PXP'],
      sourceVersion: 3,
      updatedAt: '2026-08-12T07:39:51Z',
    });
    const account = await store.beginNextAccountAttempt();
    await assert.rejects(() => coordinator.preparePhone(account.id), WorkstationAutomationError);
    const rejected = await store.load();
    assert.equal(rejected.accounts[0].phoneClaim, null);
    assert.equal(rejected.accounts[0].phoneClaimHistory.length, 1);

    const pending = await store.ensureAccountPhoneClaim(account.id, generatePhoneClaimKey());
    await store.recordAccountPhoneClaim(account.id, {
      idempotencyKey: pending.idempotencyKey,
      phoneId: 'phone-example-01',
      phoneNumber: '+14109824518',
      claimedAt: '2026-08-12T07:41:00Z',
      replayed: false,
    });
    const mapping = await store.findPhoneMapping('+14109824518');
    await coordinator.markPhoneInvalid({
      accountId: account.id,
      localPhoneId: mapping.id,
      remotePhoneId: 'phone-example-01',
      reason: 'sms_code_unavailable_without_resend',
    });
    const invalid = await store.load();
    assert.equal(unavailableCalls, 1);
    assert.equal(invalid.phones[0].status, 'invalid');
    assert.equal(invalid.accounts[0].phoneClaim.status, 'invalid');
    assert.equal(invalid.accounts[0].phoneClaim.remoteUnavailableSynced, true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
