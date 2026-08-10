'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { BitBrowserClient } = require('../src/bitbrowser/client');
const { FixedWindowController, exactWindowMatches, parseCallbackUrl } = require('../src/bitbrowser/window-controller');
const { Sub2ApiAdminClient, parseCodeInput } = require('../src/sub2api/admin-client');
const { OAuthFlow } = require('../src/oauth/flow');
const { loadRuntimeEnv, parseRuntimeEnv } = require('../src/runtime-env');

test('runtime environment parser only accepts allowlisted non-empty values', () => {
  assert.deepEqual(parseRuntimeEnv('\n# comment\nSUB2API_ADMIN_API_KEY=secret\nSUB2API_BASE_URL=https://sub2apipro.opencodex.uk\n'), {
    SUB2API_ADMIN_API_KEY: 'secret',
    SUB2API_BASE_URL: 'https://sub2apipro.opencodex.uk',
  });
  assert.throws(() => parseRuntimeEnv('UNSAFE=value'), /Unsupported runtime environment key/);
  assert.throws(() => parseRuntimeEnv('SUB2API_ADMIN_API_KEY='), /value is empty/);
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
  assert.equal(parseCallbackUrl('http://localhost:1455/other?code=x'), null);
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

test('Sub2API client fails closed when administrator credential is absent', async () => {
  const client = new Sub2ApiAdminClient({ fetchImpl: async () => { throw new Error('must not call network'); } });
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
  assert.equal(new URL(calls[0].url).pathname, '/api/v1/admin/accounts/generate-auth-url');
  await client.exchangeOpenAiCode({ sessionId: authorization.sessionId, code: 'code', state: authorization.state });
  assert.equal(calls[0].body.proxy_id, undefined);
  assert.deepEqual(calls[1].body, { session_id: 'session', code: 'code', state: 'expected' });
  assert.equal(parseCodeInput('http://localhost:1455/auth/callback?code=code&state=expected').code, 'code');
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
