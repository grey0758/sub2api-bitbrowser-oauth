#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { FixedWindowController } = require('../src/bitbrowser/window-controller');
const { LocalImportPoolStore } = require('../src/pool/local-import-pool');
const { loadRuntimeEnv } = require('../src/runtime-env');
const { Sub2ApiAdminClient } = require('../src/sub2api/admin-client');
const { WorkstationAutomationClient } = require('../src/workstation/automation-client');
const { WorkstationInventoryImportCoordinator } = require('../src/workstation/inventory-import');

const FAKE_ACCOUNT_LINE = 'dependency-test@example.invalid|not-a-real-password|JBSWY3DPEHPK3PXP';
const FAKE_REPLACEMENT_LINE = 'replacement-test@example.invalid|not-a-real-password|JBSWY3DPEHPK3PXP';
const FAKE_PHONE = '+15550102020';
const FAKE_SMS_URL = 'https://sms.example.invalid/access';

function json(response, status, value) {
  response.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'private, no-store',
  });
  response.end(JSON.stringify(value));
}

async function readBody(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 64 * 1024) throw new Error('request body too large');
    chunks.push(chunk);
  }
  return chunks.length === 0 ? {} : JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

async function createFakeInventoryServer() {
  const state = {
    accountLine: FAKE_ACCOUNT_LINE,
    accountSourceVersion: 1,
    accountReplacements: new Map(),
    banPool: [],
    replacementRequests: 0,
    bindingCount: 0,
    unavailable: false,
    claims: new Map(),
    claimRequests: 0,
    unavailableUpdates: 0,
  };
  const server = http.createServer(async (request, response) => {
    try {
      if (request.headers.authorization !== 'Bearer dependency-test-token') {
        json(response, 401, { error: 'unauthorized' });
        return;
      }
      const url = new URL(request.url, 'http://127.0.0.1');
      if (request.method === 'GET' && url.pathname === '/api/v1/account-inventory/import-lines') {
        json(response, 200, {
          version: 1,
          source_version: state.accountSourceVersion,
          updated_at: '2026-08-12T00:00:00Z',
          count: 1,
          import_lines: [state.accountLine],
        });
        return;
      }
      if (request.method === 'GET' && url.pathname === '/api/v1/account-inventory/ban-pool') {
        const bannedCount = state.banPool.filter((item) => item.status === 'banned').length;
        json(response, 200, {
          version: 2,
          updated_at: '2026-08-12T00:00:00Z',
          count: state.banPool.length,
          banned_count: bannedCount,
          banned_replaced_count: state.banPool.length - bannedCount,
          pending_replacement_count: bannedCount,
          accounts: state.banPool,
        });
        return;
      }
      if (request.method === 'POST' && url.pathname === '/api/v1/account-inventory/ban-and-replace') {
        const key = String(request.headers['idempotency-key'] || '');
        const previous = state.accountReplacements.get(key);
        if (previous) {
          json(response, 200, { ...previous, replayed: true });
          return;
        }
        const body = await readBody(request);
        if (body.account !== 'dependency-test@example.invalid') {
          json(response, 404, { error: 'account_not_found' });
          return;
        }
        state.replacementRequests += 1;
        const bannedAccount = {
          id: 'dependency-test-ban',
          status: 'banned',
          banned_at: '2026-08-12T00:03:00Z',
          replaced_at: null,
          status_changed_at: '2026-08-12T00:03:00Z',
          account_import_line: FAKE_ACCOUNT_LINE,
          replacement_import_line: FAKE_REPLACEMENT_LINE,
        };
        state.banPool.push(bannedAccount);
        state.accountLine = FAKE_REPLACEMENT_LINE;
        state.accountSourceVersion += 1;
        const result = {
          version: 2,
          updated_at: '2026-08-12T00:03:00Z',
          replayed: false,
          banned_account: bannedAccount,
        };
        state.accountReplacements.set(key, result);
        json(response, 200, result);
        return;
      }
      if (request.method === 'GET' && url.pathname === '/api/v1/phone-inventory/eligible') {
        const phones = state.unavailable || state.bindingCount >= 3 ? [] : [{
          id: 'dependency-test-phone',
          number: FAKE_PHONE,
          unavailable: state.unavailable,
          binding_count: state.bindingCount,
          binding_limit: 3,
          last_binding_at: null,
          binding_events: [],
        }];
        json(response, 200, {
          version: 1,
          queried_at: '2026-08-12T00:00:00Z',
          binding_limit: 3,
          min_age_minutes: Number(url.searchParams.get('min_age_minutes')),
          count: phones.length,
          phones,
        });
        return;
      }
      if (request.method === 'POST' && url.pathname === '/api/v1/phone-inventory/claim') {
        const key = String(request.headers['idempotency-key'] || '');
        const previous = state.claims.get(key);
        if (previous) {
          json(response, 200, { ...previous, replayed: true });
          return;
        }
        await readBody(request);
        state.claimRequests += 1;
        state.bindingCount += 1;
        const result = {
          version: 1,
          claimed_at: '2026-08-12T00:01:00Z',
          replayed: false,
          phone: {
            id: 'dependency-test-phone',
            number: FAKE_PHONE,
            unavailable: false,
            binding_count: state.bindingCount,
            binding_limit: 3,
            last_binding_at: '2026-08-12T00:01:00Z',
            binding_events: [],
          },
        };
        state.claims.set(key, result);
        json(response, 200, result);
        return;
      }
      if (request.method === 'PATCH' && url.pathname === '/api/v1/phone-inventory/dependency-test-phone') {
        const body = await readBody(request);
        state.unavailable = body.unavailable === true;
        state.unavailableUpdates += 1;
        json(response, 200, {
          version: 1,
          updated_at: '2026-08-12T00:02:00Z',
          phone: {
            id: 'dependency-test-phone',
            number: FAKE_PHONE,
            unavailable: state.unavailable,
            binding_count: state.bindingCount,
            binding_limit: 3,
            last_binding_at: '2026-08-12T00:01:00Z',
            binding_events: [],
          },
        });
        return;
      }
      json(response, 404, { error: 'not_found' });
    } catch {
      json(response, 500, { error: 'internal_error' });
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return {
    server,
    state,
    baseUrl: `http://127.0.0.1:${server.address().port}`,
  };
}

async function runIsolatedFakeLifecycle() {
  const runtimeRoot = path.resolve(__dirname, '..', '.runtime', 'dependency-tests');
  const directory = path.join(runtimeRoot, crypto.randomUUID());
  const file = path.join(directory, 'pool.dpapi');
  const fake = await createFakeInventoryServer();
  try {
    const pool = new LocalImportPoolStore({ file });
    await pool.importPhones(`15550102020|${FAKE_SMS_URL}`);
    const coordinator = new WorkstationInventoryImportCoordinator({
      client: new WorkstationAutomationClient({
        baseUrl: fake.baseUrl,
        token: 'dependency-test-token',
      }),
      pool,
    });
    const selected = await coordinator.beginNextAccountAttempt();
    const phone = await coordinator.preparePhone(selected.account.id);
    await coordinator.markPhoneSubmitted(phone.localPhoneId);
    await coordinator.markPhoneInvalid({
      accountId: selected.account.id,
      localPhoneId: phone.localPhoneId,
      remotePhoneId: phone.remotePhoneId,
      reason: 'dependency_test_cleanup',
    });
    await pool.markAccountImported(selected.account.id);
    const replacement = await coordinator.replaceBannedAccount(selected.account.id);
    const replay = await coordinator.replaceBannedAccount(selected.account.id);
    const banPool = await coordinator.client.getBanPool();

    const stored = await fs.promises.readFile(file, 'utf8');
    assert.equal(stored.includes('dependency-test@example.invalid'), false);
    assert.equal(stored.includes('15550102020'), false);
    assert.equal(fake.state.claimRequests, 1);
    assert.equal(fake.state.bindingCount, 1);
    assert.equal(fake.state.unavailableUpdates, 1);
    assert.equal(fake.state.unavailable, true);
    assert.equal(fake.state.replacementRequests, 1);
    assert.equal(replacement.replayed, false);
    assert.equal(replacement.sync.added, 1);
    assert.equal(replay.replayed, true);
    assert.equal(fake.state.replacementRequests, 1);
    assert.equal(banPool.pendingReplacementCount, 1);
    assert.equal(JSON.stringify(banPool).includes('not-a-real-password'), false);
  } finally {
    await new Promise((resolve) => fake.server.close(resolve));
    const resolvedRoot = path.resolve(runtimeRoot);
    const resolvedDirectory = path.resolve(directory);
    if (!resolvedDirectory.startsWith(`${resolvedRoot}${path.sep}`)) {
      throw new Error('Dependency test cleanup path escaped the runtime root');
    }
    await fs.promises.rm(resolvedDirectory, { recursive: true, force: true });
  }
  assert.equal(fs.existsSync(directory), false);
}

async function runProductionReadOnlyChecks() {
  const workstation = new WorkstationAutomationClient();
  const inventory = await workstation.getAccountImportLines();
  const banPool = await workstation.getBanPool();
  const eligible = await workstation.getEligiblePhones({ minAgeMinutes: 45, limit: 1 });
  assert.equal(inventory.count, inventory.importLines.length);
  assert.equal(banPool.count, banPool.bannedCount + banPool.bannedReplacedCount);
  assert.equal(banPool.pendingReplacementCount, banPool.bannedCount);

  loadRuntimeEnv();
  const credentialCount = [
    process.env.SUB2API_ADMIN_TOKEN,
    process.env.SUB2API_ADMIN_API_KEY,
    process.env.SUB2API_ADMIN_COOKIE,
  ].filter(Boolean).length;
  assert.equal(credentialCount, 1);
  const accountPage = await new Sub2ApiAdminClient().listAccounts({ page: 1, pageSize: 1 });
  assert.ok(accountPage && typeof accountPage === 'object');

  const window = await new FixedWindowController().findExact();
  assert.equal(window.name, 'us001_codex');
  return {
    inventoryCount: inventory.count,
    banPoolCount: banPool.count,
    pendingReplacementCount: banPool.pendingReplacementCount,
    eligibleCount: eligible.length,
  };
}

async function main() {
  await runIsolatedFakeLifecycle();
  const production = await runProductionReadOnlyChecks();
  console.log(
    `Dependency check passed: isolated fake lifecycle cleaned; production account inventory=${production.inventoryCount}; ` +
    `ban pool=${production.banPoolCount}; pending replacements=${production.pendingReplacementCount}; ` +
    `eligible phones=${production.eligibleCount}; Sub2API and us001_codex reachable.`
  );
}

main().catch((error) => {
  const status = error?.status ? ` (HTTP ${error.status})` : '';
  console.error(`real-dependency-check: ${error?.name || 'Error'}${status}`);
  process.exitCode = 1;
});
