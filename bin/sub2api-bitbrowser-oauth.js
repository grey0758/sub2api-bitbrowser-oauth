#!/usr/bin/env node
'use strict';

const { FixedWindowController } = require('../src/bitbrowser/window-controller');
const { Sub2ApiAdminClient, Sub2ApiError } = require('../src/sub2api/admin-client');
const { buildAccountHealthAudit } = require('../src/sub2api/account-health');
const { OAuthFlow } = require('../src/oauth/flow');
const {
  OpenAiAccountImportFlow,
  OpenAiImportConfigError,
  OpenAiLoginError,
  OpenAiRouteError,
  SmsCodeTimeoutError,
  loadOpenAiAccountRuntime,
} = require('../src/oauth/account-import');
const { loadRuntimeEnv } = require('../src/runtime-env');
const {
  WorkstationAutomationClient,
  WorkstationAutomationError,
} = require('../src/workstation/automation-client');
const { WorkstationInventoryImportCoordinator } = require('../src/workstation/inventory-import');
const {
  LocalImportPoolError,
  LocalImportPoolStore,
  parseAccountPoolSource,
} = require('../src/pool/local-import-pool');

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

function parseArgs(argv) {
  const args = { command: argv[0] && !['--help', '-h'].includes(argv[0]) ? argv[0] : 'start' };
  if (argv[0] === '--help' || argv[0] === '-h') args.help = true;
  for (let i = 1; i < argv.length; i += 1) {
    const item = argv[i];
    if (item === '--proxy-id') args.proxyId = argv[++i];
    else if (item === '--timeout-ms') args.timeoutMs = Number(argv[++i]);
    else if (item === '--limit') args.limit = Number(argv[++i]);
    else if (item === '--email') args.email = String(argv[++i] || '').trim();
    else if (item === '--retry-failed') args.retryFailed = true;
    else if (item === '--retry-banned') args.retryBanned = true;
    else if (item === '--replace-banned') args.replaceBanned = true;
    else if (item === '--incognito') args.incognito = true;
    else if (item === '--close-window') args.closeWindow = true;
    else if (item === '--help' || item === '-h') args.help = true;
    else throw new Error(`Unknown argument: ${item}`);
  }
  return args;
}

function usage() {
  return [
    'Usage:',
    '  node bin/sub2api-bitbrowser-oauth.js check',
    '  node bin/sub2api-bitbrowser-oauth.js start [--incognito] [--proxy-id ID]',
    '  node bin/sub2api-bitbrowser-oauth.js run [--incognito] [--proxy-id ID] [--timeout-ms N]',
    '  node bin/sub2api-bitbrowser-oauth.js import-account [--incognito] [--proxy-id ID] [--timeout-ms N]',
    '  node bin/sub2api-bitbrowser-oauth.js probe-accounts [--incognito] [--proxy-id ID] [--timeout-ms N] < accounts.txt',
    '  node bin/sub2api-bitbrowser-oauth.js import-next [--incognito] [--proxy-id ID] [--timeout-ms N]',
    '  node bin/sub2api-bitbrowser-oauth.js inventory-sync-accounts',
    '  node bin/sub2api-bitbrowser-oauth.js inventory-ban-pool-status',
    '  node bin/sub2api-bitbrowser-oauth.js inventory-ban-and-replace --email EMAIL',
    '  node bin/sub2api-bitbrowser-oauth.js inventory-import-next [--incognito] [--proxy-id ID] [--timeout-ms N]',
    '  node bin/sub2api-bitbrowser-oauth.js account-health-audit',
    '  node bin/sub2api-bitbrowser-oauth.js reauthorize-errors [--email EMAIL] [--retry-failed] [--retry-banned] [--replace-banned] [--incognito] [--proxy-id ID] [--timeout-ms N] [--limit N]',
    '  node bin/sub2api-bitbrowser-oauth.js pool-import-phones < phones.txt',
    '  node bin/sub2api-bitbrowser-oauth.js pool-import-accounts < accounts.txt',
    '  node bin/sub2api-bitbrowser-oauth.js pool-status',
    '  node bin/sub2api-bitbrowser-oauth.js pool-reset-phone-cooldowns',
    '  node bin/sub2api-bitbrowser-oauth.js pool-correct-invalid-phone',
    '  node bin/sub2api-bitbrowser-oauth.js pool-enable-resend',
    '',
    'start generates the Sub2API OpenAI OAuth URL, opens it in the exact',
    'BitBrowser window us001_codex (or BITBROWSER_WINDOW_NAME), then disconnects',
    'without closing or deleting the named window. --incognito opens the OAuth',
    'page in an isolated, off-the-record BrowserContext.',
    'run additionally waits for localhost:1455/auth/callback and exchanges it.',
    'import-account performs the reproducible account login flow, including',
    'local TOTP, optional phone/SMS verification, consent, callback-state',
    'validation, exchange, account create/update, and account-list verification.',
    'probe-accounts stops at consent or phone verification and never exchanges',
    'a callback, imports an account, claims a phone, or persists the input rows.',
    '',
    'Credentials are runtime-only: SUB2API_ADMIN_TOKEN, SUB2API_ADMIN_API_KEY,',
    'or SUB2API_ADMIN_COOKIE. import-account additionally requires',
    'OPENAI_ACCOUNT_EMAIL, OPENAI_ACCOUNT_PASSWORD, and OPENAI_TOTP_SECRET.',
    'OPENAI_PHONE and SMS_ACCESS_URL are required only if OpenAI asks for phone',
    'verification. Account runtime values are never read from repository files.',
    'Pool commands keep their payload in a DPAPI-encrypted, Git-ignored local file.',
    'Inventory commands additionally require WORKSTATION_AUTOMATION_TOKEN.',
  ].join('\n');
}

function safeError(error) {
  if (error instanceof OpenAiImportConfigError) return error.message;
  if (error instanceof LocalImportPoolError) return error.message;
  if (error instanceof WorkstationAutomationError) {
    if (error.status === 401) return 'Workstation automation authentication failed';
    if (error.status) {
      const code = error.code ? `; code=${error.code}` : '';
      return `Workstation automation request failed (HTTP ${error.status}${code})`;
    }
    return error.outcomeUnknown
      ? 'Workstation mutation result is unknown; retry the same operation to reuse its idempotency key'
      : 'Workstation automation request failed';
  }
  if (error instanceof OpenAiRouteError) return 'OpenAI authorization returned a route content-type error; restart us001_codex and retry';
  if (error instanceof OpenAiLoginError) {
    if (error.code === 'account_banned') return 'OpenAI account is banned or deactivated; it was not reauthorized';
    return error.code === 'rate_limited'
      ? 'OpenAI login is temporarily rate limited; the account was deferred'
      : 'OpenAI rejected the account login';
  }
  if (error instanceof SmsCodeTimeoutError) {
    return error.resendAttempted
      ? 'SMS verification code was unavailable after two six-attempt rounds and one resend'
      : `SMS verification code was not available after ${error.attempts} direct API attempts`;
  }
  if (error instanceof Sub2ApiError) {
    if (error.status === 401 || error.status === 403) return 'Sub2API administrator authentication failed';
    if (error.status) return `Sub2API administrator request failed (HTTP ${error.status})`;
    return 'Sub2API administrator request failed';
  }
  return error?.message || String(error);
}

async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.help) { console.log(usage()); return; }
  const browser = new FixedWindowController();
  if (args.command === 'check') {
    const window = await browser.findExact();
    console.log(`BitBrowser window matched: ${window.name} (status=${window.status})`);
    return;
  }

  if (args.command === 'pool-import-phones' || args.command === 'pool-import-accounts') {
    const source = await readStdin();
    const pool = new LocalImportPoolStore();
    const result = args.command === 'pool-import-phones'
      ? await pool.importPhones(source)
      : await pool.importAccounts(source);
    console.log(`Local pool updated: added=${result.added}; rejected=${result.rejected}; total=${result.total}.`);
    return;
  }
  if (args.command === 'pool-status') {
    const summary = await new LocalImportPoolStore().summary();
    console.log(
      `Local pool status: phones total=${summary.phones.total}, available=${summary.phones.available}, ` +
      `cooldown=${summary.phones.cooldown}, invalid=${summary.phones.invalid}; ` +
      `accounts total=${summary.accounts.total}, pending=${summary.accounts.pending}, ` +
      `imported=${summary.accounts.imported}.`
    );
    return;
  }
  if (args.command === 'pool-reset-phone-cooldowns') {
    const result = await new LocalImportPoolStore().resetPhoneCooldowns();
    console.log(`Local phone cooldowns reset: reset=${result.reset}; total=${result.total}.`);
    return;
  }
  if (args.command === 'pool-correct-invalid-phone') {
    const result = await new LocalImportPoolStore().correctInvalidPhoneToCooldown({ allowResend: true });
    console.log(`Local invalid phone corrected to cooldown: corrected=${result.corrected}; total=${result.total}.`);
    return;
  }
  if (args.command === 'pool-enable-resend') {
    const result = await new LocalImportPoolStore().setAvailablePhonesAllowResend(true);
    console.log(`Local phone resend policy enabled: updated=${result.updated}; total=${result.total}.`);
    return;
  }

  if (args.command === 'inventory-sync-accounts') {
    const coordinator = new WorkstationInventoryImportCoordinator({
      client: new WorkstationAutomationClient(),
      pool: new LocalImportPoolStore(),
    });
    const result = await coordinator.syncAccounts();
    console.log(
      `Workstation accounts synchronized into the encrypted pool: added=${result.added}; ` +
      `updated=${result.updated}; total=${result.total}.`
    );
    return;
  }
  if (args.command === 'inventory-ban-pool-status') {
    const result = await new WorkstationAutomationClient().getBanPool();
    console.log(
      `Workstation ban pool status: total=${result.count}; banned=${result.bannedCount}; ` +
      `replaced=${result.bannedReplacedCount}; pending-replacement=${result.pendingReplacementCount}.`
    );
    return;
  }
  if (args.command === 'inventory-ban-and-replace') {
    if (!args.email) throw new Error('inventory-ban-and-replace requires --email');
    const pool = new LocalImportPoolStore();
    const account = await pool.findAccountByEmail(args.email);
    if (!account) throw new LocalImportPoolError('Local account entry was not found', { code: 'account_not_found' });
    const coordinator = new WorkstationInventoryImportCoordinator({
      client: new WorkstationAutomationClient(),
      pool,
    });
    const result = await coordinator.replaceBannedAccount(account.id);
    console.log(
      `Workstation banned account replaced and inventory synchronized: ` +
      `replayed=${result.replayed}; added=${result.sync?.added || 0}; ` +
      `updated=${result.sync?.updated || 0}.`
    );
    return;
  }
  loadRuntimeEnv();
  if (args.command === 'account-health-audit') {
    const sub2api = new Sub2ApiAdminClient();
    const pool = new LocalImportPoolStore();
    const accounts = await sub2api.listAllAccounts();
    const snapshot = await pool.load();
    const audit = buildAccountHealthAudit(accounts, snapshot.accounts, snapshot.accountHealthAudit);
    const result = await pool.saveAccountHealthAudit(audit);
    console.log(
      `Account health audit saved in the encrypted pool: total=${result.total}; ` +
      `error=${result.error}; pool-login=${result.poolLogin}.`
    );
    return;
  }
  const flow = new OAuthFlow({ sub2api: new Sub2ApiAdminClient(), browser });
  if (args.command === 'start') {
    const started = await flow.start({ proxyId: args.proxyId, incognito: Boolean(args.incognito) });
    await flow.release({ closeWindow: Boolean(args.closeWindow) });
    const contextLabel = started.session.incognito ? ' in an incognito context' : '';
    console.log(`OpenAI OAuth URL generated and opened in ${started.session.window.name}${contextLabel}.`);
    console.log('The authorization URL is intentionally not printed; complete login in that window.');
    return;
  }
  if (args.command === 'run') {
    await flow.run({ proxyId: args.proxyId, incognito: Boolean(args.incognito), timeoutMs: args.timeoutMs || 10 * 60_000 });
    console.log('OpenAI OAuth callback exchanged through Sub2API administrator API.');
    return;
  }
  if (args.command === 'import-account') {
    const importer = new OpenAiAccountImportFlow({
      sub2api: new Sub2ApiAdminClient(),
      browser,
      account: loadOpenAiAccountRuntime(),
    });
    const completed = await importer.run({
      proxyId: args.proxyId,
      incognito: Boolean(args.incognito),
      timeoutMs: args.timeoutMs || 10 * 60_000,
    });
    const phoneLabel = completed.login.phoneVerification === 'completed'
      ? ' Phone verification was completed.'
      : completed.login.phoneVerification === 'requested'
        ? ' Phone verification was requested.'
        : ' Phone verification was not required.';
    const actionLabel = completed.outcome.action === 'updated' ? 'updated' : 'created';
    console.log(`OpenAI OAuth account ${actionLabel} and verified in Sub2API.${phoneLabel}`);
    return;
  }
  if (args.command === 'probe-accounts') {
    const parsed = parseAccountPoolSource(await readStdin());
    if (parsed.issues.length > 0 || parsed.accounts.length === 0 || parsed.accounts.length > 100) {
      throw new OpenAiImportConfigError('Probe input must contain 1 to 100 valid account rows');
    }
    const sub2api = new Sub2ApiAdminClient();
    const results = {
      checked: 0,
      loginValid: 0,
      phoneRequired: 0,
      banned: 0,
      invalidCredentials: 0,
      rateLimited: 0,
      failed: 0,
    };
    for (const account of parsed.accounts) {
      const importer = new OpenAiAccountImportFlow({
        sub2api,
        browser,
        account: {
          email: account.email,
          password: account.password,
          totpSecret: account.totpSecret,
          phone: '',
          smsAccessUrl: '',
          allowSmsResend: false,
        },
      });
      results.checked += 1;
      let status;
      try {
        const probe = await importer.probe({
          proxyId: args.proxyId,
          incognito: Boolean(args.incognito),
          timeoutMs: args.timeoutMs || 5 * 60_000,
        });
        if (probe.login.reached === 'phone_verification') {
          status = 'login_valid_phone_required';
          results.phoneRequired += 1;
        } else {
          status = 'login_valid';
          results.loginValid += 1;
        }
      } catch (error) {
        if (error instanceof OpenAiLoginError && error.code === 'account_banned') {
          status = 'account_banned';
          results.banned += 1;
        } else if (error instanceof OpenAiLoginError && error.code === 'invalid_credentials') {
          status = 'invalid_credentials';
          results.invalidCredentials += 1;
        } else if (error instanceof OpenAiLoginError && error.code === 'rate_limited') {
          status = 'rate_limited';
          results.rateLimited += 1;
        } else {
          status = 'check_failed';
          results.failed += 1;
        }
      }
      console.log(`${account.email}\t${status}`);
      if (status === 'rate_limited') break;
    }
    console.log(
      `Account login probe finished: checked=${results.checked}; login-valid=${results.loginValid}; ` +
      `phone-required=${results.phoneRequired}; banned=${results.banned}; ` +
      `invalid-credentials=${results.invalidCredentials}; rate-limited=${results.rateLimited}; ` +
      `failed=${results.failed}.`
    );
    return;
  }
  if (args.command === 'import-next') {
    const pool = new LocalImportPoolStore();
    const selected = await pool.beginNextAttempt();
    let phoneRecorded = false;
    const importer = new OpenAiAccountImportFlow({
      sub2api: new Sub2ApiAdminClient(),
      browser,
      account: {
        email: selected.account.email,
        password: selected.account.password,
        totpSecret: selected.account.totpSecret,
        phone: selected.phone.phone,
        smsAccessUrl: selected.phone.smsAccessUrl,
        allowSmsResend: selected.phone.allowResend,
      },
      onPhoneSubmitted: async () => {
        if (phoneRecorded) return;
        phoneRecorded = true;
        await pool.markPhoneUsed(selected.phone.id);
      },
      phoneStatusApi: {
        markInvalid: async ({ reason }) => pool.markPhoneInvalid(selected.phone.id, reason),
      },
    });
    try {
      const completed = await importer.run({
        proxyId: args.proxyId,
        incognito: Boolean(args.incognito),
        timeoutMs: args.timeoutMs || 10 * 60_000,
      });
      await pool.markAccountImported(selected.account.id);
      const phoneLabel = completed.login.phoneVerification === 'completed'
        ? ' Phone verification was completed.'
        : ' Phone verification was not required.';
      console.log(`Next local account imported and verified in Sub2API.${phoneLabel}`);
    } catch (error) {
      const outcome = error instanceof SmsCodeTimeoutError
        ? 'sms_timeout'
        : error instanceof OpenAiLoginError
          ? error.code
        : error instanceof OpenAiRouteError
          ? 'route_error'
          : error instanceof Sub2ApiError
            ? 'sub2api_error'
            : 'failed';
      await pool.markAccountPending(selected.account.id, outcome, {
        retryAfterMs: error instanceof OpenAiLoginError && error.code === 'rate_limited' ? 15 * 60_000 : 0,
      }).catch(() => {});
      throw error;
    }
    return;
  }
  if (args.command === 'inventory-import-next') {
    const pool = new LocalImportPoolStore();
    const coordinator = new WorkstationInventoryImportCoordinator({
      client: new WorkstationAutomationClient(),
      pool,
    });
    const selected = await coordinator.beginNextAccountAttempt();
    let preparedPhone = null;
    let phoneRecorded = false;
    const importer = new OpenAiAccountImportFlow({
      sub2api: new Sub2ApiAdminClient(),
      browser,
      account: {
        email: selected.account.email,
        password: selected.account.password,
        totpSecret: selected.account.totpSecret,
        phone: '',
        smsAccessUrl: '',
        allowSmsResend: false,
      },
      preparePhone: async () => {
        if (!preparedPhone) preparedPhone = await coordinator.preparePhone(selected.account.id);
        return preparedPhone;
      },
      onPhoneSubmitted: async () => {
        if (phoneRecorded || !preparedPhone) return;
        phoneRecorded = true;
        await coordinator.markPhoneSubmitted(preparedPhone.localPhoneId);
      },
      phoneStatusApi: {
        markInvalid: async ({ reason }) => {
          if (!preparedPhone) return;
          await coordinator.markPhoneInvalid({
            accountId: selected.account.id,
            localPhoneId: preparedPhone.localPhoneId,
            remotePhoneId: preparedPhone.remotePhoneId,
            reason,
          });
        },
      },
    });
    try {
      const completed = await importer.run({
        proxyId: args.proxyId,
        incognito: Boolean(args.incognito),
        timeoutMs: args.timeoutMs || 10 * 60_000,
      });
      await pool.markAccountImported(selected.account.id);
      const phoneLabel = completed.login.phoneVerification === 'completed'
        ? ' Phone verification was completed.'
        : ' Phone verification was not required.';
      console.log(`Next workstation account imported and verified in Sub2API.${phoneLabel}`);
    } catch (error) {
      const outcome = error instanceof SmsCodeTimeoutError
        ? 'sms_timeout'
        : error instanceof OpenAiLoginError
          ? error.code
        : error instanceof OpenAiRouteError
          ? 'route_error'
          : error instanceof Sub2ApiError
            ? 'sub2api_error'
            : error instanceof WorkstationAutomationError
              ? 'workstation_api_error'
              : 'failed';
      await pool.markAccountPending(selected.account.id, outcome, {
        retryAfterMs: error instanceof OpenAiLoginError && error.code === 'rate_limited' ? 15 * 60_000 : 0,
      }).catch(() => {});
      throw error;
    }
    return;
  }
  if (args.command === 'reauthorize-errors') {
    const pool = new LocalImportPoolStore();
    const snapshot = await pool.load();
    const audit = snapshot.accountHealthAudit?.entries || [];
    const poolByEmail = new Map(snapshot.accounts.map((item) => [item.email.trim().toLowerCase(), item]));
    const limit = args.limit === undefined ? Number.POSITIVE_INFINITY : Math.max(1, Math.min(100, Number(args.limit) || 1));
    const requestedEmail = String(args.email || '').trim().toLowerCase();
    const retryableOutcomes = args.retryFailed
      ? new Set(['pending', 'failed', 'route_error', 'sub2api_error'])
      : new Set(['pending']);
    if (args.retryBanned) retryableOutcomes.add('account_banned');
    const targets = audit.filter((entry) => (
      entry.status === 'error' &&
      entry.category !== 'provider_banned_or_disabled' &&
      entry.outcome !== 'account_sold' &&
      entry.hasPoolLogin &&
      (requestedEmail ? entry.email.trim().toLowerCase() === requestedEmail : retryableOutcomes.has(entry.outcome)) &&
      entry.outcome !== 'reauthorized' &&
      poolByEmail.has(entry.email.trim().toLowerCase())
    )).slice(0, limit);
    if (targets.length === 0) {
      console.log('No pending error accounts with local login material are available for reauthorization.');
      return;
    }
    const sub2api = new Sub2ApiAdminClient();
    const browserController = browser;
    const results = {
      reauthorized: 0,
      banned: 0,
      replaced: 0,
      replacementFailed: 0,
      rateLimited: 0,
      failed: 0,
    };
    const replacementCoordinator = args.replaceBanned
      ? new WorkstationInventoryImportCoordinator({
        client: new WorkstationAutomationClient(),
        pool,
      })
      : null;
    let attempted = 0;
    for (const target of targets) {
      attempted += 1;
      const queued = poolByEmail.get(target.email.trim().toLowerCase());
      const importer = new OpenAiAccountImportFlow({
        sub2api,
        browser: browserController,
        account: {
          email: queued.email,
          password: queued.password,
          totpSecret: queued.totpSecret,
          phone: '',
          smsAccessUrl: '',
          allowSmsResend: false,
        },
      });
      try {
        await importer.run({
          proxyId: args.proxyId,
          incognito: Boolean(args.incognito),
          timeoutMs: args.timeoutMs || 10 * 60_000,
        });
        await pool.updateAccountHealthOutcome(target.accountId, 'reauthorized');
        results.reauthorized += 1;
      } catch (error) {
        const outcome = error instanceof OpenAiLoginError
          ? error.code
          : error instanceof SmsCodeTimeoutError
            ? 'sms_timeout'
            : error instanceof OpenAiRouteError
              ? 'route_error'
              : error instanceof Sub2ApiError
                ? 'sub2api_error'
                : 'failed';
        await pool.updateAccountHealthOutcome(target.accountId, outcome, { code: error.code }).catch(() => {});
        if (outcome === 'account_banned') {
          results.banned += 1;
          if (replacementCoordinator) {
            try {
              await replacementCoordinator.replaceBannedAccount(queued.id);
              await pool.updateAccountHealthOutcome(target.accountId, 'account_banned_replaced');
              results.replaced += 1;
            } catch (replacementError) {
              if (
                replacementError instanceof WorkstationAutomationError &&
                !replacementError.outcomeUnknown &&
                !replacementError.retryable
              ) {
                results.replacementFailed += 1;
              } else {
                throw replacementError;
              }
            }
          }
        }
        else if (outcome === 'rate_limited') results.rateLimited += 1;
        else results.failed += 1;
        if (outcome === 'rate_limited') break;
      }
    }
    console.log(
      `Error-account reauthorization batch finished: attempted=${attempted}; ` +
      `processed=${attempted}; ` +
      `reauthorized=${results.reauthorized}; banned=${results.banned}; replaced=${results.replaced}; ` +
      `replacement-failed=${results.replacementFailed}; ` +
      `rate-limited=${results.rateLimited}; failed=${results.failed}.`
    );
    return;
  }
  throw new Error(`Unknown command: ${args.command}\n\n${usage()}`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`sub2api-bitbrowser-oauth: ${safeError(error)}`);
    process.exitCode = 1;
  });
}

module.exports = { main, parseArgs, safeError, usage };
