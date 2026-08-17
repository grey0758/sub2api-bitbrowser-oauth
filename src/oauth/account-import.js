'use strict';

const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const https = require('node:https');
const path = require('node:path');
const { OAuthFlow } = require('./flow');

const DEFAULT_SMS_ATTEMPTS = 6;
const DEFAULT_SMS_INTERVAL_MS = 10_000;
const DEFAULT_SMS_TIMEOUT_MS = 7_000;
const SMS_ROUND_MIN_DURATION_MS = 60_000;
const SMS_ROUNDS = 2;
const PHONE_CODE_INPUT_SELECTOR = [
  'input[autocomplete="one-time-code"]',
  'input[name="code"]',
  'input[id="code"]',
  'input[placeholder="Code" i]',
  'input[inputmode="numeric"]',
].join(', ');

class OpenAiImportConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'OpenAiImportConfigError';
  }
}

class OpenAiRouteError extends Error {
  constructor() {
    super('OpenAI authorization route returned an invalid content type');
    this.name = 'OpenAiRouteError';
  }
}

class OpenAiLoginError extends Error {
  constructor(message, code = 'login_failed') {
    super(message);
    this.name = 'OpenAiLoginError';
    this.code = code;
  }
}

class SmsCodeTimeoutError extends Error {
  constructor(attempts, { resendAttempted = false } = {}) {
    super(`SMS verification code was not available after ${attempts} attempts`);
    this.name = 'SmsCodeTimeoutError';
    this.attempts = attempts;
    this.resendAttempted = resendAttempted;
  }
}

/**
 * Reserved integration point for the future phone-number provider API.
 * The default implementation deliberately performs no network request.
 */
class PhoneStatusApi {
  async markInvalid(_details) {
    return { submitted: false };
  }
}

function requiredRuntimeValue(env, name) {
  const value = String(env?.[name] || '').trim();
  if (!value) throw new OpenAiImportConfigError(`Missing runtime value: ${name}`);
  return value;
}

function loadOpenAiAccountRuntime(env = process.env) {
  return {
    email: requiredRuntimeValue(env, 'OPENAI_ACCOUNT_EMAIL'),
    password: requiredRuntimeValue(env, 'OPENAI_ACCOUNT_PASSWORD'),
    totpSecret: requiredRuntimeValue(env, 'OPENAI_TOTP_SECRET'),
    phone: String(env.OPENAI_PHONE || '').trim(),
    smsAccessUrl: String(env.SMS_ACCESS_URL || '').trim(),
  };
}

function normalizeUsPhoneNumber(value) {
  const digits = String(value || '').replace(/\D/g, '');
  const local = digits.length === 11 && digits.startsWith('1') ? digits.slice(1) : digits;
  if (!/^\d{10}$/.test(local)) {
    throw new OpenAiImportConfigError('OPENAI_PHONE must contain a 10-digit US number, optionally prefixed by 1');
  }
  return local;
}

function normalizeTotpSecret(secret) {
  return String(secret || '').toUpperCase().replace(/\s+/g, '').replace(/-/g, '').replace(/=+$/, '');
}

function base32ToBuffer(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const normalized = normalizeTotpSecret(secret);
  if (!normalized || /[^A-Z2-7]/.test(normalized)) throw new OpenAiImportConfigError('OPENAI_TOTP_SECRET is not valid Base32');
  let value = 0;
  let bits = 0;
  const bytes = [];
  for (const character of normalized) {
    value = (value << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
      value &= (1 << bits) - 1;
    }
  }
  return Buffer.from(bytes);
}

function generateTotp(secret, timeMs = Date.now(), digits = 6, periodSeconds = 30) {
  const counter = Math.floor(timeMs / 1000 / periodSeconds);
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBytes.writeUInt32BE(counter >>> 0, 4);
  const digest = crypto.createHmac('sha1', base32ToBuffer(secret)).update(counterBytes).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binaryCode = (((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) >>> 0;
  return String(binaryCode % (10 ** digits)).padStart(digits, '0');
}

async function freshTotp(secret, { now = () => Date.now(), sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) } = {}) {
  const seconds = Math.floor(now() / 1000) % 30;
  if (30 - seconds < 6) await sleep((31 - seconds) * 1000);
  return generateTotp(secret, now());
}

function extractSmsCode(value) {
  return String(value || '').match(/\b\d{6}\b/)?.[0] || '';
}

function windowsSmsRequest(url, { timeoutMs = DEFAULT_SMS_TIMEOUT_MS, execFileImpl = execFile } = {}) {
  const systemRoot = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows';
  const executable = path.win32.join(
    systemRoot,
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe'
  );
  const command = [
    "$ErrorActionPreference = 'Stop'",
    '$timeoutSeconds = [Math]::Max(1, [int]$env:SUB2API_SMS_TIMEOUT_SECONDS)',
    '$response = Invoke-WebRequest -UseBasicParsing -Uri $env:SUB2API_SMS_ACCESS_URL -TimeoutSec $timeoutSeconds',
    '[Console]::Out.Write([string]$response.Content)',
  ].join('; ');
  const childEnv = {
    APPDATA: process.env.APPDATA || '',
    LOCALAPPDATA: process.env.LOCALAPPDATA || '',
    SystemRoot: systemRoot,
    WINDIR: systemRoot,
    TEMP: process.env.TEMP || '',
    TMP: process.env.TMP || '',
    USERPROFILE: process.env.USERPROFILE || '',
    SUB2API_SMS_ACCESS_URL: url,
    SUB2API_SMS_TIMEOUT_SECONDS: String(Math.ceil(timeoutMs / 1000)),
  };

  return new Promise((resolve) => {
    execFileImpl(
      executable,
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command],
      {
        encoding: 'utf8',
        env: childEnv,
        maxBuffer: 64 * 1024,
        timeout: timeoutMs + 2_000,
        windowsHide: true,
      },
      (error, stdout) => resolve(error ? '' : String(stdout || ''))
    );
  });
}

function nodeHttpsSmsRequest(parsed, { timeoutMs, requestImpl }) {
  return new Promise((resolve, reject) => {
    const request = requestImpl(parsed, {
      method: 'GET',
      timeout: timeoutMs,
      headers: { accept: '*/*', 'user-agent': 'sub2api-bitbrowser-oauth/0.1' },
    }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => resolve(response.statusCode >= 200 && response.statusCode < 300 ? body : ''));
      response.on('error', reject);
    });
    request.on('timeout', () => request.destroy(new Error('SMS request timed out')));
    request.on('error', reject);
    request.end();
  });
}

async function directSmsRequest(url, {
  timeoutMs = DEFAULT_SMS_TIMEOUT_MS,
  requestImpl = https.request,
  platform = process.platform,
  windowsRequest = windowsSmsRequest,
} = {}) {
  let parsed;
  try { parsed = new URL(url); } catch { throw new OpenAiImportConfigError('SMS_ACCESS_URL must be a valid HTTPS URL'); }
  if (parsed.protocol !== 'https:') throw new OpenAiImportConfigError('SMS_ACCESS_URL must use HTTPS');
  try {
    return await nodeHttpsSmsRequest(parsed, { timeoutMs, requestImpl });
  } catch {
    if (platform !== 'win32') return '';
    try {
      return await windowsRequest(parsed.href, { timeoutMs });
    } catch {
      return '';
    }
  }
}

async function pollSmsCode({
  url,
  attempts = DEFAULT_SMS_ATTEMPTS,
  intervalMs = DEFAULT_SMS_INTERVAL_MS,
  timeoutMs = DEFAULT_SMS_TIMEOUT_MS,
  requestText = directSmsRequest,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
  if (!url) throw new OpenAiImportConfigError('SMS_ACCESS_URL is required when phone verification is requested');
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const code = extractSmsCode(await requestText(url, { timeoutMs }));
    if (code) return { code, attempt };
    if (attempt < attempts) await sleep(intervalMs);
  }
  throw new SmsCodeTimeoutError(attempts);
}

async function waitForSmsCodeWithResend({
  url,
  phone,
  smsPoller = pollSmsCode,
  resend,
  phoneStatusApi = new PhoneStatusApi(),
  allowResend = true,
  attemptsPerRound = DEFAULT_SMS_ATTEMPTS,
  roundDurationMs = SMS_ROUND_MIN_DURATION_MS,
  now = () => Date.now(),
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
  if (allowResend && typeof resend !== 'function') throw new TypeError('resend callback is required');
  if (!phoneStatusApi || typeof phoneStatusApi.markInvalid !== 'function') {
    throw new TypeError('phoneStatusApi.markInvalid is required');
  }

  const pollRound = async () => {
    const startedAt = now();
    try {
      return await smsPoller({ url, attempts: attemptsPerRound });
    } catch (error) {
      if (!(error instanceof SmsCodeTimeoutError)) throw error;
      const remainingMs = roundDurationMs - (now() - startedAt);
      if (remainingMs > 0) await sleep(remainingMs);
      return null;
    }
  };

  const firstRound = await pollRound();
  if (firstRound) return { ...firstRound, round: 1, resent: false };

  if (allowResend) await resend();
  const secondRound = await pollRound();
  if (secondRound) return { ...secondRound, round: 2, resent: allowResend };

  const normalizedPhone = phone ? normalizeUsPhoneNumber(phone) : '';
  await phoneStatusApi.markInvalid({
    phone: normalizedPhone,
    reason: allowResend ? 'sms_code_unavailable_after_resend' : 'sms_code_unavailable_without_resend',
    attempts: attemptsPerRound * SMS_ROUNDS,
  });
  throw new SmsCodeTimeoutError(attemptsPerRound * SMS_ROUNDS, { resendAttempted: allowResend });
}

function classifyExchangeResult(value) {
  if (value === null || value === undefined) return { accepted: false, reason: 'empty_result' };
  if (typeof value !== 'object') return { accepted: true, resultType: typeof value };
  for (const key of ['success', 'ok', 'imported', 'created']) {
    if (value[key] === false) return { accepted: false, reason: `${key}_false` };
  }
  const status = ['status', 'result', 'action'].map((key) => value[key]).find((item) => typeof item === 'string' && item.trim());
  return { accepted: true, resultType: 'object', status: status ? status.trim().slice(0, 64) : '' };
}

function detectOpenAiAuthRoute(value) {
  const url = String(value || '');
  if (/choose-an-account/.test(url)) return 'choose_account';
  if (/log-in-or-create-account/.test(url)) return 'email';
  if (/\/log-in\/password/.test(url)) return 'password';
  if (/mfa-challenge/.test(url)) return 'mfa';
  if (/add-phone/.test(url)) return 'add_phone';
  if (/phone-verification/.test(url)) return 'phone_verification';
  if (/consent/.test(url)) return 'consent';
  return 'unknown';
}

async function detectOpenAiAuthPage(page) {
  const route = detectOpenAiAuthRoute(page.url());
  if (route !== 'unknown') return route;

  const visible = async (locator) => locator.isVisible().catch(() => false);
  if (await visible(page.getByText('Log in to another account', { exact: true }))) return 'choose_account';
  if (await visible(page.getByPlaceholder('Email address'))) return 'email';
  if (await visible(page.locator('input[type="password"]'))) return 'password';
  if (await visible(page.locator('input[autocomplete="one-time-code"]'))) return 'mfa';
  if (await visible(page.locator('input[type="tel"]'))) return 'add_phone';
  if (await visible(page.locator(PHONE_CODE_INPUT_SELECTOR).first())) return 'phone_verification';
  if (await visible(page.getByRole('button', { name: 'Continue', exact: true }))) return 'consent';
  return 'unknown';
}

function isOpenAiRateLimitText(value) {
  const text = String(value || '');
  // The Codex login footer says "Your ChatGPT rate limits apply to Codex" on
  // every normal account-selection page. Match error wording only: this
  // avoids treating that informational footer as an active rate limit.
  return /too many (?:requests|attempts)|try again later|\brate[- ]limit(?:ed|ing)?\b/i.test(text);
}

function isOpenAiRouteErrorText(value) {
  const text = String(value || '');
  return /Oops,?\s*an error occurred!?[\s\S]{0,160}Route Error\s*\(\s*500\s+Internal Server Error\s*\)/i.test(text)
    || /Route Error\s*\(\s*500\s+Internal Server Error\s*\)/i.test(text);
}

async function assertNoRouteError(page) {
  const text = await page.locator('body').innerText().catch(() => '');
  if (/Invalid content type:\s*text\/html/i.test(text) || isOpenAiRouteErrorText(text)) throw new OpenAiRouteError();
  if (
    /error_code\s*:\s*account_deactivated/i.test(text) ||
    /(?:account|user|organization).{0,48}(?:banned|suspended|deactivated|disabled|terminated)/i.test(text) ||
    /(?:banned|suspended|deactivated|disabled|terminated).{0,48}(?:account|user|organization)/i.test(text)
  ) {
    throw new OpenAiLoginError('OpenAI account is banned or deactivated', 'account_banned');
  }
  if (isOpenAiRateLimitText(text)) {
    throw new OpenAiLoginError('OpenAI login is temporarily rate limited', 'rate_limited');
  }
  if (/incorrect password|wrong password|invalid password|password is incorrect/i.test(text)) {
    throw new OpenAiLoginError('OpenAI rejected the account credentials', 'invalid_credentials');
  }
}

async function clickResendTextMessage(page, { timeoutMs = 10_000 } = {}) {
  const resend = page.getByText(/Resend text message/i).first();
  await resend.waitFor({ state: 'visible', timeout: timeoutMs });
  await resend.click({ timeout: timeoutMs });
}

class OpenAiAccountImportFlow {
  constructor({
    sub2api,
    browser,
    account,
    smsPoller = pollSmsCode,
    phoneStatusApi = new PhoneStatusApi(),
    onPhoneSubmitted = async () => {},
    preparePhone = async () => null,
  } = {}) {
    if (!sub2api) throw new TypeError('sub2api client is required');
    if (!browser) throw new TypeError('browser controller is required');
    if (!account) throw new TypeError('runtime account values are required');
    this.sub2api = sub2api;
    this.browser = browser;
    this.account = account;
    this.smsPoller = smsPoller;
    this.phoneStatusApi = phoneStatusApi;
    this.onPhoneSubmitted = onPhoneSubmitted;
    this.preparePhone = preparePhone;
  }

  async completeLogin(page, { timeoutMs = 5 * 60_000, stopBeforePhoneVerification = false } = {}) {
    const deadline = Date.now() + timeoutMs;
    let nextActionAt = 0;
    let submittedRoute = '';
    let phoneVerification = 'not_required';
    while (Date.now() < deadline) {
      await assertNoRouteError(page);
      const route = await detectOpenAiAuthPage(page);
      if (route === 'consent') {
        return stopBeforePhoneVerification
          ? { phoneVerification, reached: 'consent' }
          : { phoneVerification };
      }
      if (stopBeforePhoneVerification && ['add_phone', 'phone_verification'].includes(route)) {
        return { phoneVerification: 'required', reached: 'phone_verification' };
      }
      if (submittedRoute && route !== submittedRoute) submittedRoute = '';
      if (submittedRoute === route) {
        await page.waitForTimeout(300);
        continue;
      }
      if (Date.now() < nextActionAt) {
        await page.waitForTimeout(Math.min(250, nextActionAt - Date.now()));
        continue;
      }
      if (route === 'choose_account') {
        const another = page.getByText('Log in to another account', { exact: true });
        await another.waitFor({ state: 'visible', timeout: Math.max(1, deadline - Date.now()) });
        await another.click();
        submittedRoute = route;
        nextActionAt = Date.now() + 1_000;
        continue;
      }
      if (route === 'email') {
        const email = page.getByPlaceholder('Email address');
        await email.waitFor({ state: 'visible', timeout: Math.max(1, deadline - Date.now()) });
        if (!(await email.isEditable().catch(() => false))) {
          nextActionAt = Date.now() + 500;
          continue;
        }
        try {
          await email.fill(this.account.email, { timeout: 2_000 });
          await email.press('Enter', { timeout: 2_000 });
        } catch {
          nextActionAt = Date.now() + 500;
          continue;
        }
        submittedRoute = route;
        nextActionAt = Date.now() + 1_000;
        continue;
      }
      if (route === 'password') {
        const password = page.locator('input[type="password"]');
        await password.waitFor({ state: 'visible', timeout: Math.max(1, deadline - Date.now()) });
        if (!(await password.isEditable().catch(() => false))) {
          nextActionAt = Date.now() + 500;
          continue;
        }
        try {
          await password.fill(this.account.password, { timeout: 2_000 });
          await page.waitForTimeout(300);
          await page.getByRole('button', { name: 'Continue', exact: true }).click({ timeout: 2_000 });
        } catch {
          nextActionAt = Date.now() + 500;
          continue;
        }
        submittedRoute = route;
        nextActionAt = Date.now() + 1_000;
        continue;
      }
      if (route === 'mfa') {
        const input = page.locator('input[autocomplete="one-time-code"]');
        await input.waitFor({ state: 'visible', timeout: Math.max(1, deadline - Date.now()) });
        if (!(await input.isEditable().catch(() => false))) {
          nextActionAt = Date.now() + 500;
          continue;
        }
        try {
          await input.fill(await freshTotp(this.account.totpSecret), { timeout: 2_000 });
          await page.waitForTimeout(900);
          await page.locator('button[type="submit"]').first().click({ timeout: 2_000 });
        } catch {
          nextActionAt = Date.now() + 500;
          continue;
        }
        submittedRoute = route;
        nextActionAt = Date.now() + 1_000;
        continue;
      }
      if (route === 'add_phone') {
        const input = page.locator('input[type="tel"]');
        await input.waitFor({ state: 'visible', timeout: Math.max(1, deadline - Date.now()) });
        if (!(await input.isEditable().catch(() => false))) {
          nextActionAt = Date.now() + 500;
          continue;
        }
        const preparedPhone = await this.preparePhone();
        if (preparedPhone) {
          this.account.phone = preparedPhone.phone;
          this.account.smsAccessUrl = preparedPhone.smsAccessUrl;
          this.account.allowSmsResend = preparedPhone.allowSmsResend;
        }
        const phone = normalizeUsPhoneNumber(this.account.phone);
        try {
          await input.fill(phone, { timeout: 2_000 });
          await page.getByRole('button', { name: 'Continue', exact: true }).click({ timeout: 2_000 });
        } catch {
          nextActionAt = Date.now() + 500;
          continue;
        }
        await this.onPhoneSubmitted({ phone });
        submittedRoute = route;
        phoneVerification = 'requested';
        nextActionAt = Date.now() + 1_000;
        continue;
      }
      if (route === 'phone_verification') {
        const sms = await waitForSmsCodeWithResend({
          url: this.account.smsAccessUrl,
          phone: this.account.phone,
          smsPoller: this.smsPoller,
          resend: () => clickResendTextMessage(page),
          phoneStatusApi: this.phoneStatusApi,
          allowResend: this.account.allowSmsResend !== false,
          sleep: (ms) => page.waitForTimeout(ms),
        });
        const routeAfterPolling = await detectOpenAiAuthPage(page);
        if (routeAfterPolling === 'consent') {
          phoneVerification = 'completed';
          continue;
        }
        if (routeAfterPolling !== 'phone_verification') {
          nextActionAt = Date.now() + 500;
          continue;
        }
        const input = page.locator(PHONE_CODE_INPUT_SELECTOR).first();
        try {
          await input.waitFor({
            state: 'visible',
            timeout: Math.max(1, Math.min(10_000, deadline - Date.now())),
          });
        } catch (error) {
          if (await detectOpenAiAuthPage(page) !== 'phone_verification') continue;
          throw error;
        }
        if (!(await input.isEditable().catch(() => false))) {
          nextActionAt = Date.now() + 500;
          continue;
        }
        try {
          await input.fill(sms.code, { timeout: 2_000 });
          await page.waitForTimeout(900);
          await page.locator('button[type="submit"]').first().click({ timeout: 2_000 });
        } catch {
          nextActionAt = Date.now() + 500;
          continue;
        }
        submittedRoute = route;
        phoneVerification = 'completed';
        nextActionAt = Date.now() + 1_000;
        continue;
      }
      await page.waitForTimeout(300);
    }
    throw new Error('OpenAI authorization consent page was not reached');
  }

  async probe({ proxyId, incognito = true, timeoutMs = 5 * 60_000, maxRouteRetries = 3 } = {}) {
    const retries = Math.max(0, Math.min(5, Number(maxRouteRetries) || 0));
    for (let routeAttempt = 0; routeAttempt <= retries; routeAttempt += 1) {
      const authorization = await this.sub2api.generateOpenAiAuthUrl({ proxyId });
      const session = await this.browser.open({ url: authorization.authUrl, incognito, waitUntil: 'commit' });
      try {
        const login = await this.completeLogin(session.page, {
          timeoutMs: Math.min(timeoutMs, 5 * 60_000),
          stopBeforePhoneVerification: true,
        });
        return { login, routeAttempts: routeAttempt };
      } catch (error) {
        if (!(error instanceof OpenAiRouteError) || routeAttempt >= retries) throw error;
      } finally {
        await this.browser.release({ closeWindow: false });
      }
    }
    throw new OpenAiRouteError();
  }

  async run({ proxyId, incognito = true, timeoutMs = 10 * 60_000, maxRouteRetries = 3 } = {}) {
    const oauth = new OAuthFlow({ sub2api: this.sub2api, browser: this.browser });
    const retries = Math.max(0, Math.min(5, Number(maxRouteRetries) || 0));
    for (let routeAttempt = 0; routeAttempt <= retries; routeAttempt += 1) {
      const authorization = await this.sub2api.generateOpenAiAuthUrl({ proxyId });
      const session = await this.browser.open({ url: authorization.authUrl, incognito, waitUntil: 'commit' });
      try {
        const login = await this.completeLogin(session.page, { timeoutMs: Math.min(timeoutMs, 5 * 60_000) });
        const callbackPromise = session.waitForCallback({ timeoutMs });
        await session.page.getByRole('button', { name: 'Continue', exact: true }).click();
        const callback = await callbackPromise;
        if (!callback.state || callback.state !== authorization.state) {
          throw new Error('OAuth callback state does not match the generated authorization session');
        }
        const result = await oauth.exchange({
          authorization,
          input: `http://localhost:1455/auth/callback?code=${encodeURIComponent(callback.code)}&state=${encodeURIComponent(callback.state)}`,
          proxyId,
        });
        const imported = await this.sub2api.importOpenAiOAuthAccount({
          email: this.account.email,
          exchangeResult: result,
          proxyId,
        });
        const outcome = { accepted: true, action: imported.action };
        return { login, outcome, session, routeAttempts: routeAttempt };
      } catch (error) {
        if (!(error instanceof OpenAiRouteError) || routeAttempt >= retries) throw error;
      } finally {
        await this.browser.release({ closeWindow: false });
      }
    }
    throw new OpenAiRouteError();
  }
}

module.exports = {
  DEFAULT_SMS_ATTEMPTS,
  DEFAULT_SMS_INTERVAL_MS,
  SMS_ROUND_MIN_DURATION_MS,
  SMS_ROUNDS,
  OpenAiAccountImportFlow,
  OpenAiImportConfigError,
  OpenAiLoginError,
  OpenAiRouteError,
  PHONE_CODE_INPUT_SELECTOR,
  PhoneStatusApi,
  SmsCodeTimeoutError,
  classifyExchangeResult,
  clickResendTextMessage,
  detectOpenAiAuthRoute,
  isOpenAiRouteErrorText,
  isOpenAiRateLimitText,
  directSmsRequest,
  extractSmsCode,
  generateTotp,
  loadOpenAiAccountRuntime,
  normalizeTotpSecret,
  normalizeUsPhoneNumber,
  pollSmsCode,
  waitForSmsCodeWithResend,
  windowsSmsRequest,
};
