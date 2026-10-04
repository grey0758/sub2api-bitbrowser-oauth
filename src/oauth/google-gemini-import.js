'use strict';

const {
  directSmsRequest,
  extractSmsCode,
  generateTotp,
} = require('./account-import');
const { parseCallbackUrl } = require('../bitbrowser/window-controller');

const GOOGLE_HOSTS = new Set(['accounts.google.com', 'consent.google.com']);

class GoogleLoginError extends Error {
  constructor(message, code = 'login_failed') {
    super(message);
    this.name = 'GoogleLoginError';
    this.code = code;
  }
}

function googleHost(value) {
  try { return new URL(value).hostname.toLowerCase(); } catch { return ''; }
}

function googlePath(value) {
  try { return new URL(value).pathname.toLowerCase(); } catch { return ''; }
}

async function visible(locator) {
  return locator.isVisible().catch(() => false);
}

async function detectGoogleOAuthPage(page) {
  const host = googleHost(page.url());
  const pathname = googlePath(page.url());
  if (!GOOGLE_HOSTS.has(host)) {
    return parseCallbackUrl(page.url(), { allowCodeAssist: true }) ? 'redirected' : 'unexpected_redirect';
  }
  if (/\/challenge\/(?:totp|authenticator)/.test(pathname)) return 'totp';
  if (/\/challenge\//.test(pathname) && !/\/challenge\/pwd/.test(pathname)) return 'unsupported_challenge';
  if (await visible(page.locator('input[type="email"], input#identifierId').first())) return 'email';
  if (await visible(page.locator('input[type="password"]').first())) return 'password';
  if (await visible(page.getByText(/Use another account/i).first())) return 'choose_account';
  if (await visible(page.getByRole('button', { name: /^(Continue|Allow)$/i }).last())) return 'consent';
  return 'waiting';
}

async function assertGoogleLoginHealthy(page) {
  const text = await page.locator('body').innerText().catch(() => '');
  if (
    /wrong password|incorrect password|password (?:is )?incorrect/i.test(text) ||
    /couldn['’]t find your Google Account/i.test(text)
  ) {
    throw new GoogleLoginError('Google rejected the account credentials', 'invalid_credentials');
  }
  if (/couldn['’]t sign you in|this browser or app may not be secure/i.test(text)) {
    throw new GoogleLoginError('Google refused this browser login', 'browser_rejected');
  }
  if (/too many failed attempts|try again later|temporarily locked/i.test(text)) {
    throw new GoogleLoginError('Google login is temporarily rate limited', 'rate_limited');
  }
}

async function freshGoogleTotp(secret, page) {
  const seconds = Math.floor(Date.now() / 1000) % 30;
  if (30 - seconds < 8) await page.waitForTimeout((31 - seconds) * 1000);
  return generateTotp(secret);
}

async function readGoogleTwoFactor(twoFactor, page, {
  requestText = directSmsRequest,
  attempts = 6,
  intervalMs = 5_000,
} = {}) {
  if (twoFactor?.kind === 'totp-secret') return freshGoogleTotp(twoFactor.value, page);
  if (twoFactor?.kind !== 'https-url') {
    throw new GoogleLoginError('Google account has no supported two-factor method', 'two_factor_unavailable');
  }
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const code = extractSmsCode(await requestText(twoFactor.value));
    if (code) return code;
    if (attempt < attempts) await page.waitForTimeout(intervalMs);
  }
  throw new GoogleLoginError('Google two-factor code was unavailable', 'two_factor_unavailable');
}

class GoogleGeminiOAuthImportFlow {
  constructor({ sub2api, browser, account, requestText = directSmsRequest } = {}) {
    if (!sub2api) throw new TypeError('sub2api client is required');
    if (!browser) throw new TypeError('browser controller is required');
    if (!account) throw new TypeError('Google account values are required');
    this.sub2api = sub2api;
    this.browser = browser;
    this.account = account;
    this.requestText = requestText;
  }

  async completeLogin(page, { timeoutMs = 5 * 60_000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    let submittedRoute = '';
    while (Date.now() < deadline) {
      await assertGoogleLoginHealthy(page);
      const route = await detectGoogleOAuthPage(page);
      if (route === 'consent' || route === 'redirected') return { reached: route };
      if (route === 'unexpected_redirect') {
        throw new GoogleLoginError('Google OAuth redirected to an unexpected site', 'unexpected_redirect');
      }
      if (route === 'unsupported_challenge') {
        throw new GoogleLoginError('Google requested an unsupported verification challenge', 'manual_challenge');
      }
      if (submittedRoute && route !== submittedRoute) submittedRoute = '';
      if (submittedRoute === route) {
        await page.waitForTimeout(300);
        continue;
      }
      if (route === 'choose_account') {
        await page.getByText(/Use another account/i).first().click({ timeout: 5_000 });
      } else if (route === 'email') {
        const input = page.locator('input[type="email"], input#identifierId').first();
        await input.fill(this.account.email, { timeout: 5_000 });
        await input.press('Enter', { timeout: 5_000 });
      } else if (route === 'password') {
        const input = page.locator('input[type="password"]').first();
        await input.fill(this.account.password, { timeout: 5_000 });
        await input.press('Enter', { timeout: 5_000 });
      } else if (route === 'totp') {
        const input = page.locator('input[name="totpPin"], input#totpPin, input[autocomplete="one-time-code"]').first();
        await input.waitFor({ state: 'visible', timeout: 10_000 });
        const code = await readGoogleTwoFactor(this.account.twoFactor, page, {
          requestText: this.requestText,
        });
        if (await detectGoogleOAuthPage(page) === 'unsupported_challenge') {
          throw new GoogleLoginError('Google changed the verification challenge', 'manual_challenge');
        }
        await input.fill(code, { timeout: 5_000 });
        await input.press('Enter', { timeout: 5_000 });
      } else {
        await page.waitForTimeout(300);
        continue;
      }
      submittedRoute = route;
      await page.waitForTimeout(800);
    }
    throw new GoogleLoginError('Google OAuth login did not reach consent', 'timeout');
  }

  async run({
    proxyId,
    projectId,
    oauthType = 'google_one',
    tierId,
    incognito = true,
    timeoutMs = 10 * 60_000,
  } = {}) {
    const authorization = await this.sub2api.generateGeminiAuthUrl({
      proxyId,
      projectId,
      oauthType,
      tierId,
    });
    const session = await this.browser.open({
      url: authorization.authUrl,
      incognito,
      waitUntil: 'commit',
      timeoutMs: Math.min(timeoutMs, 90_000),
    });
    try {
      const login = await this.completeLogin(session.page, {
        timeoutMs: Math.min(timeoutMs, 5 * 60_000),
      });
      const callbackPromise = session.waitForCallback({ timeoutMs, allowCodeAssist: true });
      if (login.reached === 'consent') {
        // Google can render more than one bounded consent confirmation. Keep
        // driving only the exact Continue/Allow controls while the page stays
        // on an allowlisted Google host; the callback watcher runs first so a
        // fast navigation cannot lose the one-time code.
        for (let step = 0; step < 4; step += 1) {
          const route = await detectGoogleOAuthPage(session.page);
          if (route === 'redirected') break;
          if (route === 'unsupported_challenge') {
            throw new GoogleLoginError('Google requested an unsupported verification challenge', 'manual_challenge');
          }
          if (route !== 'consent') {
            await session.page.waitForTimeout(500);
            continue;
          }
          const authorize = session.page.getByRole('button', { name: /^(Continue|Allow)$/i }).last();
          await authorize.click({ timeout: 10_000 });
          await session.page.waitForTimeout(800);
        }
      }
      const callback = await callbackPromise;
      if (!callback.state || callback.state !== authorization.state) {
        throw new Error('Gemini OAuth callback state does not match the authorization session');
      }
      const exchangeResult = await this.sub2api.exchangeGeminiCode({
        sessionId: authorization.sessionId,
        code: callback.code,
        state: callback.state,
        proxyId,
        oauthType: authorization.oauthType,
        tierId,
      });
      const imported = await this.sub2api.importGeminiOAuthAccount({
        email: this.account.email,
        exchangeResult,
        proxyId,
      });
      return { login, action: imported.action };
    } finally {
      await this.browser.release({ closeWindow: false });
    }
  }
}

module.exports = {
  GOOGLE_HOSTS,
  GoogleGeminiOAuthImportFlow,
  GoogleLoginError,
  assertGoogleLoginHealthy,
  detectGoogleOAuthPage,
  readGoogleTwoFactor,
};
