'use strict';

const {
  directSmsRequest,
  extractSmsCode,
  generateTotp,
} = require('./account-import');
const { parseCallbackUrl } = require('../bitbrowser/window-controller');

const GOOGLE_HOSTS = new Set(['accounts.google.com', 'consent.google.com']);
const GOOGLE_USE_ANOTHER_ACCOUNT = /^(?:Use another account|使用其他账号|使用其他帐号|使用其他帳戶|使用其他帳號|換用其他帳戶|Dùng một tài khoản khác|Sử dụng tài khoản khác)$/i;
const GOOGLE_TRY_ANOTHER_WAY = /^(?:Try another way|Choose another option|换一种方式|換一種方式|尝试其他方式|嘗試其他方式|試試其他方式|Thử cách khác)$/i;
const GOOGLE_AUTHENTICATOR_METHOD = /(?:Google Authenticator|Authenticator app|verification code from (?:the )?Google Authenticator|Google 身份验证器|Google 身分驗證器|ứng dụng Google Authenticator)/i;
const GOOGLE_CONSENT_ACTION = /^(?:Continue|Allow|Approve|Agree|继续|繼續|允许|允許|同意|Tiếp tục|Cho phép)$/i;
const GOOGLE_MANUAL_CHALLENGE_TEXT = /(?:confirm you(?:'|’)?re not a robot|recaptcha|enter the characters you see|account recovery|check your phone|tap yes on your phone|确认您不是机器人|確認您不是機器人|输入您看到的字符|輸入您看到的字元|恢复账号|恢復帳戶|查看您的手机|查看您的手機|请在手机上点按|請在手機上輕觸|xác nhận bạn không phải là rô-bốt|kiểm tra điện thoại)/i;

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

function isAllowedGoogleOAuthLocation(value) {
  const host = googleHost(value);
  return GOOGLE_HOSTS.has(host) || host === 'codeassist.google.com';
}

function classifyGoogleChallengePath(value) {
  const pathname = googlePath(value);
  if (/\/challenge\/(?:totp|authenticator)(?:\/|$)/.test(pathname)) return 'totp';
  if (/\/challenge\/(?:selection|chooser)(?:\/|$)/.test(pathname)) return 'challenge_selection';
  if (/(?:\/challenge\/(?:captcha|recaptcha|speedbump|sorry)(?:\/|$)|\/(?:captcha|recaptcha|speedbump|sorry)(?:\/|$))/.test(pathname)) {
    return 'manual_challenge';
  }
  return /\/challenge\//.test(pathname) && !/\/challenge\/pwd(?:\/|$)/.test(pathname)
    ? 'challenge'
    : '';
}

async function visible(locator) {
  return locator.isVisible().catch(() => false);
}

function googleText(page, pattern) {
  return page.getByText(pattern).last();
}

async function hasManualGoogleChallenge(page) {
  const direct = classifyGoogleChallengePath(page.url());
  if (direct === 'manual_challenge') return true;
  const frames = typeof page.frames === 'function' ? page.frames() : [];
  if (frames.some((frame) => classifyGoogleChallengePath(frame.url?.() || '') === 'manual_challenge')) return true;
  const body = await page.locator('body').innerText().catch(() => '');
  return GOOGLE_MANUAL_CHALLENGE_TEXT.test(body);
}

async function detectGoogleOAuthPage(page, { allowAntigravity = false } = {}) {
  const host = googleHost(page.url());
  if (!GOOGLE_HOSTS.has(host)) {
    return parseCallbackUrl(page.url(), { allowCodeAssist: true, allowAntigravity })
      ? 'redirected'
      : 'unexpected_redirect';
  }
  const challenge = classifyGoogleChallengePath(page.url());
  if (challenge === 'totp') return 'totp';
  if (challenge === 'manual_challenge') return 'manual_challenge';
  if (await visible(page.locator('input[type="email"], input#identifierId').first())) return 'email';
  if (await visible(page.locator('input[type="password"]').first())) return 'password';
  if (await visible(googleText(page, GOOGLE_USE_ANOTHER_ACCOUNT))) return 'choose_account';
  if (challenge === 'challenge_selection') return 'challenge_selection';
  if (challenge === 'challenge' && await visible(googleText(page, GOOGLE_TRY_ANOTHER_WAY))) {
    return 'challenge_alternatives';
  }
  if (challenge === 'challenge') {
    return await hasManualGoogleChallenge(page) ? 'manual_challenge' : 'unsupported_challenge';
  }
  if (await visible(page.getByRole('button', { name: GOOGLE_CONSENT_ACTION }).last())) return 'consent';
  if (await hasManualGoogleChallenge(page)) return 'manual_challenge';
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
  if (/wrong code|incorrect code|invalid code|code you entered is incorrect/i.test(text)) {
    throw new GoogleLoginError('Google rejected the two-factor code', 'invalid_two_factor');
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

  async completeLogin(page, { timeoutMs = 5 * 60_000, allowAntigravity = false } = {}) {
    const deadline = Date.now() + timeoutMs;
    let submittedRoute = '';
    let submittedAt = 0;
    let waitingSince = 0;
    while (Date.now() < deadline) {
      await assertGoogleLoginHealthy(page);
      const route = await detectGoogleOAuthPage(page, { allowAntigravity });
      if (route === 'consent' || route === 'redirected') return { reached: route };
      if (route === 'unexpected_redirect') {
        throw new GoogleLoginError('Google OAuth redirected to an unexpected site', 'unexpected_redirect');
      }
      if (route === 'unsupported_challenge' || route === 'manual_challenge') {
        throw new GoogleLoginError('Google requested an unsupported verification challenge', 'manual_challenge');
      }
      if (route === 'waiting') {
        if (!waitingSince) waitingSince = Date.now();
        if (Date.now() - waitingSince >= 20_000) {
          throw new GoogleLoginError('Google OAuth reached an unrecognized page state', 'unrecognized_page');
        }
        await page.waitForTimeout(300);
        continue;
      }
      waitingSince = 0;
      if (submittedRoute && route !== submittedRoute) {
        submittedRoute = '';
        submittedAt = 0;
      }
      if (submittedRoute === route) {
        if (submittedAt && Date.now() - submittedAt >= 45_000) {
          throw new GoogleLoginError('Google OAuth did not advance after a login step', 'login_stalled');
        }
        await page.waitForTimeout(300);
        continue;
      }
      if (route === 'choose_account') {
        await googleText(page, GOOGLE_USE_ANOTHER_ACCOUNT).click({ timeout: 5_000 });
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
      } else if (route === 'challenge_alternatives') {
        await googleText(page, GOOGLE_TRY_ANOTHER_WAY).click({ timeout: 5_000 });
      } else if (route === 'challenge_selection') {
        const authenticator = googleText(page, GOOGLE_AUTHENTICATOR_METHOD);
        if (!await visible(authenticator)) {
          throw new GoogleLoginError('Google did not offer the configured Authenticator method', 'manual_challenge');
        }
        await authenticator.click({ timeout: 5_000 });
      } else {
        await page.waitForTimeout(300);
        continue;
      }
      submittedRoute = route;
      submittedAt = Date.now();
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
    directBrowserEgress = false,
    timeoutMs = 10 * 60_000,
  } = {}) {
    const authorization = await this.sub2api.generateGeminiAuthUrl({
      proxyId,
      projectId,
      oauthType,
      tierId,
    });
    let session;
    try {
      session = await this.browser.open({
        incognito,
        directEgress: directBrowserEgress,
        timeoutMs: Math.min(timeoutMs, 90_000),
      });
      try {
        await session.goto(authorization.authUrl, {
          waitUntil: 'commit',
          timeout: Math.min(timeoutMs, 90_000),
        });
      } catch (error) {
        // Chromium reports ERR_ABORTED for some successful Google redirect
        // hand-offs. Continue only when the page itself proves it stayed on
        // the exact authorization/callback host allowlist.
        const aborted = /net::ERR_ABORTED\b/.test(String(error?.message || ''));
        if (!aborted || !isAllowedGoogleOAuthLocation(session.page.url())) throw error;
      }
    } catch {
      // Playwright navigation errors include the complete OAuth URL (and its
      // state) in their message. Convert them at this boundary so neither the
      // CLI nor an operator log can expose that material.
      await this.browser.release({ closeWindow: false }).catch(() => {});
      throw new GoogleLoginError('Google OAuth authorization page was unreachable', 'navigation_failed');
    }
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
          if (route === 'unsupported_challenge' || route === 'manual_challenge') {
            throw new GoogleLoginError('Google requested an unsupported verification challenge', 'manual_challenge');
          }
          if (route !== 'consent') {
            await session.page.waitForTimeout(500);
            continue;
          }
          const authorize = session.page.getByRole('button', { name: GOOGLE_CONSENT_ACTION }).last();
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
  GOOGLE_AUTHENTICATOR_METHOD,
  GOOGLE_CONSENT_ACTION,
  GOOGLE_TRY_ANOTHER_WAY,
  GOOGLE_USE_ANOTHER_ACCOUNT,
  assertGoogleLoginHealthy,
  classifyGoogleChallengePath,
  detectGoogleOAuthPage,
  isAllowedGoogleOAuthLocation,
  readGoogleTwoFactor,
};
