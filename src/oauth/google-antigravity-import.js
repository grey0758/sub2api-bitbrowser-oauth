'use strict';

const {
  GoogleGeminiOAuthImportFlow,
  GoogleLoginError,
  GOOGLE_CONSENT_ACTION,
  detectGoogleOAuthPage,
  isAllowedGoogleOAuthLocation,
} = require('./google-gemini-import');

class GoogleAntigravityOAuthImportFlow extends GoogleGeminiOAuthImportFlow {
  async run({ proxyId, incognito = true, timeoutMs = 10 * 60_000 } = {}) {
    const authorization = await this.sub2api.generateAntigravityAuthUrl({ proxyId });
    let session;
    try {
      session = await this.browser.open({
        incognito,
        timeoutMs: Math.min(timeoutMs, 90_000),
      });
      try {
        await session.goto(authorization.authUrl, {
          waitUntil: 'commit',
          timeout: Math.min(timeoutMs, 90_000),
        });
      } catch (error) {
        const aborted = /net::ERR_ABORTED\b/.test(String(error?.message || ''));
        if (!aborted || !isAllowedGoogleOAuthLocation(session.page.url())) throw error;
      }
    } catch {
      await this.browser.release({ closeWindow: false }).catch(() => {});
      throw new GoogleLoginError('Google OAuth authorization page was unreachable', 'navigation_failed');
    }
    try {
      const login = await this.completeLogin(session.page, {
        timeoutMs: Math.min(timeoutMs, 5 * 60_000),
        allowAntigravity: true,
      });
      const callbackPromise = session.waitForCallback({ timeoutMs, allowAntigravity: true });
      if (login.reached === 'consent') {
        for (let step = 0; step < 4; step += 1) {
          const route = await detectGoogleOAuthPage(session.page, { allowAntigravity: true });
          if (route === 'redirected') break;
          if (route === 'unsupported_challenge' || route === 'manual_challenge') {
            throw new GoogleLoginError('Google requested an unsupported verification challenge', 'manual_challenge');
          }
          if (route !== 'consent') {
            await session.page.waitForTimeout(500);
            continue;
          }
          await session.page.getByRole('button', { name: GOOGLE_CONSENT_ACTION }).last()
            .click({ timeout: 10_000 });
          await session.page.waitForTimeout(800);
        }
      }
      const callback = await callbackPromise;
      if (!callback.state || callback.state !== authorization.state) {
        throw new Error('Antigravity OAuth callback state does not match the authorization session');
      }
      const exchangeResult = await this.sub2api.exchangeAntigravityCode({
        sessionId: authorization.sessionId,
        code: callback.code,
        state: callback.state,
        proxyId,
      });
      const imported = await this.sub2api.importAntigravityOAuthAccount({
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

module.exports = { GoogleAntigravityOAuthImportFlow };
