'use strict';

const { chromium } = require('playwright');
const { BitBrowserClient } = require('./client');

const DEFAULT_WINDOW_NAME = 'us001_codex';

function exactWindowMatches(windows, windowName) {
  return windows.filter((window) => !window?.isDelete && String(window?.name || '') === windowName);
}

/**
 * Controls one pre-created BitBrowser window by exact name.
 *
 * Safety contract: this controller never creates, deletes, closes, refreshes,
 * or clears any window other than the exact configured window. By default its
 * release operation only disconnects Playwright and leaves the BitBrowser
 * window open for the operator.
 */
class FixedWindowController {
  constructor({ client = new BitBrowserClient(), windowName = process.env.BITBROWSER_WINDOW_NAME || DEFAULT_WINDOW_NAME, chromiumImpl = chromium, connectTimeoutMs = 30_000 } = {}) {
    this.client = client;
    this.windowName = windowName;
    this.chromium = chromiumImpl;
    this.connectTimeoutMs = connectTimeoutMs;
    this.session = null;
  }

  async findExact() {
    const matches = exactWindowMatches(await this.client.listWindows(), this.windowName);
    if (matches.length === 0) throw new Error(`BitBrowser window not found: ${this.windowName}`);
    if (matches.length > 1) throw new Error(`BitBrowser window name is ambiguous: ${this.windowName} (${matches.length} matches)`);
    return matches[0];
  }

  async open({ url, waitUntil = 'domcontentloaded', timeoutMs = 60_000 } = {}) {
    if (this.session) return this.session;
    const window = await this.findExact();
    const opened = await this.client.openWindow(window.id);
    const browser = await this.chromium.connectOverCDP(opened.ws, { timeout: this.connectTimeoutMs });
    const context = browser.contexts()[0] || await browser.newContext();
    const page = context.pages()[0] || await context.newPage();
    this.session = new FixedWindowSession({ controller: this, browser, context, page, window });
    if (url) await page.goto(url, { waitUntil, timeout: timeoutMs });
    return this.session;
  }

  async release({ closeWindow = false } = {}) {
    const session = this.session;
    this.session = null;
    if (!session) return;
    await session.disconnect();
    if (closeWindow) await this.client.closeWindow(session.window.id);
  }
}

class FixedWindowSession {
  constructor({ controller, browser, context, page, window }) {
    this.controller = controller;
    this.browser = browser;
    this.context = context;
    this.page = page;
    this.window = window;
  }

  async goto(url, options = {}) {
    return this.page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60_000, ...options });
  }

  pages() {
    return this.context.pages();
  }

  async waitForCallback({ timeoutMs = 10 * 60_000, pollMs = 500 } = {}) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      for (const page of this.context.pages()) {
        const parsed = parseCallbackUrl(page.url());
        if (parsed) return { ...parsed, page };
      }
      await new Promise((resolve) => setTimeout(resolve, pollMs));
    }
    throw new Error(`OAuth callback was not observed within ${Math.ceil(timeoutMs / 1000)} seconds`);
  }

  async disconnect() {
    // Playwright's CDP close disconnects the client; it does not call the
    // BitBrowser /browser/close endpoint. Keep the named profile available.
    await this.browser.close().catch(() => {});
  }
}

function parseCallbackUrl(value) {
  if (!value || !/^https?:\/\//i.test(value)) return null;
  let parsed;
  try { parsed = new URL(value); } catch { return null; }
  if (!/^localhost$|^127\.0\.0\.1$/.test(parsed.hostname)) return null;
  if (!/^\/auth\/callback\/?$/.test(parsed.pathname)) return null;
  const code = parsed.searchParams.get('code');
  if (!code) return null;
  return { code, state: parsed.searchParams.get('state') || '' };
}

module.exports = { DEFAULT_WINDOW_NAME, FixedWindowController, FixedWindowSession, exactWindowMatches, parseCallbackUrl };
