'use strict';

/**
 * Small BitBrowser HTTP client extracted from plus_paypal's browser module.
 * This client deliberately exposes only the API calls needed by the fixed
 * window controller. It never creates or deletes a window.
 */
class BitBrowserApiError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'BitBrowserApiError';
    Object.assign(this, details);
  }
}

function normalizeBaseUrl(value) {
  const base = String(value || 'http://127.0.0.1:54345').trim().replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(base)) throw new TypeError('BITBROWSER_API_URL must use http or https');
  return base;
}

class BitBrowserClient {
  constructor({ baseUrl = process.env.BITBROWSER_API_URL, fetchImpl = globalThis.fetch, timeoutMs = 30_000 } = {}) {
    if (typeof fetchImpl !== 'function') throw new Error('Node 18+ fetch is required');
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  async post(path, body = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      let data;
      try {
        data = await response.json();
      } catch (error) {
        throw new BitBrowserApiError(`BitBrowser returned non-JSON from ${path}`, { cause: error, status: response.status });
      }
      if (!response.ok || data?.success === false) {
        const message = data?.msg || data?.message || `HTTP ${response.status}`;
        throw new BitBrowserApiError(`BitBrowser ${path}: ${message}`, { status: response.status, data });
      }
      return data;
    } catch (error) {
      if (error.name === 'AbortError') throw new BitBrowserApiError(`BitBrowser request timed out: ${path}`, { cause: error });
      if (error instanceof BitBrowserApiError) throw error;
      throw new BitBrowserApiError(`BitBrowser request failed: ${path}`, { cause: error });
    } finally {
      clearTimeout(timer);
    }
  }

  async listWindows({ page = 0, pageSize = 200 } = {}) {
    const response = await this.post('/browser/list', { page, pageSize });
    return Array.isArray(response?.data?.list) ? response.data.list : [];
  }

  async openWindow(id, { args, loadExtensions, extractIp } = {}) {
    if (!id) throw new TypeError('BitBrowser window id is required');
    const body = { id };
    if (args !== undefined) body.args = args;
    if (loadExtensions !== undefined) body.loadExtensions = loadExtensions;
    if (extractIp !== undefined) body.extractIp = extractIp;
    const response = await this.post('/browser/open', body);
    const ws = response?.data?.ws;
    if (!ws) throw new BitBrowserApiError('BitBrowser open response did not include a CDP websocket URL', { data: response });
    return { ...response.data, id };
  }

  async closeWindow(id) {
    if (!id) return;
    try {
      await this.post('/browser/close', { id });
    } catch (error) {
      // BitBrowser can report the process-level ESRCH race after the window
      // has already stopped. An explicit close request has still succeeded.
      if (!/\bkill\s+ESRCH\b/i.test(String(error?.message || ''))) throw error;
    }
  }
}

module.exports = { BitBrowserClient, BitBrowserApiError, normalizeBaseUrl };
