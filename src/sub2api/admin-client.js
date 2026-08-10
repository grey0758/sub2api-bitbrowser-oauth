'use strict';

const DEFAULT_BASE_URL = 'https://sub2apipro.opencodex.uk';

class Sub2ApiError extends Error {
  constructor(message, { status, data, cause } = {}) {
    super(message);
    this.name = 'Sub2ApiError';
    this.status = status;
    this.data = data;
    this.cause = cause;
  }
}

function normalizeBaseUrl(value) {
  const base = String(value || DEFAULT_BASE_URL).trim().replace(/\/+$/, '');
  if (!/^https:\/\//i.test(base) && !/^http:\/\/127\.0\.0\.1(?::\d+)?$/i.test(base)) {
    throw new TypeError('SUB2API_BASE_URL must be HTTPS, or loopback HTTP for local verification');
  }
  return base;
}

function authHeaders({ token, apiKey, cookie } = {}) {
  const headers = { accept: 'application/json', 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  if (apiKey) headers['x-api-key'] = apiKey;
  if (cookie) headers.cookie = cookie;
  return headers;
}

class Sub2ApiAdminClient {
  constructor({
    baseUrl = process.env.SUB2API_BASE_URL,
    token = process.env.SUB2API_ADMIN_TOKEN,
    apiKey = process.env.SUB2API_ADMIN_API_KEY,
    cookie = process.env.SUB2API_ADMIN_COOKIE,
    fetchImpl = globalThis.fetch,
    timeoutMs = 120_000,
  } = {}) {
    if (typeof fetchImpl !== 'function') throw new Error('Node 18+ fetch is required');
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.token = token ? String(token).trim() : '';
    this.apiKey = apiKey ? String(apiKey).trim() : '';
    this.cookie = cookie ? String(cookie).trim() : '';
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  assertCredentials() {
    if (!this.token && !this.apiKey && !this.cookie) {
      throw new Error('Sub2API administrator credentials are missing; set SUB2API_ADMIN_TOKEN, SUB2API_ADMIN_API_KEY, or SUB2API_ADMIN_COOKIE at runtime');
    }
  }

  async post(path, body = {}) {
    this.assertCredentials();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: authHeaders({ token: this.token, apiKey: this.apiKey, cookie: this.cookie }),
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      let data;
      try { data = await response.json(); } catch (error) {
        throw new Sub2ApiError(`Sub2API returned non-JSON from ${path}`, { status: response.status, cause: error });
      }
      if (!response.ok) {
        throw new Sub2ApiError(`Sub2API ${path} failed (HTTP ${response.status})`, { status: response.status, data });
      }
      // The web client unwraps the common `{code: 0, data: ...}` envelope in
      // its Axios interceptor. Mirror that behavior for direct API calls.
      if (data && typeof data === 'object' && Object.prototype.hasOwnProperty.call(data, 'code')) {
        if (data.code !== 0) {
          throw new Sub2ApiError(`Sub2API ${path} returned an application error`, { status: response.status, data });
        }
        return data.data;
      }
      return data;
    } catch (error) {
      if (error.name === 'AbortError') throw new Sub2ApiError(`Sub2API request timed out: ${path}`, { cause: error });
      if (error instanceof Sub2ApiError) throw error;
      throw new Sub2ApiError(`Sub2API request failed: ${path}`, { cause: error });
    } finally {
      clearTimeout(timer);
    }
  }

  async generateOpenAiAuthUrl({ proxyId } = {}) {
    const body = proxyId == null || proxyId === '' ? {} : { proxy_id: proxyId };
    const result = await this.post('/admin/accounts/generate-auth-url', body);
    const authUrl = result?.auth_url;
    const sessionId = result?.session_id;
    if (typeof authUrl !== 'string' || !/^https:\/\/auth\.openai\.com\/oauth\/authorize\?/i.test(authUrl)) {
      throw new Sub2ApiError('Sub2API returned an unexpected OpenAI authorization URL', { data: result });
    }
    if (typeof sessionId !== 'string' || !sessionId) {
      throw new Sub2ApiError('Sub2API returned no OAuth session_id', { data: result });
    }
    let state = '';
    try { state = new URL(authUrl).searchParams.get('state') || ''; } catch { /* validated above */ }
    return { authUrl, sessionId, state };
  }

  async exchangeOpenAiCode({ sessionId, code, state, proxyId } = {}) {
    if (!sessionId || !code || !state) throw new Error('sessionId, code, and state are required for OAuth exchange');
    const body = { session_id: sessionId, code, state };
    if (proxyId != null && proxyId !== '') body.proxy_id = proxyId;
    return this.post('/admin/accounts/exchange-code', body);
  }
}

function parseCodeInput(value) {
  const raw = String(value || '').trim();
  if (!raw) throw new Error('OAuth callback URL or code is required');
  if (!/^https?:\/\//i.test(raw)) return { code: raw, state: '' };
  let url;
  try { url = new URL(raw); } catch { throw new Error('OAuth callback input is not a valid URL'); }
  const code = url.searchParams.get('code');
  if (!code) throw new Error('OAuth callback URL does not contain a code parameter');
  return { code, state: url.searchParams.get('state') || '' };
}

module.exports = { DEFAULT_BASE_URL, Sub2ApiAdminClient, Sub2ApiError, normalizeBaseUrl, parseCodeInput };
