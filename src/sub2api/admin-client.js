'use strict';

const DEFAULT_BASE_URL = 'https://sub2apiplus.opencodex.uk';

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

function normalizeApiPrefix(value) {
  const prefix = String(value || '/api/v1').trim();
  if (!prefix.startsWith('/')) throw new TypeError('SUB2API_API_PREFIX must start with /');
  return `/${prefix.replace(/^\/+|\/+$/g, '')}`;
}

function authHeaders({ token, apiKey, cookie } = {}) {
  const headers = { accept: 'application/json', 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  if (apiKey) headers['x-api-key'] = apiKey;
  if (cookie) headers.cookie = cookie;
  return headers;
}

const OPENAI_CREDENTIAL_FIELDS = [
  'refresh_token',
  'id_token',
  'email',
  'chatgpt_account_id',
  'chatgpt_user_id',
  'organization_id',
  'plan_type',
  'subscription_expires_at',
  'client_id',
];

function buildOpenAiCredentials(value) {
  if (!value || typeof value !== 'object') {
    throw new Sub2ApiError('Sub2API returned no OpenAI credential material');
  }
  if (typeof value.access_token !== 'string' || !value.access_token.trim()) {
    throw new Sub2ApiError('Sub2API returned incomplete OpenAI credential material');
  }
  const expiresAtIsValid =
    (typeof value.expires_at === 'string' && value.expires_at.trim()) ||
    (typeof value.expires_at === 'number' && Number.isFinite(value.expires_at));
  if (!expiresAtIsValid) {
    throw new Sub2ApiError('Sub2API returned incomplete OpenAI credential material');
  }

  const credentials = {
    access_token: value.access_token,
    expires_at: value.expires_at,
  };
  for (const field of OPENAI_CREDENTIAL_FIELDS) {
    if (value[field]) credentials[field] = value[field];
  }
  return credentials;
}

function buildOpenAiExtraInfo(value) {
  const extra = {};
  for (const field of ['email', 'name', 'privacy_mode']) {
    if (value?.[field]) extra[field] = value[field];
  }
  return Object.keys(extra).length > 0 ? extra : undefined;
}

const GEMINI_OAUTH_TYPES = new Set(['code_assist', 'google_one', 'ai_studio']);

function normalizeGeminiOAuthType(value) {
  const oauthType = String(value || 'google_one').trim();
  if (!GEMINI_OAUTH_TYPES.has(oauthType)) {
    throw new TypeError('Gemini oauthType must be code_assist, google_one, or ai_studio');
  }
  return oauthType;
}

function buildGeminiCredentials(value) {
  if (!value || typeof value !== 'object') {
    throw new Sub2ApiError('Sub2API returned no Gemini credential material');
  }
  if (typeof value.access_token !== 'string' || !value.access_token.trim()) {
    throw new Sub2ApiError('Sub2API returned incomplete Gemini credential material');
  }
  const expiresAt = typeof value.expires_at === 'number' && Number.isFinite(value.expires_at)
    ? Math.floor(value.expires_at).toString()
    : typeof value.expires_at === 'string' && value.expires_at.trim()
      ? value.expires_at.trim()
      : '';
  if (!expiresAt) throw new Sub2ApiError('Sub2API returned incomplete Gemini credential material');
  const credentials = { access_token: value.access_token, expires_at: expiresAt };
  for (const field of ['refresh_token', 'token_type', 'scope', 'project_id', 'oauth_type', 'tier_id']) {
    if (value[field]) credentials[field] = value[field];
  }
  return credentials;
}

function buildAntigravityCredentials(value) {
  if (!value || typeof value !== 'object') {
    throw new Sub2ApiError('Sub2API returned no Antigravity credential material');
  }
  if (
    typeof value.access_token !== 'string' || !value.access_token.trim() ||
    typeof value.refresh_token !== 'string' || !value.refresh_token.trim()
  ) {
    throw new Sub2ApiError('Sub2API returned incomplete Antigravity credential material');
  }
  const expiresAt = typeof value.expires_at === 'number' && Number.isFinite(value.expires_at)
    ? Math.floor(value.expires_at).toString()
    : typeof value.expires_at === 'string' && value.expires_at.trim()
      ? value.expires_at.trim()
      : '';
  if (!expiresAt) throw new Sub2ApiError('Sub2API returned incomplete Antigravity credential material');
  const credentials = {
    access_token: value.access_token,
    refresh_token: value.refresh_token,
    expires_at: expiresAt,
  };
  for (const field of ['token_type', 'project_id', 'email']) {
    if (value[field]) credentials[field] = value[field];
  }
  return credentials;
}

function normalizeAccountPage(value) {
  if (Array.isArray(value)) return { accounts: value, total: value.length };
  if (!value || typeof value !== 'object') {
    throw new Sub2ApiError('Sub2API returned an invalid account list');
  }
  const accounts = [value.items, value.accounts, value.list].find(Array.isArray);
  if (!accounts) throw new Sub2ApiError('Sub2API returned an invalid account list');
  const total = [value.total, value.count].find((item) => Number.isInteger(item) && item >= 0);
  return { accounts, total };
}

function accountEmailCandidates(account) {
  return [
    account?.extra?.email_address,
    account?.extra?.email,
    account?.credentials?.email,
    account?.parent_email,
  ].filter((item) => typeof item === 'string' && item.trim());
}

class Sub2ApiAdminClient {
  constructor({
    baseUrl = process.env.SUB2API_BASE_URL,
    apiPrefix = process.env.SUB2API_API_PREFIX,
    token = process.env.SUB2API_ADMIN_TOKEN,
    apiKey = process.env.SUB2API_ADMIN_API_KEY,
    cookie = process.env.SUB2API_ADMIN_COOKIE,
    fetchImpl = globalThis.fetch,
    timeoutMs = 120_000,
  } = {}) {
    if (typeof fetchImpl !== 'function') throw new Error('Node 18+ fetch is required');
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.apiPrefix = normalizeApiPrefix(apiPrefix);
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

  async request(method, path, { body, query } = {}) {
    this.assertCredentials();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const url = new URL(`${this.baseUrl}${this.apiPrefix}${path}`);
      for (const [key, value] of Object.entries(query || {})) {
        if (value !== undefined && value !== null && value !== '') url.searchParams.set(key, String(value));
      }
      const options = {
        method,
        headers: authHeaders({ token: this.token, apiKey: this.apiKey, cookie: this.cookie }),
        signal: controller.signal,
      };
      if (body !== undefined) options.body = JSON.stringify(body);
      const response = await this.fetchImpl(url.toString(), options);
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

  async get(path, query) {
    return this.request('GET', path, { query });
  }

  async post(path, body = {}) {
    return this.request('POST', path, { body });
  }

  async generateOpenAiAuthUrl({ proxyId } = {}) {
    const body = proxyId == null || proxyId === '' ? {} : { proxy_id: proxyId };
    const result = await this.post('/admin/openai/generate-auth-url', body);
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
    return this.post('/admin/openai/exchange-code', body);
  }

  async getGeminiOAuthCapabilities() {
    return this.get('/admin/gemini/oauth/capabilities');
  }

  async generateAntigravityAuthUrl({ proxyId } = {}) {
    const body = {};
    if (proxyId != null && proxyId !== '') body.proxy_id = proxyId;
    const result = await this.post('/admin/antigravity/oauth/auth-url', body);
    const authUrl = result?.auth_url;
    const sessionId = result?.session_id;
    const state = result?.state;
    let parsed;
    try { parsed = new URL(authUrl); } catch { /* validated below */ }
    if (
      !parsed ||
      parsed.protocol !== 'https:' ||
      !['accounts.google.com', 'consent.google.com'].includes(parsed.hostname)
    ) {
      throw new Sub2ApiError('Sub2API returned an unexpected Antigravity authorization URL', { data: result });
    }
    if (typeof sessionId !== 'string' || !sessionId || typeof state !== 'string' || !state) {
      throw new Sub2ApiError('Sub2API returned an incomplete Antigravity OAuth session', { data: result });
    }
    if (parsed.searchParams.get('state') !== state) {
      throw new Sub2ApiError('Sub2API returned an inconsistent Antigravity OAuth state');
    }
    return { authUrl, sessionId, state };
  }

  async exchangeAntigravityCode({ sessionId, code, state, proxyId } = {}) {
    if (!sessionId || !code || !state) {
      throw new Error('sessionId, code, and state are required for Antigravity OAuth exchange');
    }
    const body = { session_id: sessionId, code, state };
    if (proxyId != null && proxyId !== '') body.proxy_id = proxyId;
    return this.post('/admin/antigravity/oauth/exchange-code', body);
  }

  async generateGeminiAuthUrl({ proxyId, projectId, oauthType = 'google_one', tierId } = {}) {
    const normalizedType = normalizeGeminiOAuthType(oauthType);
    if (normalizedType === 'code_assist' && !String(projectId || '').trim()) {
      throw new TypeError('Gemini code_assist OAuth requires projectId');
    }
    const body = { oauth_type: normalizedType };
    if (proxyId != null && proxyId !== '') body.proxy_id = proxyId;
    if (String(projectId || '').trim()) body.project_id = String(projectId).trim();
    if (String(tierId || '').trim()) body.tier_id = String(tierId).trim();
    const result = await this.post('/admin/gemini/oauth/auth-url', body);
    const authUrl = result?.auth_url;
    const sessionId = result?.session_id;
    const state = result?.state;
    let parsed;
    try { parsed = new URL(authUrl); } catch { /* validated below */ }
    if (
      !parsed ||
      parsed.protocol !== 'https:' ||
      !['accounts.google.com', 'consent.google.com'].includes(parsed.hostname)
    ) {
      throw new Sub2ApiError('Sub2API returned an unexpected Gemini authorization URL', { data: result });
    }
    if (typeof sessionId !== 'string' || !sessionId || typeof state !== 'string' || !state) {
      throw new Sub2ApiError('Sub2API returned an incomplete Gemini OAuth session', { data: result });
    }
    return { authUrl, sessionId, state, oauthType: normalizedType };
  }

  async exchangeGeminiCode({ sessionId, code, state, proxyId, oauthType = 'google_one', tierId } = {}) {
    if (!sessionId || !code || !state) throw new Error('sessionId, code, and state are required for Gemini OAuth exchange');
    const body = {
      session_id: sessionId,
      code,
      state,
      oauth_type: normalizeGeminiOAuthType(oauthType),
    };
    if (proxyId != null && proxyId !== '') body.proxy_id = proxyId;
    if (String(tierId || '').trim()) body.tier_id = String(tierId).trim();
    return this.post('/admin/gemini/oauth/exchange-code', body);
  }

  async listAccounts({ page = 1, pageSize = 100 } = {}) {
    return this.get('/admin/accounts', { page, page_size: pageSize });
  }

  async listAllAccounts({ pageSize = 100 } = {}) {
    const size = Math.max(1, Math.min(100, Number(pageSize) || 100));
    const accounts = [];
    for (let page = 1; page <= 100; page += 1) {
      const listed = normalizeAccountPage(await this.listAccounts({ page, pageSize: size }));
      accounts.push(...listed.accounts);
      if (
        listed.accounts.length < size ||
        (listed.total !== undefined && page * size >= listed.total)
      ) break;
    }
    return accounts;
  }

  async findOpenAiAccountByEmail(email, { pageSize = 100 } = {}) {
    const expected = String(email || '').trim().toLowerCase();
    if (!expected) throw new TypeError('email is required for account lookup');
    const matches = [];
    for (let page = 1; page <= 100; page += 1) {
      const listed = normalizeAccountPage(await this.listAccounts({ page, pageSize }));
      for (const account of listed.accounts) {
        if (
          account?.platform === 'openai' &&
          accountEmailCandidates(account).some((candidate) => candidate.trim().toLowerCase() === expected)
        ) {
          matches.push(account);
        }
      }
      if (
        listed.accounts.length < pageSize ||
        (listed.total !== undefined && page * pageSize >= listed.total)
      ) break;
    }
    if (matches.length > 1) {
      throw new Sub2ApiError('Sub2API account lookup returned duplicate exact email matches');
    }
    return matches[0] || null;
  }

  async findGeminiAccountByName(name, { pageSize = 100 } = {}) {
    const expected = String(name || '').trim().toLowerCase();
    if (!expected) throw new TypeError('name is required for Gemini account lookup');
    const matches = [];
    for (let page = 1; page <= 100; page += 1) {
      const listed = normalizeAccountPage(await this.listAccounts({ page, pageSize }));
      for (const account of listed.accounts) {
        if (
          account?.platform === 'gemini' &&
          typeof account.name === 'string' &&
          account.name.trim().toLowerCase() === expected
        ) matches.push(account);
      }
      if (
        listed.accounts.length < pageSize ||
        (listed.total !== undefined && page * pageSize >= listed.total)
      ) break;
    }
    if (matches.length > 1) {
      throw new Sub2ApiError('Sub2API Gemini account lookup returned duplicate exact-name matches');
    }
    return matches[0] || null;
  }

  async findAntigravityAccountByName(name, { pageSize = 100 } = {}) {
    const expected = String(name || '').trim().toLowerCase();
    if (!expected) throw new TypeError('name is required for Antigravity account lookup');
    const matches = [];
    for (let page = 1; page <= 100; page += 1) {
      const listed = normalizeAccountPage(await this.listAccounts({ page, pageSize }));
      for (const account of listed.accounts) {
        if (
          account?.platform === 'antigravity' &&
          typeof account.name === 'string' &&
          account.name.trim().toLowerCase() === expected
        ) matches.push(account);
      }
      if (
        listed.accounts.length < pageSize ||
        (listed.total !== undefined && page * pageSize >= listed.total)
      ) break;
    }
    if (matches.length > 1) {
      throw new Sub2ApiError('Sub2API Antigravity account lookup returned duplicate exact-name matches');
    }
    return matches[0] || null;
  }

  async createAccount(body) {
    return this.post('/admin/accounts', body);
  }

  async applyOAuthCredentials(accountId, body) {
    if (accountId === undefined || accountId === null || accountId === '') {
      throw new TypeError('accountId is required for OAuth credential application');
    }
    return this.post(`/admin/accounts/${encodeURIComponent(String(accountId))}/apply-oauth-credentials`, body);
  }

  async importOpenAiOAuthAccount({ email, exchangeResult, proxyId, verifyAttempts = 5 } = {}) {
    const expectedEmail = String(email || '').trim();
    if (!expectedEmail) throw new TypeError('email is required for OpenAI account import');
    if (
      typeof exchangeResult?.email !== 'string' ||
      exchangeResult.email.trim().toLowerCase() !== expectedEmail.toLowerCase()
    ) {
      throw new Sub2ApiError('OpenAI OAuth identity did not match the requested account');
    }

    const credentials = buildOpenAiCredentials(exchangeResult);
    const extra = buildOpenAiExtraInfo(exchangeResult);
    const existing = await this.findOpenAiAccountByEmail(expectedEmail);
    let action;
    if (existing) {
      await this.applyOAuthCredentials(existing.id, {
        type: 'oauth',
        credentials,
        ...(extra ? { extra } : {}),
      });
      action = 'updated';
    } else {
      const body = {
        name: expectedEmail,
        platform: 'openai',
        type: 'oauth',
        credentials,
        ...(extra ? { extra } : {}),
      };
      if (proxyId !== undefined && proxyId !== null && proxyId !== '') body.proxy_id = proxyId;
      await this.createAccount(body);
      action = 'created';
    }

    const attempts = Math.max(1, Number(verifyAttempts) || 1);
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const verified = await this.findOpenAiAccountByEmail(expectedEmail);
      if (verified) return { action, accountId: verified.id };
      if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, 500));
    }
    throw new Sub2ApiError('Sub2API account import was not visible in the account list after the write');
  }

  async importGeminiOAuthAccount({ email, exchangeResult, proxyId, verifyAttempts = 5 } = {}) {
    const expectedEmail = String(email || '').trim();
    if (!expectedEmail) throw new TypeError('email is required for Gemini account import');
    const credentials = buildGeminiCredentials(exchangeResult);
    const extra = exchangeResult?.extra && typeof exchangeResult.extra === 'object'
      ? exchangeResult.extra
      : undefined;
    const existing = await this.findGeminiAccountByName(expectedEmail);
    let action;
    if (existing) {
      await this.applyOAuthCredentials(existing.id, {
        type: 'oauth',
        credentials,
        ...(extra ? { extra } : {}),
      });
      action = 'updated';
    } else {
      const body = {
        name: expectedEmail,
        platform: 'gemini',
        type: 'oauth',
        credentials,
        ...(extra ? { extra } : {}),
      };
      if (proxyId !== undefined && proxyId !== null && proxyId !== '') body.proxy_id = proxyId;
      await this.createAccount(body);
      action = 'created';
    }
    const attempts = Math.max(1, Number(verifyAttempts) || 1);
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const verified = await this.findGeminiAccountByName(expectedEmail);
      if (verified) return { action, accountId: verified.id };
      if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, 500));
    }
    throw new Sub2ApiError('Sub2API Gemini account import was not visible after the write');
  }

  async importAntigravityOAuthAccount({ email, exchangeResult, proxyId, verifyAttempts = 5 } = {}) {
    const expectedEmail = String(email || '').trim();
    if (!expectedEmail) throw new TypeError('email is required for Antigravity account import');
    if (
      typeof exchangeResult?.email !== 'string' ||
      exchangeResult.email.trim().toLowerCase() !== expectedEmail.toLowerCase()
    ) {
      throw new Sub2ApiError('Antigravity OAuth exchange identity does not match the selected account');
    }
    const credentials = buildAntigravityCredentials(exchangeResult);
    const existing = await this.findAntigravityAccountByName(expectedEmail);
    let action;
    if (existing) {
      await this.applyOAuthCredentials(existing.id, { type: 'oauth', credentials });
      action = 'updated';
    } else {
      const body = {
        name: expectedEmail,
        platform: 'antigravity',
        type: 'oauth',
        credentials,
        priority: 1000,
        rate_multiplier: 1,
      };
      if (proxyId !== undefined && proxyId !== null && proxyId !== '') body.proxy_id = proxyId;
      await this.createAccount(body);
      action = 'created';
    }
    const attempts = Math.max(1, Number(verifyAttempts) || 1);
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const verified = await this.findAntigravityAccountByName(expectedEmail);
      if (
        verified &&
        verified.type === 'oauth' &&
        Number(verified.proxy_id) === Number(proxyId) &&
        Number(verified.priority) === 1000 &&
        Number(verified.rate_multiplier) === 1
      ) return { action, accountId: verified.id };
      if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, 500));
    }
    throw new Sub2ApiError('Sub2API Antigravity account import did not satisfy the required final account state');
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

module.exports = {
  DEFAULT_BASE_URL,
  Sub2ApiAdminClient,
  Sub2ApiError,
  accountEmailCandidates,
  buildAntigravityCredentials,
  buildOpenAiCredentials,
  buildOpenAiExtraInfo,
  buildGeminiCredentials,
  normalizeAccountPage,
  normalizeBaseUrl,
  normalizeApiPrefix,
  normalizeGeminiOAuthType,
  parseCodeInput,
};
