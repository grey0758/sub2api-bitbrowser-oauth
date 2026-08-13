'use strict';

const crypto = require('node:crypto');

const DEFAULT_WORKSTATION_BASE_URL = 'https://workstation.opencodex.uk';
const DEFAULT_MIN_AGE_MINUTES = 45;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]{16,128}$/;
const PHONE_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const BAN_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const BATCH_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const BAN_STATUSES = new Set(['banned', 'banned_replaced']);

class WorkstationAutomationError extends Error {
  constructor(message, { status, code, retryable = false, outcomeUnknown = false, cause } = {}) {
    super(message);
    this.name = 'WorkstationAutomationError';
    this.status = status;
    this.code = code;
    this.retryable = retryable;
    this.outcomeUnknown = outcomeUnknown;
    this.cause = cause;
  }
}

function normalizeBaseUrl(value) {
  const base = String(value || DEFAULT_WORKSTATION_BASE_URL).trim().replace(/\/+$/, '');
  if (!/^https:\/\//i.test(base) && !/^http:\/\/127\.0\.0\.1(?::\d+)?$/i.test(base)) {
    throw new TypeError('WORKSTATION_AUTOMATION_BASE_URL must be HTTPS, or loopback HTTP for local verification');
  }
  return base;
}

function normalizeInteger(value, { name, minimum, maximum, defaultValue }) {
  const normalized = value === undefined || value === null || value === '' ? defaultValue : Number(value);
  if (!Number.isInteger(normalized) || normalized < minimum || normalized > maximum) {
    throw new TypeError(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return normalized;
}

function normalizeErrorCode(value) {
  const code = typeof value === 'string' ? value.trim() : '';
  return /^[a-z][a-z0-9_]{0,63}$/.test(code) ? code : '';
}

function normalizeIdempotencyKey(value) {
  const key = String(value || '').trim();
  if (!IDEMPOTENCY_KEY_PATTERN.test(key)) {
    throw new TypeError('idempotencyKey must be 16 to 128 supported characters');
  }
  return key;
}

function normalizeBanAccount(value) {
  if (!value || typeof value !== 'object') {
    throw new WorkstationAutomationError('Workstation automation returned an invalid banned account record');
  }
  const id = String(value.id || '').trim();
  const status = String(value.status || '').trim();
  if (!BAN_ID_PATTERN.test(id) || !BAN_STATUSES.has(status)) {
    throw new WorkstationAutomationError('Workstation automation returned an invalid banned account record');
  }
  return {
    id,
    status,
    bannedAt: typeof value.banned_at === 'string' ? value.banned_at : null,
    replacedAt: typeof value.replaced_at === 'string' ? value.replaced_at : null,
    statusChangedAt: typeof value.status_changed_at === 'string' ? value.status_changed_at : null,
  };
}

function normalizePhone(value) {
  if (!value || typeof value !== 'object') {
    throw new WorkstationAutomationError('Workstation automation returned an invalid phone record');
  }
  const id = String(value.id || '').trim();
  const number = String(value.number || '').trim();
  if (
    !PHONE_ID_PATTERN.test(id) ||
    !/^\+1\d{10}$/.test(number) ||
    typeof value.unavailable !== 'boolean' ||
    !Number.isInteger(value.binding_count) ||
    !Number.isInteger(value.binding_limit) ||
    value.binding_count < 0 ||
    value.binding_limit < 1 ||
    value.binding_count > value.binding_limit
  ) {
    throw new WorkstationAutomationError('Workstation automation returned an invalid phone record');
  }
  return {
    id,
    number,
    unavailable: value.unavailable,
    bindingCount: value.binding_count,
    bindingLimit: value.binding_limit,
    lastBindingAt: typeof value.last_binding_at === 'string' ? value.last_binding_at : null,
  };
}

function generatePhoneClaimKey() {
  return `sub2api-bind-${crypto.randomUUID()}`;
}

function generateAccountReplacementKey() {
  return `sub2api-replace-${crypto.randomUUID()}`;
}

class WorkstationAutomationClient {
  constructor({
    baseUrl = process.env.WORKSTATION_AUTOMATION_BASE_URL,
    token = process.env.WORKSTATION_AUTOMATION_TOKEN,
    fetchImpl = globalThis.fetch,
    timeoutMs = 20_000,
  } = {}) {
    if (typeof fetchImpl !== 'function') throw new Error('Node 18+ fetch is required');
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.token = token ? String(token).trim() : '';
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  assertCredentials() {
    if (!this.token) {
      throw new Error('Workstation automation credential is missing; set WORKSTATION_AUTOMATION_TOKEN at runtime');
    }
  }

  async request(method, path, { body, query, headers = {}, outcomeUnknownOnTransportFailure = false } = {}) {
    this.assertCredentials();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const url = new URL(`${this.baseUrl}${path}`);
      for (const [key, value] of Object.entries(query || {})) {
        if (value !== undefined && value !== null && value !== '') url.searchParams.set(key, String(value));
      }
      const options = {
        method,
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${this.token}`,
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
          ...headers,
        },
        signal: controller.signal,
      };
      if (body !== undefined) options.body = JSON.stringify(body);
      const response = await this.fetchImpl(url.toString(), options);
      let data;
      try {
        data = await response.json();
      } catch (cause) {
        throw new WorkstationAutomationError('Workstation automation returned non-JSON', {
          status: response.status,
          retryable: response.status >= 500 || (response.ok && outcomeUnknownOnTransportFailure),
          outcomeUnknown: response.ok && outcomeUnknownOnTransportFailure,
          cause,
        });
      }
      if (!response.ok) {
        const code = normalizeErrorCode(data?.error);
        throw new WorkstationAutomationError(`Workstation automation request failed (HTTP ${response.status})`, {
          status: response.status,
          code,
          retryable: response.status >= 500,
        });
      }
      return data;
    } catch (error) {
      if (error instanceof WorkstationAutomationError) throw error;
      if (error?.name === 'AbortError') {
        throw new WorkstationAutomationError('Workstation automation request timed out', {
          retryable: true,
          outcomeUnknown: outcomeUnknownOnTransportFailure,
          cause: error,
        });
      }
      throw new WorkstationAutomationError('Workstation automation request failed', {
        retryable: true,
        outcomeUnknown: outcomeUnknownOnTransportFailure,
        cause: error,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  async getAccountImportLines() {
    const result = await this.request('GET', '/api/v1/account-inventory/import-lines');
    if (
      !result ||
      typeof result !== 'object' ||
      !Number.isInteger(result.version) ||
      !Number.isInteger(result.source_version) ||
      typeof result.updated_at !== 'string' ||
      !Number.isInteger(result.count) ||
      !Array.isArray(result.import_lines) ||
      result.count !== result.import_lines.length ||
      result.import_lines.length > 10_000 ||
      result.import_lines.some((line) => typeof line !== 'string' || /[\r\n]/.test(line))
    ) {
      throw new WorkstationAutomationError('Workstation automation returned an invalid account inventory');
    }
    return {
      version: result.version,
      sourceVersion: result.source_version,
      updatedAt: result.updated_at,
      count: result.count,
      importLines: result.import_lines,
    };
  }

  async getBanPool() {
    const result = await this.request('GET', '/api/v1/account-inventory/ban-pool');
    if (
      !result ||
      typeof result !== 'object' ||
      result.version !== 2 ||
      typeof result.updated_at !== 'string' ||
      !Number.isInteger(result.count) ||
      !Number.isInteger(result.banned_count) ||
      !Number.isInteger(result.banned_replaced_count) ||
      !Number.isInteger(result.pending_replacement_count) ||
      !Array.isArray(result.accounts) ||
      result.count !== result.accounts.length ||
      result.banned_count + result.banned_replaced_count !== result.count ||
      result.pending_replacement_count !== result.banned_count
    ) {
      throw new WorkstationAutomationError('Workstation automation returned an invalid ban pool');
    }
    const accounts = result.accounts.map(normalizeBanAccount);
    const actualBannedCount = accounts.filter((account) => account.status === 'banned').length;
    const actualReplacedCount = accounts.filter((account) => account.status === 'banned_replaced').length;
    if (
      result.banned_count !== actualBannedCount ||
      result.banned_replaced_count !== actualReplacedCount
    ) {
      throw new WorkstationAutomationError('Workstation automation returned an invalid ban pool');
    }
    return {
      version: result.version,
      updatedAt: result.updated_at,
      count: result.count,
      bannedCount: result.banned_count,
      bannedReplacedCount: result.banned_replaced_count,
      pendingReplacementCount: result.pending_replacement_count,
      accounts,
    };
  }

  async banAndReplaceAccount({ account, idempotencyKey } = {}) {
    const selector = String(account || '').trim();
    if (!selector || /[\r\n]/.test(selector) || selector.length > 4096) {
      throw new TypeError('account must be an exact email or import line');
    }
    const key = normalizeIdempotencyKey(idempotencyKey);
    const result = await this.request('POST', '/api/v1/account-inventory/ban-and-replace', {
      body: { account: selector },
      headers: { 'idempotency-key': key },
      outcomeUnknownOnTransportFailure: true,
    });
    if (
      !result ||
      typeof result !== 'object' ||
      result.version !== 2 ||
      typeof result.updated_at !== 'string' ||
      typeof result.replayed !== 'boolean'
    ) {
      throw new WorkstationAutomationError('Workstation automation returned an invalid account replacement', {
        retryable: true,
        outcomeUnknown: true,
      });
    }
    let bannedAccount;
    try {
      bannedAccount = normalizeBanAccount(result.banned_account);
    } catch (cause) {
      throw new WorkstationAutomationError('Workstation automation returned an invalid account replacement', {
        retryable: true,
        outcomeUnknown: true,
        cause,
      });
    }
    if (bannedAccount.status !== 'banned') {
      throw new WorkstationAutomationError('Workstation automation returned an invalid account replacement', {
        retryable: true,
        outcomeUnknown: true,
      });
    }
    return {
      version: result.version,
      updatedAt: result.updated_at,
      replayed: result.replayed,
      bannedAccount,
    };
  }

  async extractPendingReplacements({ idempotencyKey, consume } = {}) {
    const key = normalizeIdempotencyKey(idempotencyKey);
    if (typeof consume !== 'function') {
      throw new TypeError('consume callback is required for secret-bearing replacement batches');
    }
    const result = await this.request('POST', '/api/v1/account-inventory/ban-pool/extract-pending-replacements', {
      headers: { 'idempotency-key': key },
      outcomeUnknownOnTransportFailure: true,
    });
    if (
      !result ||
      typeof result !== 'object' ||
      result.version !== 2 ||
      typeof result.updated_at !== 'string' ||
      typeof result.replayed !== 'boolean' ||
      !BATCH_ID_PATTERN.test(String(result.batch_id || '')) ||
      typeof result.extracted_at !== 'string' ||
      !Number.isInteger(result.count) ||
      !Array.isArray(result.accounts) ||
      result.count !== result.accounts.length
    ) {
      throw new WorkstationAutomationError('Workstation automation returned an invalid replacement batch', {
        retryable: true,
        outcomeUnknown: true,
      });
    }
    let accounts;
    try {
      accounts = result.accounts.map(normalizeBanAccount);
    } catch (cause) {
      throw new WorkstationAutomationError('Workstation automation returned an invalid replacement batch', {
        retryable: true,
        outcomeUnknown: true,
        cause,
      });
    }
    if (accounts.some((account) => account.status !== 'banned_replaced')) {
      throw new WorkstationAutomationError('Workstation automation returned an invalid replacement batch', {
        retryable: true,
        outcomeUnknown: true,
      });
    }
    try {
      await consume({
        version: result.version,
        updatedAt: result.updated_at,
        replayed: result.replayed,
        batchId: result.batch_id,
        extractedAt: result.extracted_at,
        count: result.count,
        accounts: result.accounts,
      });
    } catch (cause) {
      throw new WorkstationAutomationError('Private replacement batch consumer failed', {
        retryable: true,
        outcomeUnknown: true,
        cause,
      });
    }
    return {
      version: result.version,
      updatedAt: result.updated_at,
      replayed: result.replayed,
      batchId: result.batch_id,
      extractedAt: result.extracted_at,
      count: result.count,
      accounts,
    };
  }

  async markBanRecordReplaced(banId) {
    const id = String(banId || '').trim();
    if (!BAN_ID_PATTERN.test(id)) throw new TypeError('banId is invalid');
    const result = await this.request('PATCH', `/api/v1/account-inventory/ban-pool/${encodeURIComponent(id)}`, {
      body: { status: 'banned_replaced' },
      outcomeUnknownOnTransportFailure: true,
    });
    if (
      !result ||
      typeof result !== 'object' ||
      result.version !== 2 ||
      typeof result.updated_at !== 'string' ||
      typeof result.already_banned_replaced !== 'boolean'
    ) {
      throw new WorkstationAutomationError('Workstation automation returned an invalid ban record update', {
        retryable: true,
        outcomeUnknown: true,
      });
    }
    let bannedAccount;
    try {
      bannedAccount = normalizeBanAccount(result.banned_account);
    } catch (cause) {
      throw new WorkstationAutomationError('Workstation automation returned an invalid ban record update', {
        retryable: true,
        outcomeUnknown: true,
        cause,
      });
    }
    if (bannedAccount.status !== 'banned_replaced') {
      throw new WorkstationAutomationError('Workstation automation returned an invalid ban record update', {
        retryable: true,
        outcomeUnknown: true,
      });
    }
    return {
      version: result.version,
      updatedAt: result.updated_at,
      alreadyBannedReplaced: result.already_banned_replaced,
      bannedAccount,
    };
  }

  async getEligiblePhones({ minAgeMinutes = DEFAULT_MIN_AGE_MINUTES, limit = 1 } = {}) {
    const age = normalizeInteger(minAgeMinutes, {
      name: 'minAgeMinutes',
      minimum: 0,
      maximum: 10_080,
      defaultValue: DEFAULT_MIN_AGE_MINUTES,
    });
    const requestedLimit = normalizeInteger(limit, { name: 'limit', minimum: 1, maximum: 100, defaultValue: 1 });
    const result = await this.request('GET', '/api/v1/phone-inventory/eligible', {
      query: { min_age_minutes: age, limit: requestedLimit },
    });
    if (
      !result ||
      typeof result !== 'object' ||
      !Number.isInteger(result.count) ||
      !Array.isArray(result.phones) ||
      result.count !== result.phones.length ||
      result.phones.length > requestedLimit
    ) {
      throw new WorkstationAutomationError('Workstation automation returned an invalid eligible-phone response');
    }
    return result.phones.map(normalizePhone);
  }

  async claimPhone({ idempotencyKey, minAgeMinutes = DEFAULT_MIN_AGE_MINUTES } = {}) {
    const key = normalizeIdempotencyKey(idempotencyKey);
    const age = normalizeInteger(minAgeMinutes, {
      name: 'minAgeMinutes',
      minimum: 0,
      maximum: 10_080,
      defaultValue: DEFAULT_MIN_AGE_MINUTES,
    });
    const result = await this.request('POST', '/api/v1/phone-inventory/claim', {
      body: { min_age_minutes: age },
      headers: { 'idempotency-key': key },
      outcomeUnknownOnTransportFailure: true,
    });
    if (
      !result ||
      typeof result !== 'object' ||
      typeof result.claimed_at !== 'string' ||
      typeof result.replayed !== 'boolean'
    ) {
      throw new WorkstationAutomationError('Workstation automation returned an invalid phone claim', {
        retryable: true,
        outcomeUnknown: true,
      });
    }
    let phone;
    try {
      phone = normalizePhone(result.phone);
    } catch (cause) {
      throw new WorkstationAutomationError('Workstation automation returned an invalid phone claim', {
        retryable: true,
        outcomeUnknown: true,
        cause,
      });
    }
    return {
      claimedAt: result.claimed_at,
      replayed: result.replayed,
      phone,
    };
  }

  async updatePhone(phoneId, { bindingCount, unavailable } = {}) {
    const id = String(phoneId || '').trim();
    if (!PHONE_ID_PATTERN.test(id)) throw new TypeError('phoneId is invalid');
    const hasBindingCount = bindingCount !== undefined;
    const hasUnavailable = unavailable !== undefined;
    if (!hasBindingCount && !hasUnavailable) throw new TypeError('bindingCount or unavailable is required');
    if (hasBindingCount && (!Number.isInteger(bindingCount) || bindingCount < 0 || bindingCount > 3)) {
      throw new TypeError('bindingCount must be an integer from 0 to 3');
    }
    if (hasUnavailable && typeof unavailable !== 'boolean') throw new TypeError('unavailable must be a boolean');
    const body = {};
    if (hasBindingCount) body.binding_count = bindingCount;
    if (hasUnavailable) body.unavailable = unavailable;
    const result = await this.request('PATCH', `/api/v1/phone-inventory/${encodeURIComponent(id)}`, {
      body,
    });
    if (!result || typeof result !== 'object' || typeof result.updated_at !== 'string') {
      throw new WorkstationAutomationError('Workstation automation returned an invalid phone update');
    }
    return { updatedAt: result.updated_at, phone: normalizePhone(result.phone) };
  }

  async setPhoneUnavailable(phoneId, unavailable = true) {
    return this.updatePhone(phoneId, { unavailable: Boolean(unavailable) });
  }
}

module.exports = {
  DEFAULT_MIN_AGE_MINUTES,
  DEFAULT_WORKSTATION_BASE_URL,
  BATCH_ID_PATTERN,
  BAN_ID_PATTERN,
  IDEMPOTENCY_KEY_PATTERN,
  WorkstationAutomationClient,
  WorkstationAutomationError,
  generateAccountReplacementKey,
  generatePhoneClaimKey,
  normalizeBanAccount,
  normalizeIdempotencyKey,
  normalizePhone,
};
