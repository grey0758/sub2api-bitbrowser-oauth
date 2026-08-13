'use strict';

const crypto = require('node:crypto');

const DEFAULT_WORKSTATION_BASE_URL = 'https://workstation.opencodex.uk';
const DEFAULT_MIN_AGE_MINUTES = 45;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]{16,128}$/;
const PHONE_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

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
    const key = String(idempotencyKey || '').trim();
    if (!IDEMPOTENCY_KEY_PATTERN.test(key)) {
      throw new TypeError('idempotencyKey must be 16 to 128 supported characters');
    }
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

  async setPhoneUnavailable(phoneId, unavailable = true) {
    const id = String(phoneId || '').trim();
    if (!PHONE_ID_PATTERN.test(id)) throw new TypeError('phoneId is invalid');
    const result = await this.request('PATCH', `/api/v1/phone-inventory/${encodeURIComponent(id)}`, {
      body: { unavailable: Boolean(unavailable) },
    });
    if (!result || typeof result !== 'object' || typeof result.updated_at !== 'string') {
      throw new WorkstationAutomationError('Workstation automation returned an invalid phone update');
    }
    return { updatedAt: result.updated_at, phone: normalizePhone(result.phone) };
  }
}

module.exports = {
  DEFAULT_MIN_AGE_MINUTES,
  DEFAULT_WORKSTATION_BASE_URL,
  IDEMPOTENCY_KEY_PATTERN,
  WorkstationAutomationClient,
  WorkstationAutomationError,
  generatePhoneClaimKey,
  normalizePhone,
};
