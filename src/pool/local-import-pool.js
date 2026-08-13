'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const {
  generateTotp,
  normalizeTotpSecret,
  normalizeUsPhoneNumber,
} = require('../oauth/account-import');

const POOL_VERSION = 1;
const PHONE_COOLDOWN_MS = 45 * 60_000;
const DEFAULT_POOL_FILE = path.resolve(__dirname, '..', '..', '.runtime', 'import-pool.dpapi');
const DPAPI_PREFIX = 'dpapi-v1:';

class LocalImportPoolError extends Error {
  constructor(message, { code, cause } = {}) {
    super(message);
    this.name = 'LocalImportPoolError';
    this.code = code;
    this.cause = cause;
  }
}

function emptySnapshot() {
  return { version: POOL_VERSION, phones: [], accounts: [], accountHealthAudit: null };
}

function restrictedPowerShellEnv() {
  const systemRoot = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows';
  return {
    APPDATA: process.env.APPDATA || '',
    LOCALAPPDATA: process.env.LOCALAPPDATA || '',
    SystemRoot: systemRoot,
    TEMP: process.env.TEMP || '',
    TMP: process.env.TMP || '',
    USERPROFILE: process.env.USERPROFILE || '',
    WINDIR: systemRoot,
  };
}

function runPowerShell(command, input, { spawnImpl = spawn, timeoutMs = 15_000 } = {}) {
  if (process.platform !== 'win32') {
    throw new LocalImportPoolError('Local import pool encryption requires Windows DPAPI', {
      code: 'dpapi_unavailable',
    });
  }
  const env = restrictedPowerShellEnv();
  const executable = path.win32.join(
    env.SystemRoot,
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe'
  );
  return new Promise((resolve, reject) => {
    const child = spawnImpl(
      executable,
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command],
      { env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true }
    );
    let stdout = '';
    let stderrBytes = 0;
    let settled = false;
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      if (stdout.length > 8 * 1024 * 1024) child.kill();
    });
    child.stderr.on('data', (chunk) => { stderrBytes += chunk.length; });
    child.on('error', (cause) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new LocalImportPoolError('Windows DPAPI process failed to start', {
        code: 'dpapi_process_failed',
        cause,
      }));
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0 || stderrBytes > 0) {
        reject(new LocalImportPoolError('Windows DPAPI operation failed', {
          code: 'dpapi_operation_failed',
        }));
        return;
      }
      resolve(stdout);
    });
    child.stdin.end(input, 'utf8');
  });
}

async function protectData(plainText, options) {
  const command = [
    'Add-Type -AssemblyName System.Security',
    '$plainText = [Console]::In.ReadToEnd()',
    '$plainBytes = [Text.Encoding]::UTF8.GetBytes($plainText)',
    '$protected = [Security.Cryptography.ProtectedData]::Protect($plainBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)',
    '[Console]::Out.Write([Convert]::ToBase64String($protected))',
  ].join('; ');
  return runPowerShell(command, plainText, options);
}

async function unprotectData(cipherText, options) {
  const command = [
    'Add-Type -AssemblyName System.Security',
    '$cipherText = [Console]::In.ReadToEnd()',
    '$protected = [Convert]::FromBase64String($cipherText)',
    '$plainBytes = [Security.Cryptography.ProtectedData]::Unprotect($protected, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)',
    '[Console]::Out.Write([Text.Encoding]::UTF8.GetString($plainBytes))',
  ].join('; ');
  return runPowerShell(command, cipherText, options);
}

function parsePhonePoolSource(source) {
  const phones = [];
  const issues = [];
  const seen = new Set();
  String(source || '').split(/\r?\n/).forEach((rawLine, index) => {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) return;
    const separator = line.indexOf('|');
    if (separator <= 0) {
      issues.push({ line: index + 1, reason: 'format' });
      return;
    }
    try {
      const phone = normalizeUsPhoneNumber(line.slice(0, separator));
      const smsAccessUrl = new URL(line.slice(separator + 1).trim());
      if (smsAccessUrl.protocol !== 'https:') throw new Error('https_required');
      const identity = `${phone}\u0000${smsAccessUrl.href}`;
      if (seen.has(identity)) return;
      seen.add(identity);
      phones.push({ phone, smsAccessUrl: smsAccessUrl.href, allowResend: false });
    } catch {
      issues.push({ line: index + 1, reason: 'invalid_phone_or_url' });
    }
  });
  return { phones, issues };
}

function parseAccountPoolSource(source) {
  const accounts = [];
  const issues = [];
  const seen = new Set();
  String(source || '').split(/\r?\n/).forEach((rawLine, index) => {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) return;
    const firstSeparator = line.indexOf('|');
    const lastSeparator = line.lastIndexOf('|');
    if (firstSeparator <= 0 || lastSeparator <= firstSeparator) {
      issues.push({ line: index + 1, reason: 'format' });
      return;
    }
    const email = line.slice(0, firstSeparator).trim();
    const password = line.slice(firstSeparator + 1, lastSeparator);
    const totpSecret = normalizeTotpSecret(line.slice(lastSeparator + 1));
    try {
      if (!/^[^\s@]+@[^\s@]+$/.test(email) || !password || !totpSecret) throw new Error('invalid_fields');
      generateTotp(totpSecret, 59_000);
      const identity = email.toLowerCase();
      if (seen.has(identity)) return;
      seen.add(identity);
      accounts.push({ email, password, totpSecret });
    } catch {
      issues.push({ line: index + 1, reason: 'invalid_account' });
    }
  });
  return { accounts, issues };
}

function normalizeSnapshot(value) {
  if (
    !value ||
    typeof value !== 'object' ||
    value.version !== POOL_VERSION ||
    !Array.isArray(value.phones) ||
    !Array.isArray(value.accounts) ||
    value.phones.length > 10_000 ||
    value.accounts.length > 10_000
  ) {
    throw new LocalImportPoolError('Local import pool is invalid', { code: 'pool_invalid' });
  }
  for (const phone of value.phones) {
    if (
      typeof phone?.id !== 'string' ||
      !/^\d{10}$/.test(phone.phone) ||
      typeof phone.smsAccessUrl !== 'string' ||
      !['available', 'invalid'].includes(phone.status) ||
      ![true, false].includes(phone.allowResend) ||
      (phone.lastUsedAt !== null && !Number.isFinite(phone.lastUsedAt))
    ) throw new LocalImportPoolError('Local import pool is invalid', { code: 'pool_invalid' });
  }
  for (const account of value.accounts) {
    if (
      typeof account?.id !== 'string' ||
      typeof account.email !== 'string' ||
      typeof account.password !== 'string' ||
      typeof account.totpSecret !== 'string' ||
      !['pending', 'imported'].includes(account.status) ||
      !Number.isInteger(account.attempts) ||
      (account.nextAttemptAt !== undefined && account.nextAttemptAt !== null && !Number.isFinite(account.nextAttemptAt))
    ) throw new LocalImportPoolError('Local import pool is invalid', { code: 'pool_invalid' });
    const claim = account.phoneClaim;
    if (claim !== undefined && claim !== null && (
      typeof claim !== 'object' ||
      !['pending', 'claimed', 'invalid'].includes(claim.status) ||
      typeof claim.idempotencyKey !== 'string' ||
      (claim.status === 'claimed' && (
        typeof claim.phoneId !== 'string' ||
        typeof claim.phoneNumber !== 'string' ||
        typeof claim.claimedAt !== 'string'
      ))
    )) throw new LocalImportPoolError('Local import pool is invalid', { code: 'pool_invalid' });
  }
  if (value.accountHealthAudit !== undefined && value.accountHealthAudit !== null) {
    if (
      typeof value.accountHealthAudit !== 'object' ||
      value.accountHealthAudit.version !== 1 ||
      !Array.isArray(value.accountHealthAudit.entries) ||
      value.accountHealthAudit.entries.length > 10_000
    ) throw new LocalImportPoolError('Local import pool is invalid', { code: 'pool_invalid' });
    for (const entry of value.accountHealthAudit.entries) {
      if (
        typeof entry?.accountId !== 'string' ||
        typeof entry.email !== 'string' ||
        typeof entry.status !== 'string' ||
        typeof entry.category !== 'string' ||
        typeof entry.hasPoolLogin !== 'boolean' ||
        typeof entry.outcome !== 'string'
      ) throw new LocalImportPoolError('Local import pool is invalid', { code: 'pool_invalid' });
    }
  }
  return value;
}

class LocalImportPoolStore {
  constructor({
    file = DEFAULT_POOL_FILE,
    protect = protectData,
    unprotect = unprotectData,
    now = () => Date.now(),
  } = {}) {
    this.file = file;
    this.protect = protect;
    this.unprotect = unprotect;
    this.now = now;
  }

  async load() {
    if (!fs.existsSync(this.file)) return emptySnapshot();
    const stored = await fs.promises.readFile(this.file, 'utf8');
    if (!stored.startsWith(DPAPI_PREFIX)) {
      throw new LocalImportPoolError('Local import pool is not DPAPI encrypted', {
        code: 'pool_not_encrypted',
      });
    }
    try {
      const plainText = await this.unprotect(stored.slice(DPAPI_PREFIX.length));
      return normalizeSnapshot(JSON.parse(plainText));
    } catch (cause) {
      if (cause instanceof LocalImportPoolError) throw cause;
      throw new LocalImportPoolError('Local import pool could not be decrypted', {
        code: 'pool_decrypt_failed',
        cause,
      });
    }
  }

  async save(snapshot) {
    const normalized = normalizeSnapshot(snapshot);
    const encrypted = await this.protect(JSON.stringify(normalized));
    const directory = path.dirname(this.file);
    await fs.promises.mkdir(directory, { recursive: true });
    const temporary = `${this.file}.${process.pid}.${crypto.randomUUID()}.tmp`;
    try {
      await fs.promises.writeFile(temporary, `${DPAPI_PREFIX}${encrypted}`, {
        encoding: 'utf8',
        mode: 0o600,
      });
      await fs.promises.rename(temporary, this.file);
      await fs.promises.chmod(this.file, 0o600).catch(() => {});
    } finally {
      await fs.promises.unlink(temporary).catch(() => {});
    }
  }

  async importPhones(source) {
    const parsed = parsePhonePoolSource(source);
    const snapshot = await this.load();
    const identities = new Set(snapshot.phones.map((item) => `${item.phone}\u0000${item.smsAccessUrl}`));
    let added = 0;
    for (const phone of parsed.phones) {
      const identity = `${phone.phone}\u0000${phone.smsAccessUrl}`;
      if (identities.has(identity)) continue;
      identities.add(identity);
      snapshot.phones.push({
        id: crypto.randomUUID(),
        ...phone,
        status: 'available',
        lastUsedAt: null,
        invalidAt: null,
      });
      added += 1;
    }
    await this.save(snapshot);
    return { added, rejected: parsed.issues.length, total: snapshot.phones.length };
  }

  async importAccounts(source) {
    const parsed = parseAccountPoolSource(source);
    const snapshot = await this.load();
    const identities = new Set(snapshot.accounts.map((item) => item.email.toLowerCase()));
    let added = 0;
    for (const account of parsed.accounts) {
      const identity = account.email.toLowerCase();
      if (identities.has(identity)) continue;
      identities.add(identity);
      snapshot.accounts.push({
        id: crypto.randomUUID(),
        ...account,
        status: 'pending',
        attempts: 0,
        lastAttemptAt: null,
        lastOutcome: '',
        importedAt: null,
      });
      added += 1;
    }
    await this.save(snapshot);
    return { added, rejected: parsed.issues.length, total: snapshot.accounts.length };
  }

  async syncInventoryAccounts({ importLines, sourceVersion, updatedAt } = {}) {
    if (!Array.isArray(importLines)) {
      throw new LocalImportPoolError('Workstation account inventory is invalid', {
        code: 'inventory_accounts_invalid',
      });
    }
    const parsed = parseAccountPoolSource(importLines.join('\n'));
    if (parsed.issues.length > 0 || parsed.accounts.length !== importLines.length) {
      throw new LocalImportPoolError('Workstation account inventory is invalid', {
        code: 'inventory_accounts_invalid',
      });
    }
    return this.update((snapshot) => {
      const byEmail = new Map(snapshot.accounts.map((item) => [item.email.toLowerCase(), item]));
      for (const account of snapshot.accounts) {
        if (account.inventoryManaged) account.inventoryPresent = false;
      }
      let added = 0;
      let updated = 0;
      for (const account of parsed.accounts) {
        const identity = account.email.toLowerCase();
        const existing = byEmail.get(identity);
        if (existing) {
          existing.password = account.password;
          existing.totpSecret = account.totpSecret;
          existing.inventoryManaged = true;
          existing.inventoryPresent = true;
          existing.inventorySourceVersion = sourceVersion;
          updated += 1;
          continue;
        }
        const created = {
          id: crypto.randomUUID(),
          ...account,
          status: 'pending',
          attempts: 0,
          lastAttemptAt: null,
          lastOutcome: '',
          importedAt: null,
          inventoryManaged: true,
          inventoryPresent: true,
          inventorySourceVersion: sourceVersion,
        };
        snapshot.accounts.push(created);
        byEmail.set(identity, created);
        added += 1;
      }
      snapshot.workstationInventory = {
        sourceVersion,
        updatedAt,
        syncedAt: this.now(),
      };
      return { added, updated, total: snapshot.accounts.length, sourceVersion };
    });
  }

  async saveAccountHealthAudit(audit) {
    if (!audit || !Array.isArray(audit.entries)) {
      throw new LocalImportPoolError('Account health audit is invalid', { code: 'health_audit_invalid' });
    }
    return this.update((snapshot) => {
      snapshot.accountHealthAudit = {
        version: 1,
        generatedAt: Number.isFinite(audit.generatedAt) ? audit.generatedAt : this.now(),
        entries: audit.entries.map((entry) => ({ ...entry })),
      };
      return {
        total: snapshot.accountHealthAudit.entries.length,
        error: snapshot.accountHealthAudit.entries.filter((entry) => entry.status === 'error').length,
        poolLogin: snapshot.accountHealthAudit.entries.filter((entry) => entry.hasPoolLogin).length,
      };
    });
  }

  async updateAccountHealthOutcome(accountId, outcome, details = {}) {
    await this.update((snapshot) => {
      const entry = snapshot.accountHealthAudit?.entries?.find((item) => item.accountId === String(accountId));
      if (!entry) throw new LocalImportPoolError('Account health audit entry was not found', { code: 'health_entry_not_found' });
      entry.outcome = String(outcome || 'failed').slice(0, 64);
      entry.outcomeAt = this.now();
      if (details.code) entry.outcomeCode = String(details.code).slice(0, 64);
    });
  }

  async accountHealthSummary() {
    const snapshot = await this.load();
    const entries = snapshot.accountHealthAudit?.entries || [];
    const count = (predicate) => entries.filter(predicate).length;
    return {
      total: entries.length,
      error: count((entry) => entry.status === 'error'),
      active: count((entry) => entry.status === 'active'),
      poolLogin: count((entry) => entry.hasPoolLogin),
      banned: count((entry) => entry.outcome === 'account_banned' || entry.category === 'provider_banned_or_disabled'),
      reauthorized: count((entry) => entry.outcome === 'reauthorized'),
      pending: count((entry) => entry.outcome === 'pending'),
    };
  }

  async beginNextAccountAttempt({ inventoryOnly = false } = {}) {
    return this.update((snapshot) => {
      const now = this.now();
      const account = snapshot.accounts.find((item) => (
        item.status === 'pending' &&
        (!item.inventoryManaged || item.inventoryPresent !== false) &&
        (!inventoryOnly || (item.inventoryManaged && item.inventoryPresent === true)) &&
        (!Number.isFinite(item.nextAttemptAt) || item.nextAttemptAt <= now)
      ));
      if (!account) {
        throw new LocalImportPoolError('No pending local account is available', {
          code: 'no_pending_account',
        });
      }
      account.attempts += 1;
      account.lastAttemptAt = now;
      account.lastOutcome = 'in_progress';
      account.nextAttemptAt = null;
      return { ...account, phoneClaim: account.phoneClaim ? { ...account.phoneClaim } : null };
    });
  }

  async findPhoneMapping(value) {
    let expected;
    try { expected = normalizeUsPhoneNumber(value); } catch { return null; }
    const snapshot = await this.load();
    const phone = snapshot.phones.find((item) => item.status === 'available' && item.phone === expected);
    return phone ? { ...phone } : null;
  }

  async getAccountPhoneClaim(accountId) {
    const snapshot = await this.load();
    const account = snapshot.accounts.find((item) => item.id === accountId);
    if (!account) throw new LocalImportPoolError('Local account entry was not found', { code: 'account_not_found' });
    return account.phoneClaim ? { ...account.phoneClaim } : null;
  }

  async ensureAccountPhoneClaim(accountId, idempotencyKey) {
    return this.update((snapshot) => {
      const account = snapshot.accounts.find((item) => item.id === accountId);
      if (!account) throw new LocalImportPoolError('Local account entry was not found', { code: 'account_not_found' });
      if (account.phoneClaim && account.phoneClaim.status !== 'invalid') return { ...account.phoneClaim };
      account.phoneClaim = {
        status: 'pending',
        idempotencyKey,
        createdAt: this.now(),
      };
      return { ...account.phoneClaim };
    });
  }

  async recordAccountPhoneClaim(accountId, { idempotencyKey, phoneId, phoneNumber, claimedAt, replayed }) {
    return this.update((snapshot) => {
      const account = snapshot.accounts.find((item) => item.id === accountId);
      if (!account) throw new LocalImportPoolError('Local account entry was not found', { code: 'account_not_found' });
      if (!account.phoneClaim || account.phoneClaim.idempotencyKey !== idempotencyKey) {
        throw new LocalImportPoolError('Local phone claim state did not match the response', {
          code: 'phone_claim_state_mismatch',
        });
      }
      account.phoneClaim = {
        ...account.phoneClaim,
        status: 'claimed',
        phoneId,
        phoneNumber,
        claimedAt,
        replayed: Boolean(replayed),
      };
      return { ...account.phoneClaim };
    });
  }

  async abandonAccountPhoneClaim(accountId, reason = 'claim_rejected') {
    await this.update((snapshot) => {
      const account = snapshot.accounts.find((item) => item.id === accountId);
      if (!account) throw new LocalImportPoolError('Local account entry was not found', { code: 'account_not_found' });
      if (!account.phoneClaim || account.phoneClaim.status !== 'pending') return;
      account.phoneClaimHistory = Array.isArray(account.phoneClaimHistory)
        ? account.phoneClaimHistory.slice(-19)
        : [];
      account.phoneClaimHistory.push({
        idempotencyKey: account.phoneClaim.idempotencyKey,
        createdAt: account.phoneClaim.createdAt,
        abandonedAt: this.now(),
        reason: String(reason || 'claim_rejected').slice(0, 64),
      });
      account.phoneClaim = null;
    });
  }

  async markAccountPhoneClaimInvalid(accountId, reason = 'sms_unavailable') {
    await this.update((snapshot) => {
      const account = snapshot.accounts.find((item) => item.id === accountId);
      if (!account) throw new LocalImportPoolError('Local account entry was not found', { code: 'account_not_found' });
      if (!account.phoneClaim) return;
      account.phoneClaim.status = 'invalid';
      account.phoneClaim.invalidAt = this.now();
      account.phoneClaim.invalidReason = String(reason || 'sms_unavailable').slice(0, 64);
      account.phoneClaim.remoteUnavailableSynced = false;
    });
  }

  async markAccountPhoneClaimUnavailableSynced(accountId) {
    await this.update((snapshot) => {
      const account = snapshot.accounts.find((item) => item.id === accountId);
      if (!account) throw new LocalImportPoolError('Local account entry was not found', { code: 'account_not_found' });
      if (!account.phoneClaim || account.phoneClaim.status !== 'invalid') return;
      account.phoneClaim.remoteUnavailableSynced = true;
      account.phoneClaim.remoteUnavailableSyncedAt = this.now();
    });
  }

  async beginNextAttempt() {
    const snapshot = await this.load();
    const now = this.now();
    const account = snapshot.accounts.find((item) => (
      item.status === 'pending' &&
      (!item.inventoryManaged || item.inventoryPresent !== false) &&
      (!Number.isFinite(item.nextAttemptAt) || item.nextAttemptAt <= now)
    ));
    if (!account) throw new LocalImportPoolError('No pending local account is available', { code: 'no_pending_account' });
    const phone = snapshot.phones.find((item) => (
      item.status === 'available' &&
      (item.lastUsedAt === null || now - item.lastUsedAt >= PHONE_COOLDOWN_MS)
    ));
    if (!phone) throw new LocalImportPoolError('No local phone is outside the 45-minute cooldown', { code: 'no_available_phone' });
    account.attempts += 1;
    account.lastAttemptAt = now;
    account.lastOutcome = 'in_progress';
    await this.save(snapshot);
    return { account: { ...account }, phone: { ...phone } };
  }

  async update(mutator) {
    const snapshot = await this.load();
    const result = await mutator(snapshot);
    await this.save(snapshot);
    return result;
  }

  async resetPhoneCooldowns() {
    return this.update((snapshot) => {
      const resetAt = this.now();
      let reset = 0;
      for (const phone of snapshot.phones) {
        if (phone.status !== 'available' || phone.lastUsedAt === null) continue;
        phone.lastCooldownResetPreviousUsedAt = phone.lastUsedAt;
        phone.lastCooldownResetAt = resetAt;
        phone.manualResetCount = Number.isInteger(phone.manualResetCount)
          ? phone.manualResetCount + 1
          : 1;
        phone.lastUsedAt = null;
        reset += 1;
      }
      return { reset, total: snapshot.phones.length };
    });
  }

  async correctInvalidPhoneToCooldown({ allowResend = true } = {}) {
    return this.update((snapshot) => {
      const phone = snapshot.phones.find((item) => item.status === 'invalid');
      if (!phone) {
        throw new LocalImportPoolError('No invalid local phone is available for correction', {
          code: 'no_invalid_phone',
        });
      }
      const correctedAt = this.now();
      phone.status = 'available';
      phone.lastUsedAt = correctedAt;
      phone.allowResend = Boolean(allowResend);
      phone.lastCorrectionAt = correctedAt;
      phone.lastCorrectionPreviousStatus = 'invalid';
      phone.correctionCount = Number.isInteger(phone.correctionCount)
        ? phone.correctionCount + 1
        : 1;
      phone.invalidAt = null;
      phone.invalidReason = '';
      return { corrected: 1, total: snapshot.phones.length };
    });
  }

  async setAvailablePhonesAllowResend(allowResend = true) {
    return this.update((snapshot) => {
      let updated = 0;
      for (const phone of snapshot.phones) {
        if (phone.status !== 'available' || phone.allowResend === Boolean(allowResend)) continue;
        phone.allowResend = Boolean(allowResend);
        phone.lastResendPolicyChangedAt = this.now();
        updated += 1;
      }
      return { updated, total: snapshot.phones.length, allowResend: Boolean(allowResend) };
    });
  }

  async markPhoneUsed(id) {
    await this.update((snapshot) => {
      const phone = snapshot.phones.find((item) => item.id === id);
      if (!phone) throw new LocalImportPoolError('Local phone entry was not found', { code: 'phone_not_found' });
      phone.lastUsedAt = this.now();
    });
  }

  async markPhoneInvalid(id, reason = 'sms_unavailable') {
    await this.update((snapshot) => {
      const phone = snapshot.phones.find((item) => item.id === id);
      if (!phone) throw new LocalImportPoolError('Local phone entry was not found', { code: 'phone_not_found' });
      phone.status = 'invalid';
      phone.invalidAt = this.now();
      phone.invalidReason = String(reason || 'sms_unavailable').slice(0, 64);
    });
  }

  async markAccountImported(id) {
    await this.update((snapshot) => {
      const account = snapshot.accounts.find((item) => item.id === id);
      if (!account) throw new LocalImportPoolError('Local account entry was not found', { code: 'account_not_found' });
      account.status = 'imported';
      account.importedAt = this.now();
      account.lastOutcome = 'imported';
      account.nextAttemptAt = null;
    });
  }

  async markAccountPending(id, outcome = 'failed', { retryAfterMs = 0 } = {}) {
    await this.update((snapshot) => {
      const account = snapshot.accounts.find((item) => item.id === id);
      if (!account) throw new LocalImportPoolError('Local account entry was not found', { code: 'account_not_found' });
      account.status = 'pending';
      account.lastOutcome = String(outcome || 'failed').slice(0, 64);
      account.nextAttemptAt = retryAfterMs > 0 ? this.now() + retryAfterMs : null;
    });
  }

  async summary() {
    const snapshot = await this.load();
    const now = this.now();
    return {
      phones: {
        total: snapshot.phones.length,
        available: snapshot.phones.filter((item) => (
          item.status === 'available' &&
          (item.lastUsedAt === null || now - item.lastUsedAt >= PHONE_COOLDOWN_MS)
        )).length,
        cooldown: snapshot.phones.filter((item) => (
          item.status === 'available' &&
          item.lastUsedAt !== null &&
          now - item.lastUsedAt < PHONE_COOLDOWN_MS
        )).length,
        invalid: snapshot.phones.filter((item) => item.status === 'invalid').length,
      },
      accounts: {
        total: snapshot.accounts.length,
        pending: snapshot.accounts.filter((item) => (
          item.status === 'pending' && (!item.inventoryManaged || item.inventoryPresent !== false)
        )).length,
        imported: snapshot.accounts.filter((item) => item.status === 'imported').length,
      },
    };
  }
}

module.exports = {
  DEFAULT_POOL_FILE,
  DPAPI_PREFIX,
  LocalImportPoolError,
  LocalImportPoolStore,
  PHONE_COOLDOWN_MS,
  POOL_VERSION,
  emptySnapshot,
  parseAccountPoolSource,
  parsePhonePoolSource,
  protectData,
  restrictedPowerShellEnv,
  unprotectData,
};
