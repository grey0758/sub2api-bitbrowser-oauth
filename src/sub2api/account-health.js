'use strict';

const crypto = require('node:crypto');
const { accountEmailCandidates } = require('./admin-client');

function classifyAccountError(message) {
  const text = String(message || '').toLowerCase();
  if (/banned|ban|deactivat|suspend|terminat|blocked|disabled/.test(text)) return 'provider_banned_or_disabled';
  if (/revoked|invalidated|oauth token|token/.test(text)) return 'oauth_token_invalid_or_revoked';
  if (/401|authentication failed|unauthoriz/.test(text)) return 'authentication_failed';
  if (/429|rate.?limit|quota/.test(text)) return 'rate_limited_or_quota';
  return 'other_error';
}

function accountHealthErrorMessage(account) {
  return [
    account?.error_message,
    account?.error,
    account?.last_error,
    account?.credentials?.error,
    account?.extra?.error,
  ].find((value) => typeof value === 'string' && value.trim()) || '';
}

function accountHealthRecord(account, poolEmails, previousEntries = new Map()) {
  const emails = accountEmailCandidates(account).map((value) => value.trim().toLowerCase());
  const errorMessage = accountHealthErrorMessage(account);
  const status = String(account?.status || account?.state || 'unknown').slice(0, 32);
  const previous = previousEntries.get(String(account?.id || ''));
  return {
    accountId: String(account?.id || '').slice(0, 128),
    email: emails[0] || '',
    status,
    category: status === 'error' ? classifyAccountError(errorMessage) : 'healthy',
    hasPoolLogin: emails.some((email) => poolEmails.has(email)),
    errorFingerprint: errorMessage
      ? crypto.createHash('sha256').update(errorMessage).digest('hex')
      : '',
    outcome: typeof previous?.outcome === 'string' && previous.outcome.trim()
      ? previous.outcome
      : 'pending',
    ...(previous?.outcomeAt ? { outcomeAt: previous.outcomeAt } : {}),
    ...(previous?.outcomeCode ? { outcomeCode: previous.outcomeCode } : {}),
    auditedAt: Date.now(),
  };
}

function buildAccountHealthAudit(accounts, poolAccounts, previousAudit = null) {
  const poolEmails = new Set(poolAccounts.map((account) => String(account.email || '').trim().toLowerCase()));
  const previousEntries = new Map(
    Array.isArray(previousAudit?.entries)
      ? previousAudit.entries.map((entry) => [String(entry.accountId || ''), entry])
      : []
  );
  const entries = accounts
    .filter((account) => account?.platform === 'openai')
    .map((account) => accountHealthRecord(account, poolEmails, previousEntries));
  return {
    version: 1,
    generatedAt: Date.now(),
    entries,
  };
}

module.exports = {
  accountHealthErrorMessage,
  accountHealthRecord,
  buildAccountHealthAudit,
  classifyAccountError,
};
