'use strict';

const fs = require('node:fs');
const path = require('node:path');

const ALLOWED_KEYS = new Set([
  'SUB2API_ADMIN_API_KEY',
  'SUB2API_ADMIN_TOKEN',
  'SUB2API_ADMIN_COOKIE',
  'SUB2API_BASE_URL',
  'SUB2API_API_PREFIX',
]);

function parseRuntimeEnv(content) {
  const values = {};
  for (const rawLine of String(content).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator <= 0) throw new Error('Invalid runtime environment line');
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (!ALLOWED_KEYS.has(key)) throw new Error(`Unsupported runtime environment key: ${key}`);
    if (!value) throw new Error(`Runtime environment value is empty: ${key}`);
    values[key] = value;
  }
  return values;
}

function loadRuntimeEnv({ file = process.env.SUB2API_RUNTIME_ENV_FILE || path.resolve(__dirname, '..', '.runtime', 'admin.env'), env = process.env } = {}) {
  if (!fs.existsSync(file)) return { loaded: false, file, keys: [] };
  const stat = fs.statSync(file);
  if (!stat.isFile()) throw new Error('Sub2API runtime environment path is not a file');
  if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
    throw new Error('Sub2API runtime environment file must not be accessible by group or others');
  }
  const values = parseRuntimeEnv(fs.readFileSync(file, 'utf8'));
  for (const [key, value] of Object.entries(values)) {
    if (!env[key]) env[key] = value;
  }
  return { loaded: true, file, keys: Object.keys(values) };
}

module.exports = { ALLOWED_KEYS, loadRuntimeEnv, parseRuntimeEnv };
