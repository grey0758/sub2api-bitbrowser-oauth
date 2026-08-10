#!/usr/bin/env node
'use strict';

const { FixedWindowController } = require('../src/bitbrowser/window-controller');
const { Sub2ApiAdminClient, Sub2ApiError } = require('../src/sub2api/admin-client');
const { OAuthFlow } = require('../src/oauth/flow');

function parseArgs(argv) {
  const args = { command: argv[0] && !['--help', '-h'].includes(argv[0]) ? argv[0] : 'start' };
  if (argv[0] === '--help' || argv[0] === '-h') args.help = true;
  for (let i = 1; i < argv.length; i += 1) {
    const item = argv[i];
    if (item === '--proxy-id') args.proxyId = argv[++i];
    else if (item === '--timeout-ms') args.timeoutMs = Number(argv[++i]);
    else if (item === '--close-window') args.closeWindow = true;
    else if (item === '--help' || item === '-h') args.help = true;
    else throw new Error(`Unknown argument: ${item}`);
  }
  return args;
}

function usage() {
  return [
    'Usage:',
    '  node bin/sub2api-bitbrowser-oauth.js check',
    '  node bin/sub2api-bitbrowser-oauth.js start [--proxy-id ID]',
    '  node bin/sub2api-bitbrowser-oauth.js run [--proxy-id ID] [--timeout-ms N]',
    '',
    'start generates the Sub2API OpenAI OAuth URL, opens it in the exact',
    'BitBrowser window us001_codex (or BITBROWSER_WINDOW_NAME), then disconnects',
    'without closing or deleting the named window.',
    'run additionally waits for localhost:1455/auth/callback and exchanges it.',
    '',
    'Credentials are runtime-only: SUB2API_ADMIN_TOKEN, SUB2API_ADMIN_API_KEY,',
    'or SUB2API_ADMIN_COOKIE. They are never read from repository files.',
  ].join('\n');
}

function safeError(error) {
  if (error instanceof Sub2ApiError) {
    if (error.status === 401 || error.status === 403) return 'Sub2API administrator authentication failed';
    if (error.status) return `Sub2API administrator request failed (HTTP ${error.status})`;
    return 'Sub2API administrator request failed';
  }
  return error?.message || String(error);
}

async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.help) { console.log(usage()); return; }
  const browser = new FixedWindowController();
  if (args.command === 'check') {
    const window = await browser.findExact();
    console.log(`BitBrowser window matched: ${window.name} (status=${window.status})`);
    return;
  }

  const flow = new OAuthFlow({ sub2api: new Sub2ApiAdminClient(), browser });
  if (args.command === 'start') {
    const started = await flow.start({ proxyId: args.proxyId });
    await flow.release({ closeWindow: Boolean(args.closeWindow) });
    console.log(`OpenAI OAuth URL generated and opened in ${started.session.window.name}.`);
    console.log('The authorization URL is intentionally not printed; complete login in that window.');
    return;
  }
  if (args.command === 'run') {
    await flow.run({ proxyId: args.proxyId, timeoutMs: args.timeoutMs || 10 * 60_000 });
    console.log('OpenAI OAuth callback exchanged through Sub2API administrator API.');
    return;
  }
  throw new Error(`Unknown command: ${args.command}\n\n${usage()}`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`sub2api-bitbrowser-oauth: ${safeError(error)}`);
    process.exitCode = 1;
  });
}

module.exports = { main, parseArgs, safeError, usage };
