import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  createPackyApp,
  createTrustedProxyMatcher,
  normalizeIp,
  resolveRequestIdentity
} from './packy-usage-server.mjs';

const KEY_A = `sk-${'a'.repeat(32)}`;
const KEY_B = `sk-${'b'.repeat(32)}`;
const EMPTY_STATIC = { my: Buffer.from('my'), leaderboard: Buffer.from('leaderboard'), css: Buffer.from('css') };

function packyData(name, used, remaining = 100) {
  return {
    name,
    total_used: used * 500000,
    total_available: remaining * 500000,
    unlimited_quota: false,
    quota_reset_period: 'monthly',
    quota_period_start: 1700000000,
    expires_at: 1800000000
  };
}

async function createFixture({ provider, startTime = 1_800_000_000_000 } = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'packy-usage-test-'));
  let currentTime = startTime;
  const databasePath = join(directory, 'usage.sqlite');
  const app = createPackyApp({
    databasePath,
    masterKey: Buffer.alloc(32, 7),
    refreshSeconds: 120,
    trustedProxyCidrs: ['127.0.0.1', '::1'],
    usageProvider: provider,
    nowMs: () => currentTime,
    staticFiles: EMPTY_STATIC
  });
  const server = createServer(app.handler);
  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  async function request(ip, path, { method = 'GET', body, secure = true } = {}) {
    const headers = { 'X-Forwarded-For': ip };
    if (secure) headers['X-Forwarded-Proto'] = 'https';
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetch(`${baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const text = await response.text();
    return { status: response.status, headers: response.headers, body: text ? JSON.parse(text) : null };
  }

  return {
    app,
    databasePath,
    request,
    advance(milliseconds) { currentTime += milliseconds; },
    async close() {
      await new Promise((resolveClose) => server.close(resolveClose));
      app.close();
      const resolvedDirectory = resolve(directory);
      assert.ok(resolvedDirectory.startsWith(resolve(tmpdir())));
      rmSync(resolvedDirectory, { recursive: true, force: true });
    }
  };
}

test('normalizes IPs and trusts forwarding headers only from configured proxies', () => {
  assert.equal(normalizeIp('::ffff:127.0.0.1'), '127.0.0.1');
  assert.equal(normalizeIp('FE80::1%12'), 'fe80::1');
  assert.equal(normalizeIp('not-an-ip'), '');

  const trustLocal = createTrustedProxyMatcher(['127.0.0.1', '10.0.0.0/8']);
  const spoofed = resolveRequestIdentity({
    socket: { remoteAddress: '198.51.100.20', encrypted: false },
    headers: { 'x-forwarded-for': '203.0.113.9', 'x-forwarded-proto': 'https' }
  }, trustLocal);
  assert.equal(spoofed.clientIp, '198.51.100.20');
  assert.equal(spoofed.secure, false);

  const proxied = resolveRequestIdentity({
    socket: { remoteAddress: '10.0.0.2', encrypted: false },
    headers: { 'x-forwarded-for': '198.51.100.30, 10.0.0.1', 'x-forwarded-proto': 'https' }
  }, trustLocal);
  assert.equal(proxied.clientIp, '198.51.100.30');
  assert.equal(proxied.secure, true);
});

test('supports multiple IPs and keys while keeping the public response minimal', async (t) => {
  const provider = async (key) => {
    if (key === KEY_A) return packyData('software-codex-A', 20, 180);
    if (key === KEY_B) return packyData('software-codex-B', 60, 140);
    throw new Error('invalid key');
  };
  const fixture = await createFixture({ provider });
  t.after(() => fixture.close());

  const first = await fixture.request('203.0.113.10', '/api/accounts/register', { method: 'POST', body: { key: KEY_A } });
  assert.equal(first.status, 201);
  const accountA = first.body.account.id;
  assert.equal(first.body.account.name, 'software-codex-A');

  const secondIp = await fixture.request('203.0.113.11', '/api/accounts/register', { method: 'POST', body: { key: KEY_A } });
  assert.equal(secondIp.status, 200);
  assert.equal(secondIp.body.account.id, accountA);

  const secondKey = await fixture.request('203.0.113.10', '/api/accounts/register', { method: 'POST', body: { key: KEY_B } });
  assert.equal(secondKey.status, 201);
  const accountB = secondKey.body.account.id;

  const health = await fixture.request('203.0.113.10', '/health');
  assert.deepEqual({ accounts: health.body.accounts, bindings: health.body.bindings }, { accounts: 2, bindings: 3 });

  const ipOne = await fixture.request('203.0.113.10', '/api/me');
  const ipTwo = await fixture.request('203.0.113.11', '/api/me');
  const unauthorized = await fixture.request('203.0.113.12', '/api/me');
  assert.equal(ipOne.body.accounts.length, 2);
  assert.equal(ipTwo.body.accounts.length, 1);
  assert.equal(unauthorized.body.accounts.length, 0);
  assert.ok(ipOne.body.accounts.every((account) => !('key' in account) && !('ip' in account)));

  const unauthorizedToggle = await fixture.request('203.0.113.12', `/api/me/accounts/${accountA}/leaderboard`, { method: 'PATCH', body: { enabled: true } });
  assert.equal(unauthorizedToggle.status, 404);

  const toggleA = await fixture.request('203.0.113.11', `/api/me/accounts/${accountA}/leaderboard`, { method: 'PATCH', body: { enabled: true } });
  const toggleB = await fixture.request('203.0.113.10', `/api/me/accounts/${accountB}/leaderboard`, { method: 'PATCH', body: { enabled: true } });
  assert.equal(toggleA.status, 200);
  assert.equal(toggleB.status, 200);

  const ipOneAfterToggle = await fixture.request('203.0.113.10', '/api/me');
  assert.equal(ipOneAfterToggle.body.accounts.find((account) => account.id === accountA).leaderboardEnabled, true);

  const leaderboard = await fixture.request('198.51.100.1', '/api/leaderboard');
  assert.deepEqual(leaderboard.body.accounts, [
    { name: 'software-codex-B', used: 60 },
    { name: 'software-codex-A', used: 20 }
  ]);
  assert.deepEqual(Object.keys(leaderboard.body.accounts[0]).sort(), ['name', 'used']);
  assert.ok(!JSON.stringify(leaderboard.body).includes(accountA));
  assert.ok(!JSON.stringify(leaderboard.body).includes('remaining'));

  fixture.app.store.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  const databaseBytes = readFileSync(fixture.databasePath);
  assert.equal(databaseBytes.includes(Buffer.from(KEY_A)), false);
  assert.equal(databaseBytes.includes(Buffer.from(KEY_B)), false);

  const unbindOne = await fixture.request('203.0.113.10', `/api/me/accounts/${accountA}/ip`, { method: 'DELETE' });
  assert.deepEqual({ deleted: unbindOne.body.deletedAccount, remaining: unbindOne.body.remainingBindings }, { deleted: false, remaining: 1 });
  assert.equal((await fixture.request('203.0.113.10', '/api/me')).body.accounts.length, 1);
  assert.equal((await fixture.request('203.0.113.11', '/api/me')).body.accounts.length, 1);

  const unbindLastA = await fixture.request('203.0.113.11', `/api/me/accounts/${accountA}/ip`, { method: 'DELETE' });
  assert.equal(unbindLastA.body.deletedAccount, true);
  assert.deepEqual((await fixture.request('198.51.100.1', '/api/leaderboard')).body.accounts, [{ name: 'software-codex-B', used: 60 }]);

  const unbindLastB = await fixture.request('203.0.113.10', `/api/me/accounts/${accountB}/ip`, { method: 'DELETE' });
  assert.equal(unbindLastB.body.deletedAccount, true);
  assert.equal((await fixture.request('203.0.113.10', '/health')).body.accounts, 0);
});

test('shares a 120 second cache and coalesces concurrent refreshes', async (t) => {
  let calls = 0;
  let fail = false;
  const provider = async () => {
    calls += 1;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 20));
    if (fail) throw new Error('temporary outage');
    return packyData('cached-account', calls * 10, 100);
  };
  const fixture = await createFixture({ provider });
  t.after(() => fixture.close());

  const registration = await fixture.request('203.0.113.20', '/api/accounts/register', { method: 'POST', body: { key: KEY_A } });
  const accountId = registration.body.account.id;
  await fixture.request('203.0.113.20', `/api/me/accounts/${accountId}/leaderboard`, { method: 'PATCH', body: { enabled: true } });
  await Promise.all([
    fixture.request('203.0.113.20', '/api/me'),
    fixture.request('198.51.100.10', '/api/leaderboard'),
    fixture.request('203.0.113.20', '/api/me')
  ]);
  assert.equal(calls, 1);

  fixture.advance(120001);
  await Promise.all([
    fixture.request('203.0.113.20', '/api/me'),
    fixture.request('198.51.100.10', '/api/leaderboard')
  ]);
  assert.equal(calls, 2);

  fixture.advance(120001);
  fail = true;
  const stale = await fixture.request('203.0.113.20', '/api/me');
  assert.equal(stale.body.accounts[0].status, 'stale');
  assert.equal(stale.body.accounts[0].used, 20);
  await fixture.request('203.0.113.20', '/api/me');
  assert.equal(calls, 3);
});

test('requires HTTPS for remote mutation and rate limits failed registrations', async (t) => {
  const fixture = await createFixture({ provider: async () => { throw new Error('invalid'); } });
  t.after(() => fixture.close());

  const insecure = await fixture.request('203.0.113.40', '/api/accounts/register', { method: 'POST', body: { key: KEY_A }, secure: false });
  assert.equal(insecure.status, 400);
  assert.match(insecure.body.message, /HTTPS/);

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const failed = await fixture.request('203.0.113.41', '/api/accounts/register', { method: 'POST', body: { key: KEY_A } });
    assert.equal(failed.status, 400);
    assert.ok(!JSON.stringify(failed.body).includes(KEY_A));
  }
  const limited = await fixture.request('203.0.113.41', '/api/accounts/register', { method: 'POST', body: { key: KEY_A } });
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers.get('retry-after')) > 0);
});
