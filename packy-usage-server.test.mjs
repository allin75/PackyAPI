import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  AccountStore,
  createPackyApp,
  createTrustedProxyMatcher,
  nextHourlyRefreshAt,
  normalizeIp,
  resolveRequestIdentity
} from './packy-usage-server.mjs';

const KEY_A = `sk-${'a'.repeat(32)}`;
const KEY_B = `sk-${'b'.repeat(32)}`;
const KEY_C = `sk-${'c'.repeat(32)}`;
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
  let app;
  let server;
  let baseUrl;
  const defaultCookies = new Map();

  async function start() {
    app = createPackyApp({
      databasePath,
      masterKey: Buffer.alloc(32, 7),
      refreshSeconds: 300,
      trustedProxyCidrs: ['127.0.0.1', '::1'],
      usageProvider: provider,
      leaderboardRequestSpacingMs: 0,
      nowMs: () => currentTime,
      staticFiles: EMPTY_STATIC
    });
    server = createServer(app.handler);
    await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
    const address = server.address();
    baseUrl = `http://127.0.0.1:${address.port}`;
  }

  await start();

  async function request(ip, path, { method = 'GET', body, secure = true, cookie, jar } = {}) {
    const headers = { 'X-Forwarded-For': ip };
    if (secure) headers['X-Forwarded-Proto'] = 'https';
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const cookieJar = jar === undefined ? defaultCookies : jar;
    const requestCookie = cookie === undefined ? (cookieJar instanceof Map ? (cookieJar.get(ip) || '') : (cookieJar?.cookie || '')) : cookie;
    if (requestCookie) headers.Cookie = requestCookie;
    const response = await fetch(`${baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const text = await response.text();
    const setCookie = response.headers.get('set-cookie');
    if (setCookie && cookie !== null && cookieJar) {
      const sessionCookie = setCookie.split(';', 1)[0];
      if (cookieJar instanceof Map) cookieJar.set(ip, sessionCookie);
      else cookieJar.cookie = sessionCookie;
    }
    return { status: response.status, headers: response.headers, body: text ? JSON.parse(text) : null };
  }

  return {
    get app() { return app; },
    databasePath,
    request,
    advance(milliseconds) { currentTime += milliseconds; },
    async restart() {
      await new Promise((resolveClose) => server.close(resolveClose));
      app.close();
      await start();
    },
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

test('aligns leaderboard refreshes to the next natural hour', () => {
  assert.equal(nextHourlyRefreshAt(1_800_000_000), 1_800_003_600);
  assert.equal(nextHourlyRefreshAt(1_800_000_123), 1_800_003_600);
  assert.equal(nextHourlyRefreshAt(1_800_003_600), 1_800_007_200);
});

test('migrates a version 1 database to version 3 without losing accounts', () => {
  const directory = mkdtempSync(join(tmpdir(), 'packy-usage-migration-'));
  const databasePath = join(directory, 'usage.sqlite');
  const legacy = new DatabaseSync(databasePath);
  legacy.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE accounts (
      id TEXT PRIMARY KEY,
      key_fingerprint TEXT NOT NULL UNIQUE,
      key_ciphertext TEXT NOT NULL,
      key_iv TEXT NOT NULL,
      key_tag TEXT NOT NULL,
      name TEXT NOT NULL,
      origin TEXT NOT NULL,
      leaderboard_enabled INTEGER NOT NULL DEFAULT 0 CHECK (leaderboard_enabled IN (0, 1)),
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE account_ips (
      account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      ip TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (account_id, ip)
    );
    INSERT INTO accounts VALUES ('legacy-id', 'fingerprint', 'ciphertext', 'iv', 'tag', 'Legacy', 'https://www.packyapi.ai', 1, 1, 1);
    INSERT INTO account_ips VALUES ('legacy-id', '203.0.113.8', 1);
    PRAGMA user_version = 1;
  `);
  legacy.close();

  const store = new AccountStore(databasePath, Buffer.alloc(32, 9));
  assert.equal(store.db.prepare('PRAGMA user_version').get().user_version, 3);
  assert.equal(store.counts().accounts, 1);
  assert.equal(store.listByIp('203.0.113.8')[0].name, 'Legacy');
  assert.ok(store.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'leaderboard_snapshots'").get());
  assert.ok(store.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'leaderboard_snapshot_meta'").get());
  assert.ok(store.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sessions'").get());
  assert.ok(store.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'session_accounts'").get());
  store.close();
  rmSync(directory, { recursive: true, force: true });
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
  assert.equal(unauthorized.status, 401);
  assert.equal(unauthorized.body.requiresAuth, true);
  assert.ok(ipOne.body.accounts.every((account) => !('key' in account) && !('ip' in account)));

  const unauthorizedToggle = await fixture.request('203.0.113.12', `/api/me/accounts/${accountA}/leaderboard`, { method: 'PATCH', body: { enabled: true } });
  assert.equal(unauthorizedToggle.status, 401);

  const toggleA = await fixture.request('203.0.113.11', `/api/me/accounts/${accountA}/leaderboard`, { method: 'PATCH', body: { enabled: true } });
  const toggleB = await fixture.request('203.0.113.10', `/api/me/accounts/${accountB}/leaderboard`, { method: 'PATCH', body: { enabled: true } });
  assert.equal(toggleA.status, 200);
  assert.equal(toggleB.status, 200);

  const ipOneAfterToggle = await fixture.request('203.0.113.10', '/api/me');
  assert.equal(ipOneAfterToggle.body.accounts.find((account) => account.id === accountA).leaderboardEnabled, true);

  const leaderboard = await fixture.request('198.51.100.1', '/api/leaderboard');
  assert.deepEqual(leaderboard.body.accounts, [
    { name: 'software-codex-B', used: 60, rank: 1, rankChange: null, movement: 'new', stale: false },
    { name: 'software-codex-A', used: 20, rank: 2, rankChange: null, movement: 'new', stale: false }
  ]);
  assert.deepEqual(Object.keys(leaderboard.body.accounts[0]).sort(), ['movement', 'name', 'rank', 'rankChange', 'stale', 'used']);
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
  assert.deepEqual({ deleted: unbindLastA.body.deletedAccount, remaining: unbindLastA.body.remainingBindings }, { deleted: false, remaining: 0 });
  assert.equal((await fixture.request('198.51.100.1', '/api/leaderboard')).body.accounts.length, 2);

  const unbindLastB = await fixture.request('203.0.113.10', `/api/me/accounts/${accountB}/ip`, { method: 'DELETE' });
  assert.deepEqual({ deleted: unbindLastB.body.deletedAccount, remaining: unbindLastB.body.remainingBindings }, { deleted: false, remaining: 0 });
  assert.equal((await fixture.request('203.0.113.10', '/health')).body.accounts, 2);
});

test('persists leaderboard movement across refresh windows and restarts', async (t) => {
  let phase = 1;
  let calls = 0;
  const provider = async (key) => {
    calls += 1;
    const values = phase === 1
      ? new Map([[KEY_A, ['Apex', 90]], [KEY_B, ['Blaze', 60]], [KEY_C, ['Comet', 30]]])
      : new Map([[KEY_A, ['Apex', 100]], [KEY_B, ['Blaze', 70]], [KEY_C, ['Comet', 140]]]);
    const [name, used] = values.get(key);
    return packyData(name, used, 100);
  };
  const fixture = await createFixture({ provider });
  t.after(() => fixture.close());

  const accounts = [];
  for (const [index, key] of [KEY_A, KEY_B, KEY_C].entries()) {
    const registered = await fixture.request(`203.0.113.${50 + index}`, '/api/accounts/register', { method: 'POST', body: { key } });
    accounts.push(registered.body.account.id);
    await fixture.request(`203.0.113.${50 + index}`, `/api/me/accounts/${registered.body.account.id}/leaderboard`, { method: 'PATCH', body: { enabled: true } });
  }

  const first = await fixture.request('198.51.100.1', '/api/leaderboard');
  assert.equal(first.body.nextRefreshAt, 1_800_003_600);
  assert.deepEqual(first.body.accounts.map(({ name, rank, rankChange, movement }) => ({ name, rank, rankChange, movement })), [
    { name: 'Apex', rank: 1, rankChange: null, movement: 'new' },
    { name: 'Blaze', rank: 2, rankChange: null, movement: 'new' },
    { name: 'Comet', rank: 3, rankChange: null, movement: 'new' }
  ]);
  const generatedAt = first.body.generatedAt;
  assert.equal(calls, 3);

  const repeated = await fixture.request('198.51.100.2', '/api/leaderboard');
  assert.deepEqual(repeated.body, first.body);
  assert.equal(calls, 3);

  await fixture.restart();
  const restored = await fixture.request('198.51.100.3', '/api/leaderboard');
  assert.deepEqual(restored.body, first.body);
  assert.equal(calls, 3);

  phase = 2;
  fixture.advance(300_001);
  const beforeHour = await fixture.request('198.51.100.4', '/api/leaderboard');
  assert.deepEqual(beforeHour.body, first.body);
  assert.equal(calls, 3);

  fixture.advance(3_300_000);
  const [refreshed, concurrent] = await Promise.all([
    fixture.request('198.51.100.5', '/api/leaderboard'),
    fixture.request('198.51.100.6', '/api/leaderboard')
  ]);
  assert.deepEqual(concurrent.body, refreshed.body);
  assert.ok(refreshed.body.generatedAt > generatedAt);
  assert.deepEqual(refreshed.body.accounts.map(({ name, rank, rankChange, movement }) => ({ name, rank, rankChange, movement })), [
    { name: 'Comet', rank: 1, rankChange: 2, movement: 'up' },
    { name: 'Apex', rank: 2, rankChange: -1, movement: 'down' },
    { name: 'Blaze', rank: 3, rankChange: -1, movement: 'down' }
  ]);
  assert.equal(calls, 6);
  assert.equal(refreshed.body.nextRefreshAt, 1_800_007_200);

  fixture.advance(3_600_001);
  const unchanged = await fixture.request('198.51.100.7', '/api/leaderboard');
  assert.ok(unchanged.body.accounts.every((account) => account.rankChange === 0 && account.movement === 'same'));
  assert.equal(calls, 9);
  assert.deepEqual(accounts.length, 3);
});

test('continues an hourly leaderboard refresh when one account fails', async (t) => {
  let phase = 1;
  let calls = 0;
  const provider = async (key) => {
    calls += 1;
    if (phase === 2 && key === KEY_B) throw new Error('temporary outage');
    const values = phase === 1
      ? new Map([[KEY_A, ['Alpha', 100]], [KEY_B, ['Bravo', 80]], [KEY_C, ['Charlie', 60]]])
      : new Map([[KEY_A, ['Alpha', 110]], [KEY_C, ['Charlie', 130]]]);
    const [name, used] = values.get(key);
    return packyData(name, used, 100);
  };
  const fixture = await createFixture({ provider });
  t.after(() => fixture.close());

  for (const [index, key] of [KEY_A, KEY_B, KEY_C].entries()) {
    const ip = `203.0.113.${70 + index}`;
    const registered = await fixture.request(ip, '/api/accounts/register', { method: 'POST', body: { key } });
    await fixture.request(ip, `/api/me/accounts/${registered.body.account.id}/leaderboard`, { method: 'PATCH', body: { enabled: true } });
  }
  const first = await fixture.request('198.51.100.8', '/api/leaderboard');
  assert.equal(calls, 3);

  phase = 2;
  await fixture.restart();
  fixture.advance(3_600_001);
  const refreshed = await fixture.request('198.51.100.9', '/api/leaderboard');

  assert.ok(refreshed.body.generatedAt > first.body.generatedAt);
  assert.equal(refreshed.body.nextRefreshAt, 1_800_007_200);
  assert.equal(calls, 6);
  assert.deepEqual(refreshed.body.accounts, [
    { name: 'Charlie', used: 130, rank: 1, rankChange: 2, movement: 'up', stale: false },
    { name: 'Alpha', used: 110, rank: 2, rankChange: -1, movement: 'down', stale: false },
    { name: 'Bravo', used: 80, rank: 3, rankChange: -1, movement: 'down', stale: true }
  ]);

  const repeated = await fixture.request('198.51.100.10', '/api/leaderboard');
  assert.deepEqual(repeated.body, refreshed.body);
  assert.equal(calls, 6);

  await fixture.restart();
  const restored = await fixture.request('198.51.100.11', '/api/leaderboard');
  assert.deepEqual(restored.body, refreshed.body);
  assert.equal(calls, 6);
});

test('keeps a newly joined account visible when its first leaderboard refresh fails', async (t) => {
  let failNewcomer = false;
  const provider = async (key) => {
    if (failNewcomer && key === KEY_B) throw new Error('temporary outage');
    return key === KEY_A ? packyData('Reliable', 42, 100) : packyData('Newcomer', 18, 100);
  };
  const fixture = await createFixture({ provider });
  t.after(() => fixture.close());

  const reliable = await fixture.request('203.0.113.74', '/api/accounts/register', { method: 'POST', body: { key: KEY_A } });
  await fixture.request('203.0.113.74', `/api/me/accounts/${reliable.body.account.id}/leaderboard`, { method: 'PATCH', body: { enabled: true } });
  await fixture.request('198.51.100.12', '/api/leaderboard');

  const newcomer = await fixture.request('203.0.113.75', '/api/accounts/register', { method: 'POST', body: { key: KEY_B } });
  await fixture.request('203.0.113.75', `/api/me/accounts/${newcomer.body.account.id}/leaderboard`, { method: 'PATCH', body: { enabled: true } });

  await fixture.restart();
  failNewcomer = true;
  const refreshed = await fixture.request('198.51.100.13', '/api/leaderboard');
  assert.deepEqual(refreshed.body.accounts, [
    { name: 'Reliable', used: 42, rank: 1, rankChange: 0, movement: 'same', stale: false },
    { name: 'Newcomer', used: null, rank: 2, rankChange: null, movement: 'new', stale: true }
  ]);
});

test('saves a new hourly snapshot when every leaderboard account fails', async (t) => {
  let fail = false;
  const provider = async (key) => {
    if (fail) throw new Error('temporary outage');
    return key === KEY_A ? packyData('Alpha', 30, 100) : packyData('Bravo', 20, 100);
  };
  const fixture = await createFixture({ provider });
  t.after(() => fixture.close());

  for (const [index, key] of [KEY_A, KEY_B].entries()) {
    const ip = `203.0.113.${76 + index}`;
    const registered = await fixture.request(ip, '/api/accounts/register', { method: 'POST', body: { key } });
    await fixture.request(ip, `/api/me/accounts/${registered.body.account.id}/leaderboard`, { method: 'PATCH', body: { enabled: true } });
  }
  const first = await fixture.request('198.51.100.14', '/api/leaderboard');

  fail = true;
  await fixture.restart();
  fixture.advance(3_600_001);
  const refreshed = await fixture.request('198.51.100.15', '/api/leaderboard');

  assert.ok(refreshed.body.generatedAt > first.body.generatedAt);
  assert.equal(refreshed.body.nextRefreshAt, 1_800_007_200);
  assert.ok(refreshed.body.accounts.every((account) => account.stale));
  assert.deepEqual(refreshed.body.accounts.map(({ name, used }) => ({ name, used })), [
    { name: 'Alpha', used: 30 },
    { name: 'Bravo', used: 20 }
  ]);
});

test('refreshes leaderboard accounts sequentially to avoid upstream bursts', async (t) => {
  let activeCalls = 0;
  let maximumActiveCalls = 0;
  let trackConcurrency = false;
  const provider = async (key) => {
    if (trackConcurrency) {
      activeCalls += 1;
      maximumActiveCalls = Math.max(maximumActiveCalls, activeCalls);
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 12));
    if (trackConcurrency) activeCalls -= 1;
    const name = key === KEY_A ? 'Alpha' : (key === KEY_B ? 'Bravo' : 'Charlie');
    return packyData(name, key === KEY_A ? 30 : (key === KEY_B ? 20 : 10), 100);
  };
  const fixture = await createFixture({ provider });
  t.after(() => fixture.close());

  for (const [index, key] of [KEY_A, KEY_B, KEY_C].entries()) {
    const ip = `203.0.113.${80 + index}`;
    const registered = await fixture.request(ip, '/api/accounts/register', { method: 'POST', body: { key } });
    await fixture.request(ip, `/api/me/accounts/${registered.body.account.id}/leaderboard`, { method: 'PATCH', body: { enabled: true } });
  }
  await fixture.request('198.51.100.20', '/api/leaderboard');

  trackConcurrency = true;
  fixture.advance(3_600_001);
  const refreshed = await fixture.request('198.51.100.21', '/api/leaderboard');
  assert.equal(refreshed.status, 200);
  assert.equal(maximumActiveCalls, 1);
});

test('labels hourly and per-account stale leaderboard data', () => {
  const html = readFileSync(new URL('./packy-key-usage.html', import.meta.url), 'utf8');
  assert.match(html, /整点刷新/);
  assert.match(html, /沿用上轮/);
  assert.match(html, /account\.stale/);
  assert.doesNotMatch(html, /5 分钟刷新/);
  assert.doesNotMatch(html, /已自动延迟重试/);
});

test('uses the simplified packycode brand and session wording', () => {
  const myHtml = readFileSync(new URL('./packy-my-usage.html', import.meta.url), 'utf8');
  const leaderboardHtml = readFileSync(new URL('./packy-key-usage.html', import.meta.url), 'utf8');
  assert.match(myHtml, /packycode用量查询/);
  assert.match(leaderboardHtml, /packycode用量查询/);
  assert.match(myHtml, />05:00<|refreshSeconds: 300/);
  assert.match(leaderboardHtml, /整点刷新/);
  assert.match(leaderboardHtml, /chars\[chars\.length - 1\]/);
  assert.match(myHtml, /packy-leaderboard-refresh/);
  assert.match(leaderboardHtml, /addEventListener\("storage"/);
  assert.doesNotMatch(myHtml, /团队额度监控|当前 IP 还没有绑定账号/);
  assert.match(myHtml, /请输入 Key 建立浏览器会话/);
});

test('refreshes leaderboard immediately after toggles and reuses private usage cache', async (t) => {
  let calls = 0;
  const provider = async () => {
    calls += 1;
    return packyData('instant-leader', 88, 12);
  };
  const fixture = await createFixture({ provider });
  t.after(() => fixture.close());

  const registration = await fixture.request('203.0.113.60', '/api/accounts/register', { method: 'POST', body: { key: KEY_A } });
  const accountId = registration.body.account.id;
  assert.equal(calls, 1);

  const initial = await fixture.request('198.51.100.60', '/api/leaderboard');
  assert.deepEqual(initial.body.accounts, []);

  const enabled = await fixture.request('203.0.113.60', `/api/me/accounts/${accountId}/leaderboard`, { method: 'PATCH', body: { enabled: true } });
  assert.equal(enabled.status, 200);
  const joined = await fixture.request('198.51.100.60', '/api/leaderboard');
  assert.deepEqual(joined.body.accounts.map(({ name, used, rank }) => ({ name, used, rank })), [{ name: 'instant-leader', used: 88, rank: 1 }]);
  assert.equal(calls, 1);

  const disabled = await fixture.request('203.0.113.60', `/api/me/accounts/${accountId}/leaderboard`, { method: 'PATCH', body: { enabled: false } });
  assert.equal(disabled.status, 200);
  const left = await fixture.request('198.51.100.60', '/api/leaderboard');
  assert.deepEqual(left.body.accounts, []);
  assert.equal(calls, 1);
});

test('shares a 300 second cache and coalesces concurrent refreshes', async (t) => {
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

  fixture.advance(300001);
  await Promise.all([
    fixture.request('203.0.113.20', '/api/me'),
    fixture.request('198.51.100.10', '/api/leaderboard')
  ]);
  assert.equal(calls, 2);

  fixture.advance(300001);
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

test('isolates accounts by browser session even when browsers share one IP', async (t) => {
  const provider = async (key) => {
    if (key === KEY_A) return packyData('session-account-A', 10, 90);
    if (key === KEY_B) return packyData('session-account-B', 20, 80);
    throw new Error('invalid key');
  };
  const fixture = await createFixture({ provider });
  t.after(() => fixture.close());
  const browserAJar = {};
  const browserBJar = {};

  const browserARegistration = await fixture.request('203.0.113.50', '/api/accounts/register', { method: 'POST', body: { key: KEY_A }, jar: browserAJar });
  const browserBRegistration = await fixture.request('203.0.113.50', '/api/accounts/register', { method: 'POST', body: { key: KEY_B }, jar: browserBJar });
  const browserACookie = browserARegistration.headers.get('set-cookie');
  const browserBCookie = browserBRegistration.headers.get('set-cookie');

  assert.equal(browserARegistration.status, 201);
  assert.equal(browserBRegistration.status, 201);
  assert.ok(browserACookie);
  assert.ok(browserBCookie);
  assert.notEqual(browserACookie, browserBCookie);

  const browserA = await fixture.request('203.0.113.50', '/api/me', { cookie: browserACookie, jar: browserAJar });
  const browserB = await fixture.request('203.0.113.50', '/api/me', { cookie: browserBCookie, jar: browserBJar });
  const anonymous = await fixture.request('203.0.113.50', '/api/me', { cookie: null });
  assert.deepEqual(browserA.body.accounts.map((account) => account.name), ['session-account-A']);
  assert.deepEqual(browserB.body.accounts.map((account) => account.name), ['session-account-B']);
  assert.equal(anonymous.status, 401);
  assert.equal(anonymous.body.requiresAuth, true);
});
