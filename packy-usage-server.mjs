import { createServer } from 'node:http';
import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { BlockList, isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_ORIGIN = 'https://www.packyapi.ai';
const ALLOWED_PACKY_HOSTS = new Set(['www.packyapi.ai', 'www.packyapi.com', 'slb-v1.api.fan']);
const KEY_PATTERN = /^sk-[A-Za-z0-9_-]{20,}$/;
const JSON_BODY_LIMIT = 8 * 1024;
const SESSION_COOKIE_NAME = '__Host-packy_session';
const DEFAULT_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
const DEFAULT_REFRESH_SECONDS = 5 * 60;
const HOUR_SECONDS = 60 * 60;

export function nextHourlyRefreshAt(now) {
  return (Math.floor(Number(now) / HOUR_SECONDS) + 1) * HOUR_SECONDS;
}

class PublicError extends Error {
  constructor(statusCode, message, headers = {}) {
    super(message);
    this.statusCode = statusCode;
    this.headers = headers;
  }
}

export function normalizeIp(value) {
  if (!value) return '';
  let ip = String(value).trim();
  if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
  const zoneIndex = ip.indexOf('%');
  if (zoneIndex >= 0) ip = ip.slice(0, zoneIndex);
  if (/^::ffff:\d{1,3}(?:\.\d{1,3}){3}$/i.test(ip)) ip = ip.slice(7);
  return isIP(ip) ? ip.toLowerCase() : '';
}

export function isLoopbackIp(ip) {
  const normalized = normalizeIp(ip);
  if (normalized === '::1') return true;
  if (isIP(normalized) === 4) return normalized.split('.')[0] === '127';
  return false;
}

export function createTrustedProxyMatcher(entries = []) {
  const blockList = new BlockList();
  for (const rawEntry of entries) {
    const entry = String(rawEntry).trim();
    if (!entry) continue;
    const [rawAddress, rawPrefix] = entry.split('/');
    const address = normalizeIp(rawAddress);
    const family = isIP(address);
    if (!family) throw new Error(`Invalid trusted proxy address: ${entry}`);
    const type = family === 4 ? 'ipv4' : 'ipv6';
    if (rawPrefix === undefined) {
      blockList.addAddress(address, type);
      continue;
    }
    const prefix = Number(rawPrefix);
    const maxPrefix = family === 4 ? 32 : 128;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
      throw new Error(`Invalid trusted proxy prefix: ${entry}`);
    }
    blockList.addSubnet(address, prefix, type);
  }
  return (value) => {
    const address = normalizeIp(value);
    const family = isIP(address);
    return family ? blockList.check(address, family === 4 ? 'ipv4' : 'ipv6') : false;
  };
}

function firstHeaderValue(value) {
  if (Array.isArray(value)) return value[0] || '';
  return value ? String(value) : '';
}

function readCookie(request, name) {
  const header = firstHeaderValue(request.headers?.cookie);
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0) continue;
    const key = part.slice(0, separator).trim();
    if (key === name) return part.slice(separator + 1).trim();
  }
  return '';
}

function createSessionCookie(token, maxAge) {
  return `${SESSION_COOKIE_NAME}=${token}; Path=/; Max-Age=${Math.max(0, Math.floor(maxAge))}; HttpOnly; Secure; SameSite=Strict`;
}

export function resolveRequestIdentity(request, isTrustedProxy = () => false) {
  const peerIp = normalizeIp(request.socket?.remoteAddress);
  const peerIsTrusted = isTrustedProxy(peerIp);
  let clientIp = peerIp;

  if (peerIsTrusted) {
    const forwarded = firstHeaderValue(request.headers?.['x-forwarded-for'])
      .split(',')
      .map(normalizeIp)
      .filter(Boolean);
    let currentHop = peerIp;
    for (let index = forwarded.length - 1; index >= 0 && isTrustedProxy(currentHop); index -= 1) {
      currentHop = forwarded[index];
      clientIp = currentHop;
    }
  }

  const forwardedProto = peerIsTrusted
    ? firstHeaderValue(request.headers?.['x-forwarded-proto']).split(',')[0].trim().toLowerCase()
    : '';
  return {
    clientIp,
    peerIp,
    peerIsTrusted,
    secure: Boolean(request.socket?.encrypted) || forwardedProto === 'https'
  };
}

function parseMasterKey(value) {
  const text = String(value || '').trim();
  if (!text) throw new Error('Master key is empty.');
  const encoding = /^[a-f0-9]{64}$/i.test(text) ? 'hex' : 'base64';
  const key = Buffer.from(text, encoding);
  if (key.length !== 32) throw new Error('Master key must contain exactly 32 bytes.');
  return key;
}

export function loadMasterKey({ dataDir, env = process.env } = {}) {
  if (env.PACKY_MASTER_KEY) return parseMasterKey(env.PACKY_MASTER_KEY);
  const keyPath = resolve(env.PACKY_MASTER_KEY_FILE || join(dataDir, 'master.key'));
  if (!existsSync(keyPath)) {
    mkdirSync(dirname(keyPath), { recursive: true });
    writeFileSync(keyPath, `${randomBytes(32).toString('base64')}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  }
  return parseMasterKey(readFileSync(keyPath, 'utf8'));
}

function deriveKeys(masterKey) {
  return {
    encryption: Buffer.from(hkdfSync('sha256', masterKey, Buffer.alloc(0), 'packy-key-encryption-v1', 32)),
    fingerprint: Buffer.from(hkdfSync('sha256', masterKey, Buffer.alloc(0), 'packy-key-fingerprint-v1', 32)),
    session: Buffer.from(hkdfSync('sha256', masterKey, Buffer.alloc(0), 'packy-session-v1', 32))
  };
}

export class AccountStore {
  constructor(databasePath, masterKey) {
    mkdirSync(dirname(databasePath), { recursive: true });
    this.databasePath = databasePath;
    this.keys = deriveKeys(masterKey);
    this.db = new DatabaseSync(databasePath);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;
      PRAGMA busy_timeout = 5000;
    `);
    const schemaVersion = Number(this.db.prepare('PRAGMA user_version').get().user_version || 0);
    if (schemaVersion > 3) throw new Error(`Database schema version ${schemaVersion} is newer than this application supports.`);
    if (schemaVersion < 1) {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS accounts (
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
        CREATE TABLE IF NOT EXISTS account_ips (
          account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
          ip TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          PRIMARY KEY (account_id, ip)
        );
        CREATE INDEX IF NOT EXISTS account_ips_ip_idx ON account_ips(ip);
        PRAGMA user_version = 1;
      `);
    }
    if (schemaVersion < 2) {
      this.db.exec(`
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS leaderboard_snapshots (
          account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          used REAL,
          rank INTEGER NOT NULL,
          rank_delta INTEGER,
          observed_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS leaderboard_snapshots_rank_idx ON leaderboard_snapshots(rank);
        CREATE TABLE IF NOT EXISTS leaderboard_snapshot_meta (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          generated_at INTEGER NOT NULL,
          next_refresh_at INTEGER NOT NULL
        );
        PRAGMA user_version = 2;
        COMMIT;
      `);
    }
    if (schemaVersion < 3) {
      this.db.exec(`
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS sessions (
          id TEXT PRIMARY KEY,
          token_hash TEXT NOT NULL UNIQUE,
          created_at INTEGER NOT NULL,
          last_seen_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);
        CREATE TABLE IF NOT EXISTS session_accounts (
          session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
          account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
          created_at INTEGER NOT NULL,
          PRIMARY KEY (session_id, account_id)
        );
        CREATE INDEX IF NOT EXISTS session_accounts_account_idx ON session_accounts(account_id);
        PRAGMA user_version = 3;
        COMMIT;
      `);
    }
  }

  fingerprint(key) {
    return createHmac('sha256', this.keys.fingerprint).update(key, 'utf8').digest('hex');
  }

  hashSessionToken(token) {
    return createHmac('sha256', this.keys.session).update(token, 'utf8').digest('hex');
  }

  encryptKey(key) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.keys.encryption, iv);
    const ciphertext = Buffer.concat([cipher.update(key, 'utf8'), cipher.final()]);
    return {
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64')
    };
  }

  decryptKey(account) {
    const decipher = createDecipheriv('aes-256-gcm', this.keys.encryption, Buffer.from(account.key_iv, 'base64'));
    decipher.setAuthTag(Buffer.from(account.key_tag, 'base64'));
    return Buffer.concat([
      decipher.update(Buffer.from(account.key_ciphertext, 'base64')),
      decipher.final()
    ]).toString('utf8');
  }

  findByFingerprint(fingerprint) {
    return this.db.prepare('SELECT * FROM accounts WHERE key_fingerprint = ?').get(fingerprint) || null;
  }

  findById(id) {
    return this.db.prepare('SELECT * FROM accounts WHERE id = ?').get(id) || null;
  }

  listByIp(ip) {
    return this.db.prepare(`
      SELECT a.* FROM accounts a
      INNER JOIN account_ips ai ON ai.account_id = a.id
      WHERE ai.ip = ?
      ORDER BY a.name COLLATE NOCASE, a.id
    `).all(ip);
  }

  listBySession(sessionId) {
    return this.db.prepare(`
      SELECT a.* FROM accounts a
      INNER JOIN session_accounts sa ON sa.account_id = a.id
      WHERE sa.session_id = ?
      ORDER BY a.name COLLATE NOCASE, a.id
    `).all(sessionId);
  }

  createSession(now, ttlSeconds) {
    const id = randomUUID();
    const token = randomBytes(32).toString('base64url');
    const tokenHash = this.hashSessionToken(token);
    this.db.prepare(`
      INSERT INTO sessions (id, token_hash, created_at, last_seen_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, tokenHash, now, now, now + ttlSeconds);
    return { id, token, expiresAt: now + ttlSeconds };
  }

  findSession(token, now) {
    if (!token) return null;
    const session = this.db.prepare(`
      SELECT id, created_at, last_seen_at, expires_at
      FROM sessions
      WHERE token_hash = ? AND expires_at > ?
    `).get(this.hashSessionToken(token), now) || null;
    if (!session) return null;
    this.db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(now, session.id);
    return { ...session, token };
  }

  bindSession(sessionId, accountId, now) {
    this.db.prepare('INSERT OR IGNORE INTO session_accounts (session_id, account_id, created_at) VALUES (?, ?, ?)').run(sessionId, accountId, now);
    this.db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(now, sessionId);
  }

  hasSessionAccount(sessionId, accountId) {
    return Boolean(this.db.prepare('SELECT 1 FROM session_accounts WHERE session_id = ? AND account_id = ?').get(sessionId, accountId));
  }

  unbindSession(sessionId, accountId) {
    const removed = this.db.prepare('DELETE FROM session_accounts WHERE session_id = ? AND account_id = ?').run(sessionId, accountId).changes > 0;
    const remaining = Number(this.db.prepare('SELECT COUNT(*) AS count FROM session_accounts WHERE session_id = ?').get(sessionId)?.count || 0);
    return { removed, remaining, deletedAccount: false };
  }

  listLeaderboard() {
    return this.db.prepare(`
      SELECT * FROM accounts
      WHERE leaderboard_enabled = 1
      ORDER BY name COLLATE NOCASE, id
    `).all();
  }

  readLeaderboardSnapshot() {
    const meta = this.db.prepare('SELECT generated_at, next_refresh_at FROM leaderboard_snapshot_meta WHERE id = 1').get() || null;
    const rows = meta ? this.db.prepare(`
      SELECT account_id, name, used, rank, rank_delta, observed_at
      FROM leaderboard_snapshots
      ORDER BY rank
    `).all() : [];
    return { meta, rows };
  }

  saveLeaderboardSnapshot(entries, generatedAt, nextRefreshAt) {
    const insert = this.db.prepare(`
      INSERT INTO leaderboard_snapshots (account_id, name, used, rank, rank_delta, observed_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.exec('DELETE FROM leaderboard_snapshots');
      for (const entry of entries) {
        const observedAt = Number.isFinite(entry.observedAt) ? entry.observedAt : generatedAt;
        insert.run(entry.accountId, entry.name, entry.used, entry.rank, entry.rankChange, observedAt);
      }
      this.db.prepare(`
        INSERT INTO leaderboard_snapshot_meta (id, generated_at, next_refresh_at)
        VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET generated_at = excluded.generated_at, next_refresh_at = excluded.next_refresh_at
      `).run(generatedAt, nextRefreshAt);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  invalidateLeaderboardSnapshot(now) {
    this.db.prepare('UPDATE leaderboard_snapshot_meta SET next_refresh_at = ? WHERE id = 1').run(now);
  }

  createAccount({ key, name, origin, ip, now }) {
    const id = randomUUID();
    const encrypted = this.encryptKey(key);
    const fingerprint = this.fingerprint(key);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare(`
        INSERT INTO accounts (
          id, key_fingerprint, key_ciphertext, key_iv, key_tag,
          name, origin, leaderboard_enabled, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
      `).run(id, fingerprint, encrypted.ciphertext, encrypted.iv, encrypted.tag, name, origin, now, now);
      this.db.prepare('INSERT INTO account_ips (account_id, ip, created_at) VALUES (?, ?, ?)').run(id, ip, now);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
    return this.findById(id);
  }

  bindIp(accountId, ip, now) {
    this.db.prepare('INSERT OR IGNORE INTO account_ips (account_id, ip, created_at) VALUES (?, ?, ?)').run(accountId, ip, now);
    this.db.prepare('UPDATE accounts SET updated_at = ? WHERE id = ?').run(now, accountId);
  }

  hasIp(accountId, ip) {
    return Boolean(this.db.prepare('SELECT 1 FROM account_ips WHERE account_id = ? AND ip = ?').get(accountId, ip));
  }

  setLeaderboard(accountId, enabled, now) {
    this.db.prepare('UPDATE accounts SET leaderboard_enabled = ?, updated_at = ? WHERE id = ?').run(enabled ? 1 : 0, now, accountId);
  }

  updateName(accountId, name, now) {
    this.db.prepare('UPDATE accounts SET name = ?, updated_at = ? WHERE id = ?').run(name, now, accountId);
  }

  unbindIp(accountId, ip) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const removed = this.db.prepare('DELETE FROM account_ips WHERE account_id = ? AND ip = ?').run(accountId, ip).changes > 0;
      const remaining = Number(this.db.prepare('SELECT COUNT(*) AS count FROM account_ips WHERE account_id = ?').get(accountId)?.count || 0);
      let deletedAccount = false;
      if (removed && remaining === 0) {
        this.db.prepare('DELETE FROM accounts WHERE id = ?').run(accountId);
        deletedAccount = true;
      }
      this.db.exec('COMMIT');
      return { removed, remaining, deletedAccount };
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  counts() {
    return {
      accounts: Number(this.db.prepare('SELECT COUNT(*) AS count FROM accounts').get().count),
      bindings: Number(this.db.prepare('SELECT COUNT(*) AS count FROM account_ips').get().count),
      leaderboard: Number(this.db.prepare('SELECT COUNT(*) AS count FROM accounts WHERE leaderboard_enabled = 1').get().count),
      sessions: Number(this.db.prepare('SELECT COUNT(*) AS count FROM sessions').get().count)
    };
  }

  close() {
    this.db.close();
  }
}

function validatePackyOrigin(value) {
  const origin = new URL(value || DEFAULT_ORIGIN);
  if (origin.protocol !== 'https:' || !ALLOWED_PACKY_HOSTS.has(origin.hostname.toLowerCase())) {
    throw new Error('PACKY_ORIGIN must be an approved PackyAPI HTTPS origin.');
  }
  return origin.origin;
}

export async function queryPackyUsage(key, origin = DEFAULT_ORIGIN) {
  const response = await fetch(`${origin}/api/usage/token/`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${key}`,
      Accept: 'application/json',
      'User-Agent': 'cc-switch/1.0'
    },
    signal: AbortSignal.timeout(30_000)
  });
  const text = await response.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new Error('PackyAPI returned an invalid response.');
  }
  if (!response.ok || !payload?.data) throw new Error('PackyAPI rejected the Key or is temporarily unavailable.');
  return payload.data;
}

function round(value, decimals) {
  const factor = 10 ** decimals;
  return Math.round((Number(value) + Number.EPSILON) * factor) / factor;
}

function convertUsage(account, data, fetchedAt, refreshSeconds) {
  const remaining = Number(data.total_available || 0) / 500000;
  const used = Number(data.total_used || 0) / 500000;
  const total = remaining + used;
  const resetPeriod = String(data.quota_reset_period || '');
  const name = String(data.name || account.name || 'PackyAPI 账号').trim() || 'PackyAPI 账号';
  return {
    id: String(account.id),
    name,
    status: 'ok',
    stale: false,
    remaining: round(remaining, 6),
    used: round(used, 6),
    total: round(total, 6),
    usageRate: round(total > 0 ? used / total * 100 : 0, 4),
    unlimited: Boolean(data.unlimited_quota),
    resetPeriod,
    resetLabel: resetPeriod === 'monthly' ? '月度重置' : (resetPeriod ? `${resetPeriod} 重置` : '不重置'),
    quotaPeriodStart: Number(data.quota_period_start || 0),
    expiresAt: Number(data.expires_at || 0),
    fetchedAt,
    nextRefreshAt: fetchedAt + refreshSeconds
  };
}

function makeUnavailableUsage(account, attemptedAt, refreshSeconds) {
  return {
    id: String(account.id),
    name: String(account.name),
    status: 'error',
    stale: false,
    remaining: null,
    used: null,
    total: null,
    usageRate: null,
    unlimited: false,
    resetPeriod: '',
    resetLabel: '查询失败',
    quotaPeriodStart: 0,
    expiresAt: 0,
    fetchedAt: null,
    nextRefreshAt: attemptedAt + refreshSeconds
  };
}

function toPrivateAccount(usage, account) {
  return { ...usage, leaderboardEnabled: Boolean(account.leaderboard_enabled) };
}

function readStaticFile(name) {
  return readFileSync(join(MODULE_DIR, name));
}

function setSecurityHeaders(response, contentType = '') {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (contentType.startsWith('text/html')) {
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  }
}

function send(response, statusCode, contentType, body, extraHeaders = {}) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body || '', 'utf8');
  response.statusCode = statusCode;
  response.setHeader('Content-Type', contentType);
  setSecurityHeaders(response, contentType);
  for (const [name, value] of Object.entries(extraHeaders)) response.setHeader(name, value);
  response.setHeader('Content-Length', payload.length);
  response.end(payload);
}

function sendJson(response, statusCode, value, extraHeaders = {}) {
  send(response, statusCode, 'application/json; charset=utf-8', JSON.stringify(value), extraHeaders);
}

async function readJsonBody(request) {
  const contentType = firstHeaderValue(request.headers['content-type']).split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new PublicError(415, '请求必须使用 JSON 格式。');
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > JSON_BODY_LIMIT) throw new PublicError(413, '请求内容过大。');
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return value;
  } catch {
    throw new PublicError(400, 'JSON 内容无效。');
  }
}

function requireMutationSecurity(request, identity) {
  if (!identity.clientIp) throw new PublicError(400, '无法识别来源 IP。');
  if (!identity.secure && !isLoopbackIp(identity.clientIp)) {
    throw new PublicError(400, '远程登记和修改必须通过 HTTPS。');
  }
  if (String(request.headers['sec-fetch-site'] || '').toLowerCase() === 'cross-site') {
    throw new PublicError(403, '拒绝跨站请求。');
  }
  const origin = firstHeaderValue(request.headers.origin);
  if (origin && origin !== 'null') {
    const scheme = identity.secure ? 'https' : 'http';
    const host = firstHeaderValue(request.headers.host).toLowerCase();
    let suppliedOrigin = '';
    try { suppliedOrigin = new URL(origin).origin.toLowerCase(); } catch { }
    if (!host || suppliedOrigin !== `${scheme}://${host}`) throw new PublicError(403, '请求来源不匹配。');
  }
}

function createFailureLimiter({ maxFailures = 5, windowMs = 15 * 60_000, nowMs = () => Date.now() } = {}) {
  const failures = new Map();
  return {
    check(ip) {
      const cutoff = nowMs() - windowMs;
      const recent = (failures.get(ip) || []).filter((time) => time > cutoff);
      failures.set(ip, recent);
      if (recent.length >= maxFailures) {
        const retrySeconds = Math.max(1, Math.ceil((recent[0] + windowMs - nowMs()) / 1000));
        throw new PublicError(429, 'Key 验证失败次数过多，请稍后再试。', { 'Retry-After': String(retrySeconds) });
      }
    },
    fail(ip) {
      const values = failures.get(ip) || [];
      values.push(nowMs());
      failures.set(ip, values);
    },
    clear(ip) {
      failures.delete(ip);
    }
  };
}

export function createPackyApp({
  databasePath,
  masterKey,
  refreshSeconds = DEFAULT_REFRESH_SECONDS,
  trustedProxyCidrs = [],
  packyOrigin = DEFAULT_ORIGIN,
  usageProvider,
  leaderboardRequestSpacingMs = 1_000,
  sessionTtlSeconds = DEFAULT_SESSION_TTL_SECONDS,
  nowMs = () => Date.now(),
  staticFiles
}) {
  const effectiveRefreshSeconds = Math.max(DEFAULT_REFRESH_SECONDS, Number(refreshSeconds) || DEFAULT_REFRESH_SECONDS);
  const effectiveLeaderboardSpacingMs = Math.max(0, Number(leaderboardRequestSpacingMs) || 0);
  const effectiveSessionTtlSeconds = Math.max(effectiveRefreshSeconds, Number(sessionTtlSeconds) || DEFAULT_SESSION_TTL_SECONDS);
  const origin = usageProvider ? packyOrigin : validatePackyOrigin(packyOrigin);
  const queryUsage = usageProvider || ((key) => queryPackyUsage(key, origin));
  const store = new AccountStore(databasePath, masterKey);
  const isTrustedProxy = createTrustedProxyMatcher(trustedProxyCidrs);
  const limiter = createFailureLimiter({ nowMs });
  const cache = new Map();
  const inFlight = new Map();
  let leaderboardInFlight = null;
  const assets = staticFiles || {
    my: readStaticFile('packy-my-usage.html'),
    leaderboard: readStaticFile('packy-key-usage.html'),
    css: readStaticFile('packy-usage.css')
  };

  function primeUsage(account, data, fetchedAtMs) {
    const fetchedAt = Math.floor(fetchedAtMs / 1000);
    const usage = convertUsage(account, data, fetchedAt, effectiveRefreshSeconds);
    if (usage.name !== account.name) {
      store.updateName(account.id, usage.name, fetchedAt);
      account.name = usage.name;
    }
    cache.set(account.id, { result: usage, lastAttemptMs: fetchedAtMs });
    return usage;
  }

  async function getAccountUsage(account) {
    const current = cache.get(account.id);
    const now = nowMs();
    if (current && now - current.lastAttemptMs < effectiveRefreshSeconds * 1000) {
      return current.result;
    }
    if (inFlight.has(account.id)) return inFlight.get(account.id);

    const pending = (async () => {
      try {
        const key = store.decryptKey(account);
        const data = await queryUsage(key);
        return primeUsage(account, data, now);
      } catch {
        const attemptedAt = Math.floor(now / 1000);
        const stale = current?.result && current.result.status !== 'error'
          ? { ...current.result, status: 'stale', stale: true, nextRefreshAt: attemptedAt + effectiveRefreshSeconds }
          : makeUnavailableUsage(account, attemptedAt, effectiveRefreshSeconds);
        cache.set(account.id, { result: stale, lastAttemptMs: now });
        return stale;
      } finally {
        inFlight.delete(account.id);
      }
    })();
    inFlight.set(account.id, pending);
    return pending;
  }

  function getSession(request, now = Math.floor(nowMs() / 1000)) {
    const token = readCookie(request, SESSION_COOKIE_NAME);
    return store.findSession(token, now);
  }

  function requireSession(session) {
    if (!session) throw new PublicError(401, '请先输入 Key 建立会话。');
    return session;
  }

  async function getPrivatePayload(session) {
    const accounts = store.listBySession(session.id);
    const usage = await Promise.all(accounts.map(async (account) => toPrivateAccount(await getAccountUsage(account), account)));
    const now = Math.floor(nowMs() / 1000);
    return {
      generatedAt: now,
      refreshIntervalSeconds: effectiveRefreshSeconds,
      nextRefreshAt: usage.length ? Math.min(...usage.map((item) => item.nextRefreshAt || now + effectiveRefreshSeconds)) : now + effectiveRefreshSeconds,
      accounts: usage
    };
  }

  function publicLeaderboardPayload(snapshot, overrides = {}) {
    return {
      generatedAt: Number(snapshot.meta.generated_at),
      refreshIntervalSeconds: effectiveRefreshSeconds,
      nextRefreshAt: Number(snapshot.meta.next_refresh_at),
      accounts: snapshot.rows.map((entry) => {
        const rankChange = entry.rank_delta === null ? null : Number(entry.rank_delta);
        return {
          name: String(entry.name),
          used: Number.isFinite(entry.used) ? Number(entry.used) : null,
          rank: Number(entry.rank),
          rankChange,
          movement: rankChange === null ? 'new' : (rankChange > 0 ? 'up' : (rankChange < 0 ? 'down' : 'same')),
          stale: Number(entry.observed_at) < Number(snapshot.meta.generated_at)
        };
      }),
      ...overrides
    };
  }

  async function refreshLeaderboardSnapshot(previous, now) {
    const accounts = store.listLeaderboard();
    const previousRows = new Map(previous.rows.map((entry) => [String(entry.account_id), entry]));
    const entries = [];
    for (let index = 0; index < accounts.length; index += 1) {
      if (index > 0 && effectiveLeaderboardSpacingMs > 0) {
        await new Promise((resolveDelay) => setTimeout(resolveDelay, effectiveLeaderboardSpacingMs));
      }
      const account = accounts[index];
      const item = await getAccountUsage(account);
      const previousRow = previousRows.get(String(account.id));
      entries.push(item.status === 'ok' ? {
        accountId: String(account.id),
        name: item.name,
        used: Number.isFinite(item.used) ? item.used : null,
        observedAt: now
      } : {
        accountId: String(account.id),
        name: previousRow ? String(previousRow.name) : String(account.name),
        used: Number.isFinite(previousRow?.used) ? Number(previousRow.used) : null,
        observedAt: previousRow ? Number(previousRow.observed_at) : 0
      });
    }

    const previousRanks = new Map(previous.rows.map((entry) => [String(entry.account_id), Number(entry.rank)]));
    const rankedEntries = entries
      .sort((left, right) => {
        if (left.used === null && right.used !== null) return 1;
        if (right.used === null && left.used !== null) return -1;
        return (right.used || 0) - (left.used || 0)
          || left.name.localeCompare(right.name, 'zh-CN')
          || left.accountId.localeCompare(right.accountId);
      })
      .map((entry, index) => {
        const rank = index + 1;
        const previousRank = previousRanks.get(entry.accountId);
        return { ...entry, rank, rankChange: previousRank === undefined ? null : previousRank - rank };
      });
    store.saveLeaderboardSnapshot(rankedEntries, now, nextHourlyRefreshAt(now));
    return publicLeaderboardPayload(store.readLeaderboardSnapshot());
  }

  async function getLeaderboardPayload() {
    const nowMilliseconds = nowMs();
    const now = Math.floor(nowMilliseconds / 1000);
    const snapshot = store.readLeaderboardSnapshot();
    if (snapshot.meta && Number(snapshot.meta.next_refresh_at) > now) return publicLeaderboardPayload(snapshot);
    if (leaderboardInFlight) return leaderboardInFlight;
    leaderboardInFlight = refreshLeaderboardSnapshot(snapshot, now).finally(() => {
      leaderboardInFlight = null;
    });
    return leaderboardInFlight;
  }

  function invalidateLeaderboard(now) {
    store.invalidateLeaderboardSnapshot(now);
  }

  async function handler(request, response) {
    const identity = resolveRequestIdentity(request, isTrustedProxy);
    const session = getSession(request);
    const url = new URL(request.url || '/', 'http://localhost');
    const path = url.pathname;
    try {
      if (request.method === 'GET' && path === '/') {
        send(response, 302, 'text/plain; charset=utf-8', '', { Location: '/my' });
        return;
      }
      if (request.method === 'GET' && (path === '/my' || path === '/packy-my-usage.html')) {
        send(response, 200, 'text/html; charset=utf-8', assets.my);
        return;
      }
      if (request.method === 'GET' && (path === '/leaderboard' || path === '/packy-key-usage.html')) {
        send(response, 200, 'text/html; charset=utf-8', assets.leaderboard);
        return;
      }
      if (request.method === 'GET' && path === '/packy-usage.css') {
        send(response, 200, 'text/css; charset=utf-8', assets.css);
        return;
      }
      if (request.method === 'GET' && path === '/api/me') {
        sendJson(response, 200, await getPrivatePayload(requireSession(session)));
        return;
      }
      if (request.method === 'POST' && path === '/api/accounts/register') {
        requireMutationSecurity(request, identity);
        limiter.check(identity.clientIp);
        const body = await readJsonBody(request);
        const key = typeof body.key === 'string' ? body.key.trim() : '';
        if (!KEY_PATTERN.test(key)) {
          limiter.fail(identity.clientIp);
          throw new PublicError(400, 'Key 格式无效。');
        }
        const fingerprint = store.fingerprint(key);
        let account = store.findByFingerprint(fingerprint);
        let created = false;
        if (account) {
          store.bindIp(account.id, identity.clientIp, Math.floor(nowMs() / 1000));
        } else {
          let data;
          try {
            data = await queryUsage(key);
          } catch {
            limiter.fail(identity.clientIp);
            throw new PublicError(400, 'Key 无效，或 PackyAPI 暂时无法查询。');
          }
          const timestamp = Math.floor(nowMs() / 1000);
          const name = String(data.name || 'PackyAPI 账号').trim() || 'PackyAPI 账号';
          try {
            account = store.createAccount({ key, name, origin, ip: identity.clientIp, now: timestamp });
            created = true;
          } catch (error) {
            if (!String(error.message).includes('UNIQUE constraint failed')) throw error;
            account = store.findByFingerprint(fingerprint);
            store.bindIp(account.id, identity.clientIp, timestamp);
          }
          primeUsage(account, data, nowMs());
        }
        const timestamp = Math.floor(nowMs() / 1000);
        const activeSession = session || store.createSession(timestamp, effectiveSessionTtlSeconds);
        store.bindSession(activeSession.id, account.id, timestamp);
        limiter.clear(identity.clientIp);
        sendJson(response, created ? 201 : 200, { ok: true, account: { id: account.id, name: account.name, leaderboardEnabled: Boolean(account.leaderboard_enabled) } }, { 'Set-Cookie': createSessionCookie(activeSession.token, effectiveSessionTtlSeconds) });
        return;
      }

      const leaderboardMatch = path.match(/^\/api\/me\/accounts\/([0-9a-f-]{36})\/leaderboard$/i);
      if (request.method === 'PATCH' && leaderboardMatch) {
        requireMutationSecurity(request, identity);
        const activeSession = requireSession(session);
        const accountId = leaderboardMatch[1];
        if (!store.hasSessionAccount(activeSession.id, accountId)) throw new PublicError(404, '未找到可管理的账号。');
        const body = await readJsonBody(request);
        if (typeof body.enabled !== 'boolean') throw new PublicError(400, 'enabled 必须是布尔值。');
        const changedAt = Math.floor(nowMs() / 1000);
        store.setLeaderboard(accountId, body.enabled, changedAt);
        invalidateLeaderboard(changedAt);
        sendJson(response, 200, { ok: true, leaderboardEnabled: body.enabled });
        return;
      }

      const unbindMatch = path.match(/^\/api\/me\/accounts\/([0-9a-f-]{36})\/ip$/i);
      if (request.method === 'DELETE' && unbindMatch) {
        requireMutationSecurity(request, identity);
        const activeSession = requireSession(session);
        const accountId = unbindMatch[1];
        if (!store.hasSessionAccount(activeSession.id, accountId)) throw new PublicError(404, '未找到可管理的账号。');
        const result = store.unbindSession(activeSession.id, accountId);
        sendJson(response, 200, { ok: true, deletedAccount: false, remainingBindings: result.remaining });
        return;
      }

      if (request.method === 'GET' && path === '/api/leaderboard') {
        sendJson(response, 200, await getLeaderboardPayload());
        return;
      }
      if (request.method === 'GET' && path === '/health') {
        sendJson(response, 200, { ok: true, ...store.counts(), refreshIntervalSeconds: effectiveRefreshSeconds });
        return;
      }
      if (request.method === 'GET' && path === '/favicon.ico') {
        send(response, 204, 'image/x-icon', Buffer.alloc(0));
        return;
      }
      sendJson(response, 404, { message: '未找到请求的资源。' });
    } catch (error) {
      if (response.headersSent || response.writableEnded) {
        response.destroy();
        return;
      }
      const statusCode = error instanceof PublicError ? error.statusCode : 500;
      const message = error instanceof PublicError ? error.message : '服务器暂时无法处理请求。';
      const payload = { message };
      if (statusCode === 401) payload.requiresAuth = true;
      sendJson(response, statusCode, payload, error instanceof PublicError ? error.headers : {});
    }
  }

  return {
    handler,
    store,
    cache,
    close() { store.close(); }
  };
}

function parseCliArgs(argv) {
  const result = { noOpen: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--no-open') result.noOpen = true;
    else if (arg === '--host') result.host = argv[++index];
    else if (arg === '--port') result.port = argv[++index];
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return result;
}

function openBrowser(url) {
  if (process.platform !== 'win32') return;
  const child = spawn('cmd.exe', ['/c', 'start', '', url], { detached: true, stdio: 'ignore', windowsHide: true });
  child.unref();
}

export async function startServer({ argv = process.argv.slice(2), env = process.env } = {}) {
  const args = parseCliArgs(argv);
  const host = args.host || env.HOST || '127.0.0.1';
  const port = Number(args.port || env.PORT || 8765);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('PORT must be between 1024 and 65535.');
  const dataDir = resolve(env.DATA_DIR || join(MODULE_DIR, 'data'));
  const databasePath = resolve(env.DB_PATH || join(dataDir, 'packy-usage.sqlite'));
  const masterKey = loadMasterKey({ dataDir, env });
  const trustedProxyCidrs = String(env.TRUSTED_PROXY_CIDRS || '').split(',').map((item) => item.trim()).filter(Boolean);
  const app = createPackyApp({
    databasePath,
    masterKey,
    refreshSeconds: Math.max(DEFAULT_REFRESH_SECONDS, Number(env.REFRESH_INTERVAL_SECONDS || DEFAULT_REFRESH_SECONDS)),
    trustedProxyCidrs,
    packyOrigin: env.PACKY_ORIGIN || DEFAULT_ORIGIN
  });
  const server = createServer(app.handler);

  await new Promise((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolveListen);
  });
  const url = `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}/my`;
  console.log(`PackyAPI usage service: ${url}`);
  console.log(`Database: ${databasePath}`);
  console.log(`Trusted proxies: ${trustedProxyCidrs.length ? trustedProxyCidrs.join(', ') : 'none'}`);
  if (!args.noOpen) openBrowser(url);

  const shutdown = () => {
    server.close(() => {
      app.close();
      process.exit(0);
    });
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
  return { app, server, url };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  startServer().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
