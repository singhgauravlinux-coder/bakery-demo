'use strict';
const express = require('express');
const pino = require('pino');
const pinoHttp = require('pino-http');
const crypto = require('crypto');
const { Pool } = require('pg');

const SERVICE_NAME = process.env.SERVICE_NAME || 'auth-service';
const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL || '';
const TOKEN_SECRET = process.env.AUTH_TOKEN_SECRET || 'dev-only-secret-change-me';
const TOKEN_TTL_MS = Number(process.env.AUTH_TOKEN_TTL_MS || 24 * 60 * 60 * 1000);

// All logs are structured JSON on stdout (12-factor), ready for
// Fluent Bit / Loki / ELK collection from the container runtime.
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  timestamp: pino.stdTimeFunctions.isoTime,
  base: { service: SERVICE_NAME, version: process.env.SERVICE_VERSION || '1.0.0' },
  formatters: { level: (label) => ({ level: label }) },
  redact: ['req.headers.authorization']
});

if (TOKEN_SECRET === 'dev-only-secret-change-me')
  logger.warn({ event: 'insecure_config' }, 'AUTH_TOKEN_SECRET is not set — using an insecure default');

// --- Password hashing (scrypt, no native deps) --------------------------
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32);
  return `scrypt$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}
function verifyPassword(password, stored) {
  try {
    const [, saltB64, hashB64] = stored.split('$');
    const expected = Buffer.from(hashB64, 'base64url');
    const actual = crypto.scryptSync(password, Buffer.from(saltB64, 'base64url'), expected.length);
    return crypto.timingSafeEqual(actual, expected);
  } catch { return false; }
}

// --- Stateless signed tokens (HMAC-SHA256) -------------------------------
function signToken(userId) {
  const payload = Buffer.from(JSON.stringify({ sub: userId, exp: Date.now() + TOKEN_TTL_MS })).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function verifyToken(token) {
  try {
    const [payload, sig] = String(token).split('.');
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest();
    const given = Buffer.from(sig, 'base64url');
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!data.sub || Date.now() > data.exp) return null;
    return data.sub;
  } catch { return null; }
}

// --- Storage: PostgreSQL when DATABASE_URL is set, in-memory otherwise ---
const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL, max: 10 }) : null;
if (pool) pool.on('error', (err) => logger.error({ event: 'pg_pool_error', message: err.message }, 'postgres pool error'));

const memoryAccounts = new Map();

const store = pool ? {
  mode: 'postgres',
  async find(email) {
    const { rows } = await pool.query(
      'SELECT email, user_id AS "userId", name, password_hash AS "passwordHash" FROM accounts WHERE email = $1', [email]);
    return rows[0] || null;
  },
  async create(email, name, passwordHash) {
    const { rows } = await pool.query(
      `INSERT INTO accounts (email, user_id, name, password_hash)
       VALUES ($1, 'u-' || substr(md5(random()::text), 1, 8), $2, $3)
       ON CONFLICT (email) DO NOTHING
       RETURNING user_id AS "userId"`, [email, name, passwordHash]);
    return rows[0] || null;
  },
  async ping() { await pool.query('SELECT 1'); }
} : {
  mode: 'memory',
  async find(email) { return memoryAccounts.get(email) || null; },
  async create(email, name, passwordHash) {
    if (memoryAccounts.has(email)) return null;
    const account = { email, userId: 'u-' + (memoryAccounts.size + 1), name, passwordHash };
    memoryAccounts.set(email, account);
    return { userId: account.userId };
  },
  async ping() {}
};

// Seed the demo account through the same hashing code path.
async function seedDemoAccount() {
  try {
    const email = 'amelie@crumbandember.dev';
    if (!(await store.find(email))) {
      await store.create(email, 'Amelie', hashPassword('baguette'));
      logger.info({ event: 'demo_account_seeded', email }, 'demo account ready');
    }
  } catch (err) {
    logger.warn({ event: 'seed_deferred', message: err.message }, 'demo seed will succeed once the database is up');
  }
}

const app = express();
app.use(express.json());
app.use(pinoHttp({
  logger,
  customProps: (req) => ({ requestId: req.headers['x-request-id'] || undefined })
}));

// --- Kubernetes probes -------------------------------------------------
app.get('/health', (req, res) => res.json({ status: 'ok', service: SERVICE_NAME }));
app.get('/ready', async (req, res) => {
  try {
    await store.ping();
    res.json({ ready: true, service: SERVICE_NAME, storage: store.mode });
  } catch (err) {
    req.log.warn({ event: 'readiness_failed', message: err.message }, 'database unreachable');
    res.status(503).json({ ready: false, service: SERVICE_NAME, storage: store.mode });
  }
});

// --- Login, registration and token verification ---
app.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    const account = email ? await store.find(email) : null;
    if (!account || !verifyPassword(password || '', account.passwordHash)) {
      req.log.warn({ event: 'login_failed', email }, 'invalid credentials');
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    req.log.info({ event: 'login_success', userId: account.userId }, 'user logged in');
    res.json({ token: signToken(account.userId), userId: account.userId, name: account.name });
  } catch (err) { next(err); }
});

app.post('/register', async (req, res, next) => {
  try {
    const { email, password, name } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
    if (password.length < 8) return res.status(400).json({ error: 'password must be at least 8 characters' });
    const created = await store.create(email, name || email, hashPassword(password));
    if (!created) return res.status(409).json({ error: 'An account with that email already exists' });
    req.log.info({ event: 'user_registered', userId: created.userId }, 'new account created');
    res.status(201).json({ userId: created.userId });
  } catch (err) { next(err); }
});

app.get('/verify', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const userId = verifyToken(token);
  if (!userId) return res.status(401).json({ valid: false });
  res.json({ valid: true, userId });
});

// --- 404 + error handling ----------------------------------------------
app.use((req, res) => res.status(404).json({ error: 'Route not found' }));
app.use((err, req, res, next) => {
  req.log.error({ event: 'unhandled_error', message: err.message }, 'request failed');
  res.status(500).json({ error: 'Internal server error' });
});

const server = app.listen(PORT, () => {
  logger.info({ event: 'service_started', port: PORT, storage: store.mode }, `${SERVICE_NAME} listening`);
  seedDemoAccount();
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    logger.info({ event: 'shutdown', signal }, 'shutting down gracefully');
    server.close(async () => { if (pool) await pool.end().catch(() => {}); process.exit(0); });
  });
}
