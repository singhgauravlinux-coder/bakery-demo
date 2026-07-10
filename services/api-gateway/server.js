'use strict';
const express = require('express');
const pino = require('pino');
const pinoHttp = require('pino-http');

const SERVICE_NAME = process.env.SERVICE_NAME || 'api-gateway';
const PORT = Number(process.env.PORT || 3000);

// All logs are structured JSON on stdout (12-factor), ready for
// Fluent Bit / Loki / ELK collection from the container runtime.
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  timestamp: pino.stdTimeFunctions.isoTime,
  base: { service: SERVICE_NAME, version: process.env.SERVICE_VERSION || '1.0.0' },
  formatters: { level: (label) => ({ level: label }) }
});

const app = express();
app.use(express.json());
app.use(pinoHttp({
  logger,
  customProps: (req) => ({ requestId: req.headers['x-request-id'] || undefined })
}));

// --- Kubernetes probes -------------------------------------------------
app.get('/health', (req, res) => res.json({ status: 'ok', service: SERVICE_NAME }));
app.get('/ready', (req, res) => res.json({ ready: true, service: SERVICE_NAME }));

// --- Routes /api/* traffic to domain services ---
// Path prefix -> upstream Kubernetes service (cluster DNS).
const routes = {
  '/api/auth':            'http://auth-service:3000',
  '/api/users':           'http://user-service:3000',
  '/api/products':        'http://product-catalog-service:3000',
  '/api/stock':           'http://inventory-service:3000',
  '/api/prices':          'http://pricing-service:3000',
  '/api/quote':           'http://pricing-service:3000',
  '/api/carts':           'http://cart-service:3000',
  '/api/orders':          'http://order-service:3000',
  '/api/payments':        'http://payment-service:3000',
  '/api/deliveries':      'http://delivery-service:3000',
  '/api/notify':          'http://notification-service:3000',
  '/api/reviews':         'http://review-service:3000',
  '/api/search':          'http://search-service:3000',
  '/api/recommendations': 'http://recommendation-service:3000',
  '/api/promotions':      'http://promotion-service:3000',
  '/api/loyalty':         'http://loyalty-service:3000',
  '/api/recipes':         'http://recipe-service:3000',
  '/api/schedule':        'http://baking-schedule-service:3000',
  '/api/suppliers':       'http://supplier-service:3000',
  '/api/events':          'http://analytics-service:3000',
  '/api/metrics':         'http://analytics-service:3000',
  '/api/media':           'http://media-service:3000',
  '/api/invoices':        'http://invoice-service:3000'
};

app.all('/api/*', async (req, res) => {
  const prefix = Object.keys(routes).find(p => req.path === p || req.path.startsWith(p + '/'));
  if (!prefix) return res.status(404).json({ error: 'No upstream for that path' });
  const upstreamBase = process.env.UPSTREAM_OVERRIDE || routes[prefix];
  const upstreamPath = req.originalUrl.replace('/api', '');
  const requestId = req.headers['x-request-id'] || 'req_' + Math.random().toString(36).slice(2, 10);
  const started = Date.now();
  try {
    const upstreamRes = await fetch(upstreamBase + upstreamPath, {
      method: req.method,
      headers: { 'content-type': 'application/json', 'x-request-id': requestId },
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body || {})
    });
    const body = await upstreamRes.text();
    req.log.info({ event: 'proxy_request', upstream: upstreamBase, path: upstreamPath, status: upstreamRes.status, durationMs: Date.now() - started, requestId }, 'proxied');
    res.status(upstreamRes.status).type('application/json').send(body);
  } catch (err) {
    req.log.error({ event: 'proxy_error', upstream: upstreamBase, path: upstreamPath, message: err.message, requestId }, 'upstream unavailable');
    res.status(502).json({ error: 'Upstream service unavailable' });
  }
});

// --- 404 + error handling ----------------------------------------------
app.use((req, res) => res.status(404).json({ error: 'Route not found' }));
app.use((err, req, res, next) => {
  req.log.error({ event: 'unhandled_error', message: err.message }, 'request failed');
  res.status(500).json({ error: 'Internal server error' });
});

const server = app.listen(PORT, () => logger.info({ event: 'service_started', port: PORT }, `${SERVICE_NAME} listening`));

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    logger.info({ event: 'shutdown', signal }, 'shutting down gracefully');
    server.close(() => process.exit(0));
  });
}
