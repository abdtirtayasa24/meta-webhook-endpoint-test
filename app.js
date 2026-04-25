const express = require('express');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;
const appSecret = process.env.APP_SECRET;

// Capture raw body for signature validation and parse JSON
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// Simple request logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

function computeSignature(secret, payload) {
  return `sha256=${crypto.createHmac('sha256', secret).update(payload).digest('hex')}`;
}

function verifySignature(req) {
  if (!appSecret) {
    return true;
  }

  const signatureHeader = req.get('x-hub-signature-256');
  if (!signatureHeader) {
    console.warn('Missing x-hub-signature-256 header.');
    return false;
  }

  const expectedSignature = computeSignature(appSecret, req.rawBody || Buffer.from(''));
  return crypto.timingSafeEqual(Buffer.from(signatureHeader), Buffer.from(expectedSignature));
}

app.get('/', (req, res) => {
  res.status(200).json({
    status: 'ok',
    message: 'Meta webhook endpoint is running.',
    webhook: '/webhook',
    requireVerifyToken: Boolean(verifyToken),
    requireAppSecret: Boolean(appSecret)
  });
});

app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const challenge = req.query['hub.challenge'];
  const token = req.query['hub.verify_token'];

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('Webhook verification succeeded.');
    return res.status(200).send(challenge);
  }

  console.warn('Webhook verification failed.', {
    mode,
    tokenProvided: Boolean(token),
    expectedToken: Boolean(verifyToken)
  });
  return res.status(403).json({ error: 'Verification failed' });
});

app.post('/webhook', (req, res) => {
  if (!verifySignature(req)) {
    return res.status(401).json({ error: 'Invalid request signature' });
  }

  const payload = req.body;
  console.log('Received webhook payload:');
  console.log(JSON.stringify(payload, null, 2));

  if (!payload || !Array.isArray(payload.entry)) {
    return res.status(400).json({ error: 'Unexpected webhook format' });
  }

  const summary = payload.entry.map((entry) => {
    return {
      id: entry.id,
      time: entry.time,
      changes: Array.isArray(entry.changes) ? entry.changes.length : 0
    };
  });

  console.log('Payload summary:', JSON.stringify(summary, null, 2));

  return res.status(200).json({ status: 'processed', entries: summary.length });
});

app.use((err, req, res, next) => {
  console.error('Unexpected error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
  console.log(`GET  / -> health check`);
  console.log(`GET  /webhook -> verification endpoint`);
  console.log(`POST /webhook -> webhook receiver`);
});
