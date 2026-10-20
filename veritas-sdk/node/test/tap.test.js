'use strict';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { Tap, inspectBody, routeTemplate } = require('../veritas_tap');

const PHONE = '9876543210'; const AADHAAR = '2345 6789 0124'; const EMAIL = 'asha.rao@example.com';
const RAW = [PHONE, AADHAAR, '234567890124', EMAIL, 'asha.rao'];
const make = (extra = {}) => new Tap({ url: 'http://127.0.0.1:1', token: 't', org: 'org_a', system: 'customer-api', start: false, minIntervalSeconds: 0, ...extra });

test('a nested body gives masked fields with paths and counts', () => {
  const r = inspectBody({ user: { phone: PHONE, email: EMAIL, nick: 'asha' }, items: [{ mobile: PHONE }, { mobile: PHONE }], total: 5 });
  assert.deepStrictEqual(r.fields, { 'user.phone': '[PHONE_REDACTED]', 'user.email': '[EMAIL_REDACTED]', 'items[].mobile': '[PHONE_REDACTED]' });
  assert.deepStrictEqual(r.counts, { phone: 3, email: 1 });
});

test('an event carries placeholders, paths and counts and no value', () => {
  const tap = make();
  tap.observe('GET', '/customers/42', 200, 'response', JSON.stringify({ user: { phone: PHONE, aadhaar: AADHAAR } }));
  const e = tap.queue[0];
  assert.strictEqual(e.source_kind, 'api');
  assert.strictEqual(e.raw_snippet, 'GET /customers/{id} 200 response carrying personal data in 2 field(s)');
  assert.deepStrictEqual(e.agent_detections, { phone: 1, aadhaar: 1 });
  for (const raw of RAW) assert.ok(!JSON.stringify(e).includes(raw), raw);
});

test('clean bodies, big bodies and non-JSON report nothing', () => {
  const tap = make({ maxBodyBytes: 100 });
  tap.observe('GET', '/a', 200, 'response', '{"status":"ok"}');
  tap.observe('GET', '/a', 200, 'response', JSON.stringify({ phone: PHONE, pad: 'x'.repeat(500) }));
  tap.observe('GET', '/a', 200, 'response', 'not json');
  assert.strictEqual(tap.queue.length, 0);
});

test('the same route and fields are reported once per interval', () => {
  const tap = make({ minIntervalSeconds: 60 });
  for (let i = 0; i < 20; i += 1) tap.observe('GET', '/c/1', 200, 'response', JSON.stringify({ phone: PHONE }));
  assert.strictEqual(tap.queue.length, 1);
  assert.strictEqual(tap.stats.skippedInterval, 19);
});

test('a full queue drops the oldest', () => {
  const tap = make({ queueSize: 3 });
  for (let i = 0; i < 10; i += 1) tap.observe('GET', `/r${i}`, 200, 'response', JSON.stringify({ phone: PHONE }));
  assert.strictEqual(tap.queue.length, 3);
  assert.strictEqual(tap.stats.droppedFull, 7);
});

test('route templates', () => {
  assert.strictEqual(routeTemplate('/customers/123/orders/9f1c2b3a-1111-2222-3333-444455556666'), '/customers/{id}/orders/{id}');
  assert.strictEqual(routeTemplate('/customers/123', '/customers/:id'), '/customers/:id');
});

test('configuration is checked', () => {
  assert.throws(() => make({ mode: 'hash' }));
  assert.throws(() => make({ mode: 'scramble' }));
});

test('hash mode gives keyed tokens', () => {
  const key = Buffer.from('k'.repeat(32));
  const r = inspectBody({ user: { phone: PHONE } }, { mode: 'hash', key });
  assert.ok(r.fields['user.phone'].startsWith('[PHONE#') && !JSON.stringify(r).includes(PHONE));
});

test('express middleware reports both directions and leaves the response intact', async () => {
  const tap = make({ start: true, post: async (e) => { sent.push(e); } });
  const sent = [];
  const mw = tap.express();
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      req.body = JSON.parse(Buffer.concat(chunks).toString() || '{}');
      mw(req, res, () => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ user: { phone: PHONE } }));
      });
    });
  });
  await new Promise((r) => server.listen(0, r));
  const port = server.address().port;
  const resp = await fetch(`http://127.0.0.1:${port}/customers/7`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: EMAIL }) });
  assert.deepStrictEqual(await resp.json(), { user: { phone: PHONE } });          // the caller sees the real response
  await tap.flush();
  server.close();
  assert.strictEqual(sent.length, 2);
  assert.deepStrictEqual(sent.map((e) => e.raw_snippet.split(' ')[3]).sort(), ['request', 'response']);
  for (const raw of RAW) assert.ok(!JSON.stringify(sent).includes(raw), raw);
});

test('a down server never blocks and the breaker opens', async () => {
  const tap = new Tap({ url: 'http://127.0.0.1:1', token: 't', org: 'o', system: 's', minIntervalSeconds: 0, timeoutMs: 200 });
  const t = Date.now();
  for (let i = 0; i < 200; i += 1) tap.observe('GET', `/r${i % 9}`, 200, 'response', JSON.stringify({ phone: PHONE, n: i }));
  assert.ok(Date.now() - t < 1500);
  await tap.flush(8000);
  assert.ok(tap.stats.failed > 0);
});
