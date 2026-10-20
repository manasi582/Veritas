'use strict';
// Veritas Payload Tap for Node services (Express and anything with (req, res, next) middleware).
//
//   const { Tap } = require('./veritas_tap');
//   const tap = Tap.fromEnv();   // VERITAS_TAP_URL, VERITAS_TAP_TOKEN, VERITAS_TAP_ORG, VERITAS_TAP_SYSTEM
//   app.use(express.json());
//   app.use(tap.express());      // after the body parser
//
// It finds structured personal data in JSON requests and responses with the same rules as the server and the agent,
// masks the values inside your process, and reports which route carried which kind of data in which field: placeholders,
// field paths, route and status, never a value. It never delays, changes or fails a request (work runs after the
// response, with a bounded queue, short timeouts and a circuit breaker). It does not find names. See docs/PAYLOAD_TAP.md.

const vr = require('./veritas_recognizers');

const MAX_DEPTH = 8;
const MAX_NODES = 2000;
const ID_SEGMENT = /^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$/;

function walk(value, path, out, budget, depth) {
  if (budget.n <= 0 || depth > MAX_DEPTH) return;
  budget.n -= 1;
  if (Array.isArray(value)) value.slice(0, 200).forEach((v) => walk(v, `${path}[]`, out, budget, depth + 1));
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) walk(v, path ? `${path}.${k}` : String(k), out, budget, depth + 1);
  else if (typeof value === 'string') out.push([path, value]);
  else if (typeof value === 'number') out.push([path, String(value)]);
}

/** {fields, counts}: the leaves of a decoded JSON body that hold personal data, masked, with array positions as []. */
function inspectBody(body, { mode = 'mask', key = null, maxFields = 50 } = {}) {
  const leaves = [];
  walk(body, '', leaves, { n: MAX_NODES }, 0);
  const fields = {};
  const counts = {};
  for (const [path, raw] of leaves) {
    const value = raw.length > 4000 ? raw.slice(0, 4000) : raw;
    const dets = vr.scan(value);
    if (!dets.length) continue;
    let masked;
    if (mode === 'hash' && key) {
      let out = ''; let pos = 0;
      for (const s of vr.coveredSpans(dets)) { out += value.slice(pos, s.start) + vr.hashToken(s.label, value.slice(s.start, s.end), key); pos = s.end; }
      masked = out + value.slice(pos);
    } else masked = vr.mask(value, dets);
    for (const s of vr.coveredSpans(dets)) counts[s.label.toLowerCase()] = (counts[s.label.toLowerCase()] || 0) + 1;
    if (Object.keys(fields).length < maxFields) fields[path] = masked.slice(0, 500);
  }
  return { fields, counts };
}

function routeTemplate(path, route) {
  if (route) return String(route).slice(0, 200);
  return String(path || '/').split('/').map((seg) => (ID_SEGMENT.test(seg) ? '{id}' : seg)).join('/').slice(0, 200);
}

class Tap {
  constructor({ url, token, org, system, mode = 'mask', hashKey = null, sampleEvery = 1, minIntervalSeconds = 5,
                maxBodyBytes = 65536, queueSize = 500, timeoutMs = 3000, start = true, post = null } = {}) {
    if (!['mask', 'hash'].includes(mode)) throw new Error('mode must be mask or hash');
    if (mode === 'hash' && !hashKey) throw new Error('mode hash needs hashKey (the organization key delivered at registration)');
    this.endpoint = `${String(url).replace(/\/+$/, '')}/v1/${org}/events`;
    Object.assign(this, { token, system, mode, hashKey, sampleEvery: Math.max(1, sampleEvery), minInterval: minIntervalSeconds * 1000,
                          maxBody: maxBodyBytes, queueSize, timeoutMs });
    this.queue = [];
    this.stats = { seen: 0, reported: 0, sent: 0, droppedFull: 0, failed: 0, maskingErrors: 0, skippedInterval: 0 };
    this.seenAt = new Map();
    this.n = 0; this.failures = 0; this.pausedUntil = 0; this.sending = false;
    this._post = post || ((event) => this._defaultPost(event));
    this.autostart = start;
  }

  static fromEnv(extra = {}) {
    const e = process.env;
    const key = e.VERITAS_TAP_HASH_KEY ? Buffer.from(e.VERITAS_TAP_HASH_KEY, 'hex') : null;
    return new Tap({ url: e.VERITAS_TAP_URL, token: e.VERITAS_TAP_TOKEN, org: e.VERITAS_TAP_ORG, system: e.VERITAS_TAP_SYSTEM,
                     mode: key ? 'hash' : 'mask', hashKey: key, ...extra });
  }

  observe(method, path, status, direction, body, route) {
    try {
      this.stats.seen += 1; this.n += 1;
      if (this.n % this.sampleEvery || !body || body.length > this.maxBody) return;
      let decoded = body;
      if (Buffer.isBuffer(body) || typeof body === 'string') {
        try { decoded = JSON.parse(body.toString()); } catch (_) { return; }
      }
      let r;
      try { r = inspectBody(decoded, { mode: this.mode, key: this.hashKey }); } catch (_) { this.stats.maskingErrors += 1; return; }
      const names = Object.keys(r.fields);
      if (!names.length) return;
      const tmpl = routeTemplate(path, route);
      const sig = [method, tmpl, status, direction, names.slice().sort().join(',')].join('|');
      const now = Date.now();
      const last = this.seenAt.get(sig);
      if (last !== undefined && now - last < this.minInterval) { this.stats.skippedInterval += 1; return; }
      if (this.seenAt.size > 5000) this.seenAt.clear();
      this.seenAt.set(sig, now);
      const event = {
        source_type: 'api', source_kind: 'api', source_system: this.system,
        raw_snippet: `${method} ${tmpl} ${status} ${direction} carrying personal data in ${names.length} field(s)`,
        fields: r.fields, schema: 2, redaction_mode: this.mode, recognizer_pack_version: vr.PACK_VERSION, agent_detections: r.counts,
      };
      this.stats.reported += 1;
      if (this.queue.length >= this.queueSize) { this.queue.shift(); this.stats.droppedFull += 1; }
      this.queue.push(event);
      if (this.autostart) this._kick();
    } catch (_) { /* the tap must never break the application */ }
  }

  _kick() {
    if (this.sending) return;
    this.sending = true;
    setImmediate(async () => {
      while (this.queue.length) {
        const event = this.queue.shift();
        if (Date.now() < this.pausedUntil) { this.stats.failed += 1; continue; }
        try { await this._post(event); this.stats.sent += 1; this.failures = 0; }
        catch (e) {
          this.stats.failed += 1;
          if (e && e.retryAfter) this.pausedUntil = Date.now() + e.retryAfter * 1000;
          else { this.failures += 1; if (this.failures >= 5) { this.pausedUntil = Date.now() + 60000; this.failures = 0; } }
        }
      }
      this.sending = false;
    });
  }

  async _defaultPost(event) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.timeoutMs);
    try {
      const r = await fetch(this.endpoint, { method: 'POST', signal: ctl.signal, body: JSON.stringify(event),
                                             headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' } });
      if (r.status === 429 || r.status === 503) { const e = new Error('busy'); e.retryAfter = Number(r.headers.get('retry-after')) || 5; throw e; }
      await r.arrayBuffer();
    } finally { clearTimeout(timer); }
  }

  async flush(timeoutMs = 5000) {
    const end = Date.now() + timeoutMs;
    while ((this.queue.length || this.sending) && Date.now() < end) await new Promise((r) => setTimeout(r, 10));
  }

  /** Express middleware: use after express.json(). */
  express() {
    return (req, res, next) => {
      const chunks = [];
      let size = 0;
      const maxBody = this.maxBody;
      const originalWrite = res.write;
      const originalEnd = res.end;
      const keep = (chunk, enc) => {
        if (chunk == null || typeof chunk === 'function') return;
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), typeof enc === 'string' ? enc : 'utf8');
        size += buf.length;
        if (size <= maxBody) chunks.push(buf);
      };
      res.write = function (chunk, enc, cb) { try { keep(chunk, enc); } catch (_) {} return originalWrite.call(this, chunk, enc, cb); };
      res.end = function (chunk, enc, cb) { try { keep(chunk, enc); } catch (_) {} return originalEnd.call(this, chunk, enc, cb); };
      res.on('finish', () => {
        setImmediate(() => {
          try {
            const route = req.route && req.route.path ? (req.baseUrl || '') + req.route.path : null;
            const path = req.originalUrl ? req.originalUrl.split('?')[0] : req.path;
            if (req.body && typeof req.body === 'object' && Object.keys(req.body).length) {
              const raw = JSON.stringify(req.body);
              if (raw.length <= maxBody) this.observe(req.method, path, res.statusCode, 'request', raw, route);
            }
            const type = String(res.getHeader('content-type') || '');
            if (type.includes('json') && chunks.length && size <= maxBody) this.observe(req.method, path, res.statusCode, 'response', Buffer.concat(chunks), route);
          } catch (_) { /* never harm the application */ }
        });
      });
      next();
    };
  }

  close() { this.autostart = false; }
}

module.exports = { Tap, inspectBody, routeTemplate };
