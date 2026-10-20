'use strict';
// The Veritas recognizer pack for Node: the same rules as dpdpa-agent/veritas_recognizers.py (Aadhaar with its
// Verhoeff checksum, PAN, Indian mobile numbers, e-mail, payment cards with the Luhn check), ported by hand and
// held to the same golden corpus (tests/vectors/recognizers_corpus.json) by test/recognizers.test.js.
// No dependencies. It does not find names.

const crypto = require('crypto');

const PACK_VERSION = '1.2.0';
const LABELS = { IN_AADHAAR: 'AADHAAR', IN_PAN: 'PAN', IN_PHONE: 'PHONE', EMAIL_ADDRESS: 'EMAIL', CREDIT_CARD: 'CARD' };
const PRIORITY = { IN_AADHAAR: 100, IN_PAN: 100, CREDIT_CARD: 100, IN_PHONE: 90, EMAIL_ADDRESS: 90 };

const W = '[\\p{L}\\p{N}_]';            // Python's \w is Unicode-aware; so is this
const EMAIL = new RegExp(
  `\\b(((${'[!#$%&\'*+\\-/=?^_`{|}~\\p{L}\\p{N}]'})|(${'[!#$%&\'*+\\-/=?^_`{|}~\\p{L}\\p{N}]'}${'[!#$%&\'*+\\-/=?^_`{|}~.\\p{L}\\p{N}]'}{0,}${'[!#$%&\'*+\\-/=?^_`{|}~\\p{L}\\p{N}]'}))` +
  `[@]${W}+(?:-+${W}+)*(?:\\.${W}+(?:-+${W}+)*)+)\\b`, 'gu');

const RULES = [
  ['IN_AADHAAR', 0.75, /\b\d{4}\s\d{4}\s\d{4}\b/g],
  ['IN_AADHAAR', 0.4, /\b\d{12}\b/g],
  ['IN_PAN', 0.85, /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g],
  ['IN_PHONE', 0.9, /(?<!\w)(?:\+91[\s-]?|91[\s-]?)[6-9]\d{9}\b/g],
  ['IN_PHONE', 0.75, /\b[6-9]\d{9}\b/g],
  ['EMAIL_ADDRESS', 0.5, EMAIL],
  ['CREDIT_CARD', 0.5, /\b(?:\d[ -]?){12,18}\d\b/g],
];

const D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],
  [5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],
  [4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
const PAN_TYPES = new Set('ABCFGHLJPT');

function isValidAadhaar(value) {
  const s = String(value).replace(/\s+/g, '');
  if (s.length !== 12 || !/^\d{12}$/.test(s) || s[0] === '0') return false;
  let c = 0;
  [...s].reverse().forEach((ch, i) => { c = D[c][P[i % 8][Number(ch)]]; });
  return c === 0;
}

function isValidPan(value) {
  const v = String(value).trim();
  return /^[A-Z]{5}[0-9]{4}[A-Z]$/.test(v) && PAN_TYPES.has(v[3]);
}

function luhnValid(value) {
  const digits = String(value).replace(/[ -]/g, '');
  if (digits.length < 13 || digits.length > 19 || !/^\d+$/.test(digits)) return false;
  let total = 0;
  [...digits].reverse().forEach((ch, i) => {
    let n = Number(ch);
    if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
    total += n;
  });
  return total % 10 === 0;
}

function emailPlausible(value) {
  const tld = value.slice(value.lastIndexOf('.') + 1);
  return tld.length >= 2 && /^\p{L}+$/u.test(tld) && value.length <= 254;
}

/** Every finding in `text`: [{entityType, start, end, score, validation, label}], in order of position. */
function scan(text) {
  if (!text || !text.trim()) return [];
  let found = [];
  const seen = new Set();
  for (const [entityType, score, rx] of RULES) {
    rx.lastIndex = 0;
    for (const m of text.matchAll(rx)) {
      const value = m[0];
      let validation = 'none';
      if (entityType === 'IN_AADHAAR') { if (!isValidAadhaar(value)) continue; validation = 'validated'; }
      else if (entityType === 'IN_PAN') validation = isValidPan(value) ? 'validated' : 'failed';
      else if (entityType === 'CREDIT_CARD') { if (!luhnValid(value)) continue; validation = 'validated'; }
      else if (entityType === 'EMAIL_ADDRESS' && !emailPlausible(value)) continue;
      const key = `${entityType}:${m.index}:${m.index + value.length}`;
      if (seen.has(key)) continue;
      seen.add(key);
      found.push({ entityType, start: m.index, end: m.index + value.length, score, validation, label: LABELS[entityType] });
    }
  }
  found.sort((a, b) => (b.score - a.score) || (a.start - b.start) || ((b.end - b.start) - (a.end - a.start)));
  const kept = [];
  for (const d of found) {
    if (!kept.some((k) => k.entityType === d.entityType && d.start >= k.start && d.end <= k.end)) kept.push(d);
  }
  return kept.sort((a, b) => (a.start - b.start) || (a.end - b.end) || (a.entityType < b.entityType ? -1 : 1));
}

function coveredSpans(detections) {
  const spans = [];
  for (const d of [...detections].sort((a, b) => (a.start - b.start) || (a.end - b.end))) {
    const top = spans[spans.length - 1];
    if (top && d.start < top.end) {
      top.end = Math.max(top.end, d.end);
      if (PRIORITY[d.entityType] > top.priority) { top.label = d.label; top.priority = PRIORITY[d.entityType]; }
    } else {
      spans.push({ start: d.start, end: d.end, label: d.label, priority: PRIORITY[d.entityType] });
    }
  }
  return spans;
}

const placeholder = (label) => `[${label}_REDACTED]`;

function mask(text, detections) {
  const dets = detections || scan(text);
  let out = '';
  let pos = 0;
  for (const s of coveredSpans(dets)) { out += text.slice(pos, s.start) + placeholder(s.label); pos = s.end; }
  return out + text.slice(pos);
}

function normaliseIdentifier(label, value) {
  label = label.toUpperCase();
  const v = String(value || '').trim();
  if (label === 'AADHAAR' || label === 'CARD') return v.replace(/\D/g, '');
  if (label === 'PAN') return v.toUpperCase();
  if (label === 'EMAIL') return v.toLowerCase();
  if (label === 'PHONE') { const d = v.replace(/\D/g, ''); return d.length > 10 ? d.slice(-10) : d; }
  return v;
}

const keyIdOf = (key) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from('veritas-kid:'), key])).digest('hex').slice(0, 6);

function keyedDigest(label, value, key) {
  label = label.toUpperCase();
  return crypto.createHmac('sha256', key).update(`${label}\n${normaliseIdentifier(label, value)}`, 'utf8').digest('hex');
}

const hashToken = (label, value, key) => `[${label.toUpperCase()}#${keyIdOf(key)}.${keyedDigest(label, value, key).slice(0, 16)}]`;

module.exports = { PACK_VERSION, LABELS, scan, mask, coveredSpans, placeholder, isValidAadhaar, isValidPan, luhnValid,
                   normaliseIdentifier, keyedDigest, keyIdOf, hashToken };
