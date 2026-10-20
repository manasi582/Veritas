'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vr = require('../veritas_recognizers');

const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', '..', 'tests', 'vectors', 'recognizers_corpus.json'), 'utf8'));

test('the Node pack is the same pack as the Python one', () => {
  assert.strictEqual(vr.PACK_VERSION, corpus.pack_version);
});

for (const c of corpus.cases) {
  test(`golden corpus: ${JSON.stringify(c.text.slice(0, 40))}`, () => {
    const found = vr.scan(c.text).map((d) => [d.entityType, c.text.slice(d.start, d.end), d.validation]);
    const want = c.detections.map((d) => [d.entity_type, d.text, d.validation]);
    assert.deepStrictEqual(found, want);
    assert.strictEqual(vr.mask(c.text), c.masked);
  });
}

test('keyed tokens equal the Python ones', () => {
  const key = Buffer.from('k'.repeat(32));
  assert.strictEqual(vr.hashToken('PHONE', '+91 98765 43210', key), '[PHONE#f28328.070a14b0793a58e5]');
  assert.strictEqual(vr.hashToken('phone', '9876543210', key), vr.hashToken('PHONE', '91-9876543210', key));
});

test('validators', () => {
  assert.ok(vr.isValidAadhaar('2345 6789 0124'));
  assert.ok(!vr.isValidAadhaar('1234 5678 9012'));
  assert.ok(vr.isValidPan('ABCPE1234F') && !vr.isValidPan('ABCDE1234F'));
  assert.ok(vr.luhnValid('4111 1111 1111 1111') && !vr.luhnValid('4111 1111 1111 1112'));
});
