'use strict';

/**
 * @fileoverview Tests for headercheck package.
 * @author idirdev
 */

const test   = require('node:test');
const assert = require('node:assert/strict');
const http   = require('http');

const {
  gradeHeaders,
  checkHeaders,
  summary,
  SECURITY_HEADERS,
  formatTable,
} = require('../src/index.js');

/** Start a test HTTP server that returns specific headers. */
function startServer(responseHeaders, port = 0) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, responseHeaders);
      res.end();
    });
    server.listen(port, '127.0.0.1', () => {
      resolve(server);
    });
  });
}

test('gradeHeaders: all present returns A', () => {
  const results = SECURITY_HEADERS.map(h => ({ present: true, severity: h.severity }));
  assert.equal(gradeHeaders(results), 'A');
});

test('gradeHeaders: all missing returns F', () => {
  const results = SECURITY_HEADERS.map(h => ({ present: false, severity: h.severity }));
  assert.equal(gradeHeaders(results), 'F');
});

test('gradeHeaders: missing only low-severity returns high grade', () => {
  const results = SECURITY_HEADERS.map(h => ({
    present:  h.severity !== 'low',
    severity: h.severity,
  }));
  const grade = gradeHeaders(results);
  assert.ok(['A', 'B'].includes(grade), `Expected A or B, got ${grade}`);
});

test('gradeHeaders: missing critical headers drops grade', () => {
  const results = SECURITY_HEADERS.map(h => ({
    present:  h.severity !== 'critical',
    severity: h.severity,
  }));
  const grade = gradeHeaders(results);
  assert.ok(['C', 'D', 'E', 'F'].includes(grade), `Expected C-F, got ${grade}`);
});

test('checkHeaders: detects present security headers', async () => {
  const server = await startServer({
    'content-security-policy':   "default-src 'self'",
    'x-frame-options':           'DENY',
    'x-content-type-options':    'nosniff',
    'strict-transport-security': 'max-age=31536000',
  });
  const { port } = server.address();
  try {
    const result = await checkHeaders(`http://127.0.0.1:${port}/`);
    const csp = result.results.find(r => r.header === 'content-security-policy');
    assert.ok(csp.present, 'CSP header should be present');
    assert.ok(csp.value.includes("default-src 'self'"), 'CSP value should match');
  } finally {
    await new Promise(r => server.close(r));
  }
});

test('checkHeaders: detects missing security headers', async () => {
  const server = await startServer({ 'x-custom-header': 'value' });
  const { port } = server.address();
  try {
    const result = await checkHeaders(`http://127.0.0.1:${port}/`);
    const csp = result.results.find(r => r.header === 'content-security-policy');
    assert.ok(!csp.present, 'CSP should be missing');
  } finally {
    await new Promise(r => server.close(r));
  }
});

test('checkHeaders: grade reflects server headers', async () => {
  const server = await startServer({});
  const { port } = server.address();
  try {
    const result = await checkHeaders(`http://127.0.0.1:${port}/`);
    assert.ok(['C', 'D', 'E', 'F'].includes(result.grade),
      `Expected low grade for no security headers, got ${result.grade}`);
  } finally {
    await new Promise(r => server.close(r));
  }
});

test('checkHeaders: returns statusCode', async () => {
  const server = await startServer({});
  const { port } = server.address();
  try {
    const result = await checkHeaders(`http://127.0.0.1:${port}/`);
    assert.equal(result.statusCode, 200);
  } finally {
    await new Promise(r => server.close(r));
  }
});

test('summary: aggregates multiple results correctly', () => {
  const checks = [
    { grade: 'A', results: [] },
    { grade: 'F', results: [{ present: false, header: 'content-security-policy' }] },
  ];
  const s = summary(checks);
  assert.equal(s.checked, 2);
  assert.ok(s.missingHeaders['content-security-policy'] >= 1);
});

test('SECURITY_HEADERS: contains at least 12 entries', () => {
  assert.ok(SECURITY_HEADERS.length >= 12, `Expected >= 12, got ${SECURITY_HEADERS.length}`);
});

test('formatTable: outputs grade and URL in header line', async () => {
  const server = await startServer({ 'x-frame-options': 'DENY' });
  const { port } = server.address();
  try {
    const result = await checkHeaders(`http://127.0.0.1:${port}/`);
    const table  = formatTable(result);
    assert.ok(table.includes('Grade:'), 'Table should contain Grade label');
    assert.ok(table.includes('127.0.0.1'), 'Table should contain URL');
  } finally {
    await new Promise(r => server.close(r));
  }
});
