'use strict';

const { analyze, computeGrade } = require('../src/analyzer');
const { rules } = require('../src/rules');

let passed = 0;
let failed = 0;
let total = 0;

function assert(condition, message) {
  total++;
  if (condition) {
    passed++;
    console.log('  PASS: ' + message);
  } else {
    failed++;
    console.error('  FAIL: ' + message);
  }
}

function assertEqual(actual, expected, message) {
  total++;
  if (actual === expected) {
    passed++;
    console.log('  PASS: ' + message);
  } else {
    failed++;
    console.error('  FAIL: ' + message + ' (expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual) + ')');
  }
}

function suite(name, fn) {
  console.log('\n' + name);
  console.log('-'.repeat(name.length));
  fn();
}

// ---- Tests ----

suite('Rules definitions', function() {
  assert(Array.isArray(rules), 'rules is an array');
  assertEqual(rules.length, 10, 'There are 10 security rules');
  for (const rule of rules) {
    assert(typeof rule.check === 'function', 'Rule ' + rule.id + ' has a check function');
    assert(typeof rule.weight === 'number', 'Rule ' + rule.id + ' has a numeric weight');
    assert(rule.name && rule.header, 'Rule ' + rule.id + ' has name and header');
  }
});

suite('computeGrade', function() {
  assertEqual(computeGrade(95), 'A', '95% => A');
  assertEqual(computeGrade(90), 'A', '90% => A');
  assertEqual(computeGrade(85), 'B', '85% => B');
  assertEqual(computeGrade(80), 'B', '80% => B');
  assertEqual(computeGrade(70), 'C', '70% => C');
  assertEqual(computeGrade(65), 'C', '65% => C');
  assertEqual(computeGrade(55), 'D', '55% => D');
  assertEqual(computeGrade(50), 'D', '50% => D');
  assertEqual(computeGrade(35), 'E', '35% => E');
  assertEqual(computeGrade(30), 'E', '30% => E');
  assertEqual(computeGrade(20), 'F', '20% => F');
  assertEqual(computeGrade(0), 'F', '0% => F');
});

suite('Analyze: perfect headers', function() {
  const headers = {
    'content-security-policy': "default-src 'self'; script-src 'self'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
    'x-xss-protection': '1; mode=block',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'cache-control': 'no-store',
  };
  const result = analyze(headers, 'en');
  assertEqual(result.grade, 'A', 'Perfect headers get A grade');
  assertEqual(result.summary.fail, 0, 'No failures');
  assert(result.score >= 90, 'Score >= 90 (got ' + result.score + ')');
});

suite('Analyze: no headers at all', function() {
  const result = analyze({}, 'en');
  assertEqual(result.grade, 'F', 'Empty headers get F grade');
  assert(result.summary.fail > 0, 'Has failures');
  assert(result.score < 30, 'Score < 30 (got ' + result.score + ')');
});

suite('Analyze: partial headers', function() {
  const headers = {
    'x-frame-options': 'SAMEORIGIN',
    'x-content-type-options': 'nosniff',
    'strict-transport-security': 'max-age=31536000',
    'server': 'nginx',
  };
  const result = analyze(headers, 'en');
  assert(result.score > 20 && result.score < 80, 'Partial headers give mid score (got ' + result.score + ')');
  assert(result.summary.pass > 0, 'Some passes');
  assert(result.summary.fail > 0 || result.summary.warn > 0, 'Some fails or warns');
});

suite('Analyze: server version exposure', function() {
  const headers = { 'server': 'Apache/2.4.51' };
  const result = analyze(headers, 'en');
  const serverResult = result.results.find(function(r) { return r.id === 'server'; });
  assertEqual(serverResult.status, 'fail', 'Server with version is a fail');
});

suite('Analyze: X-Powered-By exposure', function() {
  const headers = { 'x-powered-by': 'Express' };
  const result = analyze(headers, 'en');
  const xpb = result.results.find(function(r) { return r.id === 'x-powered-by'; });
  assertEqual(xpb.status, 'fail', 'X-Powered-By exposed is a fail');
});

suite('Analyze: weak CSP with unsafe-inline', function() {
  const headers = { 'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'" };
  const result = analyze(headers, 'en');
  const csp = result.results.find(function(r) { return r.id === 'csp'; });
  assertEqual(csp.status, 'warn', 'CSP with unsafe-inline is a warning');
});

suite('Analyze: HSTS with short max-age', function() {
  const headers = { 'strict-transport-security': 'max-age=3600' };
  const result = analyze(headers, 'en');
  const hsts = result.results.find(function(r) { return r.id === 'hsts'; });
  assertEqual(hsts.status, 'warn', 'Short HSTS max-age is a warning');
});

suite('Analyze: French language output', function() {
  const result = analyze({}, 'fr');
  const csp = result.results.find(function(r) { return r.id === 'csp'; });
  assertEqual(csp.message, 'En-tete absent', 'French message for missing header');
});

suite('Analyze: server not exposed is pass', function() {
  const result = analyze({}, 'en');
  const server = result.results.find(function(r) { return r.id === 'server'; });
  assertEqual(server.status, 'pass', 'No server header is a pass');
  const xpb = result.results.find(function(r) { return r.id === 'x-powered-by'; });
  assertEqual(xpb.status, 'pass', 'No x-powered-by header is a pass');
});

suite('Analyze: recommendations only for non-pass', function() {
  const headers = {
    'content-security-policy': "default-src 'self'; script-src 'self'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
    'x-xss-protection': '1; mode=block',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'cache-control': 'no-store',
  };
  const result = analyze(headers, 'en');
  for (const r of result.results) {
    if (r.status === 'pass') {
      assertEqual(r.recommendation, null, r.name + ': pass has no recommendation');
    }
  }
});

suite('Analyze: case-insensitive header keys', function() {
  const headers = {
    'Content-Security-Policy': "default-src 'self'",
    'X-FRAME-OPTIONS': 'DENY',
  };
  const result = analyze(headers, 'en');
  const csp = result.results.find(function(r) { return r.id === 'csp'; });
  assertEqual(csp.status, 'pass', 'Mixed-case CSP header is detected');
  const xfo = result.results.find(function(r) { return r.id === 'x-frame-options'; });
  assertEqual(xfo.status, 'pass', 'Uppercase X-FRAME-OPTIONS is detected');
});

// ---- Summary ----
console.log('\n' + '='.repeat(40));
console.log('Results: ' + passed + '/' + total + ' passed, ' + failed + ' failed');
if (failed > 0) {
  console.log('SOME TESTS FAILED');
  process.exit(1);
} else {
  console.log('ALL TESTS PASSED');
  process.exit(0);
}
