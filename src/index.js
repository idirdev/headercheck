'use strict';

/**
 * @fileoverview HTTP security header analysis tool.
 * @module headercheck
 * @author idirdev
 */

const http  = require('http');
const https = require('https');
const url   = require('url');

/**
 * @typedef {Object} HeaderDef
 * @property {string} name        - Header name (lowercase).
 * @property {string} description - What the header does.
 * @property {string} recommended - Recommended value or guidance.
 * @property {string} severity    - 'critical' | 'high' | 'medium' | 'low'.
 */

/**
 * Security headers to check.
 * @type {HeaderDef[]}
 */
const SECURITY_HEADERS = [
  {
    name:        'content-security-policy',
    description: 'Prevents XSS attacks by controlling resource loading.',
    recommended: "default-src 'self'",
    severity:    'critical',
  },
  {
    name:        'x-frame-options',
    description: 'Prevents clickjacking attacks.',
    recommended: 'DENY or SAMEORIGIN',
    severity:    'high',
  },
  {
    name:        'x-content-type-options',
    description: 'Prevents MIME-type sniffing.',
    recommended: 'nosniff',
    severity:    'medium',
  },
  {
    name:        'strict-transport-security',
    description: 'Enforces HTTPS connections.',
    recommended: 'max-age=31536000; includeSubDomains',
    severity:    'critical',
  },
  {
    name:        'x-xss-protection',
    description: 'Legacy XSS filter (modern browsers ignore this).',
    recommended: '1; mode=block',
    severity:    'low',
  },
  {
    name:        'referrer-policy',
    description: 'Controls referrer information sent with requests.',
    recommended: 'strict-origin-when-cross-origin',
    severity:    'medium',
  },
  {
    name:        'permissions-policy',
    description: 'Controls access to browser features.',
    recommended: 'geolocation=(), microphone=(), camera=()',
    severity:    'medium',
  },
  {
    name:        'x-download-options',
    description: 'Prevents IE from executing downloads in site context.',
    recommended: 'noopen',
    severity:    'low',
  },
  {
    name:        'x-permitted-cross-domain-policies',
    description: 'Controls Adobe Flash/PDF cross-domain requests.',
    recommended: 'none',
    severity:    'low',
  },
  {
    name:        'cross-origin-opener-policy',
    description: 'Isolates browsing context from cross-origin documents.',
    recommended: 'same-origin',
    severity:    'high',
  },
  {
    name:        'cross-origin-resource-policy',
    description: 'Prevents other origins from loading resources.',
    recommended: 'same-origin',
    severity:    'high',
  },
  {
    name:        'cross-origin-embedder-policy',
    description: 'Requires resources to opt in to cross-origin embedding.',
    recommended: 'require-corp',
    severity:    'medium',
  },
];

/**
 * Make an HTTP(S) GET request and resolve with { headers, statusCode }.
 * @param {string} targetUrl - URL to request.
 * @param {{timeout?:number, followRedirects?:boolean}} [opts={}]
 * @returns {Promise<{headers:Object, statusCode:number, url:string}>}
 */
function fetchHeaders(targetUrl, opts = {}) {
  return new Promise((resolve, reject) => {
    const { timeout = 10000 } = opts;
    const parsed  = new url.URL(targetUrl);
    const lib     = parsed.protocol === 'https:' ? https : http;
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   'HEAD',
      headers:  { 'User-Agent': 'headercheck/1.0.0' },
    };

    const req = lib.request(options, (res) => {
      resolve({ headers: res.headers, statusCode: res.statusCode, url: targetUrl });
      res.resume();
    });

    req.setTimeout(timeout, () => {
      req.destroy(new Error('Request timed out'));
    });

    req.on('error', reject);
    req.end();
  });
}

/**
 * Check security headers for a single URL.
 * @param {string} targetUrl - URL to check.
 * @param {Object} [opts={}] - Options passed to fetchHeaders.
 * @returns {Promise<{url:string, statusCode:number, results:Array<Object>, grade:string}>}
 */
async function checkHeaders(targetUrl, opts = {}) {
  const { headers, statusCode } = await fetchHeaders(targetUrl, opts);
  const results = [];

  for (const def of SECURITY_HEADERS) {
    const present = def.name in headers;
    const value   = headers[def.name] || null;
    results.push({
      header:      def.name,
      description: def.description,
      recommended: def.recommended,
      severity:    def.severity,
      present,
      value,
    });
  }

  const grade = gradeHeaders(results);
  return { url: targetUrl, statusCode, results, grade };
}

/**
 * Grade the header results on a scale of A–F.
 * Grade is based on the number and severity of missing security headers.
 * @param {Array<{present:boolean, severity:string}>} results
 * @returns {string} Letter grade A–F.
 */
function gradeHeaders(results) {
  const weights = { critical: 30, high: 20, medium: 10, low: 5 };
  let deductions = 0;
  let maxScore   = 0;

  for (const r of results) {
    const w = weights[r.severity] || 5;
    maxScore += w;
    if (!r.present) deductions += w;
  }

  const score = maxScore > 0 ? ((maxScore - deductions) / maxScore) * 100 : 100;

  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 45) return 'D';
  if (score >= 25) return 'E';
  return 'F';
}

/**
 * Check security headers for multiple URLs.
 * @param {string[]} urls - URLs to check.
 * @param {Object} [opts={}] - Options passed to checkHeaders.
 * @returns {Promise<Array<Object>>} Array of check results.
 */
async function checkMultiple(urls, opts = {}) {
  const results = [];
  for (const u of urls) {
    try {
      results.push(await checkHeaders(u, opts));
    } catch (err) {
      results.push({ url: u, error: err.message, results: [], grade: 'F' });
    }
  }
  return results;
}

/**
 * Compute a summary across multiple check results.
 * @param {Array<Object>} checks - Results from checkMultiple or checkHeaders array.
 * @returns {{checked:number, passing:number, failing:number, averageGrade:string, missingHeaders:Object}}
 */
function summary(checks) {
  const grades      = ['A', 'B', 'C', 'D', 'E', 'F'];
  const missingMap  = {};
  let totalScore    = 0;

  for (const check of checks) {
    const idx = grades.indexOf(check.grade);
    totalScore += idx >= 0 ? (5 - idx) : 0;
    for (const r of (check.results || [])) {
      if (!r.present) {
        missingMap[r.header] = (missingMap[r.header] || 0) + 1;
      }
    }
  }

  const avgIdx = checks.length > 0
    ? Math.round(5 - totalScore / checks.length)
    : 5;
  const averageGrade = grades[Math.min(Math.max(avgIdx, 0), 5)];

  return {
    checked:       checks.length,
    passing:       checks.filter(c => c.grade <= 'B').length,
    failing:       checks.filter(c => c.grade >= 'C').length,
    averageGrade,
    missingHeaders: missingMap,
  };
}

/**
 * Format a single check result as a table string.
 * @param {Object} check - Result from checkHeaders.
 * @returns {string}
 */
function formatTable(check) {
  const lines = [];
  lines.push(`URL: ${check.url}  Status: ${check.statusCode}  Grade: ${check.grade}`);
  lines.push('='.repeat(70));
  const colW = 38;
  lines.push('Header'.padEnd(colW) + 'Status   Severity  Value');
  lines.push('-'.repeat(70));
  for (const r of check.results) {
    const status = r.present ? 'PRESENT' : 'MISSING';
    const value  = r.present ? (r.value || '').slice(0, 20) : '';
    lines.push(r.header.padEnd(colW) + status.padEnd(9) + r.severity.padEnd(10) + value);
  }
  return lines.join('\n');
}

/**
 * Format one or more check results as a full human-readable report.
 * @param {Array<Object>|Object} results - Single or array of check results.
 * @returns {string}
 */
function formatReport(results) {
  const checks = Array.isArray(results) ? results : [results];
  const lines  = [];

  for (const check of checks) {
    lines.push(formatTable(check));
    lines.push('');
  }

  if (checks.length > 1) {
    const s = summary(checks);
    lines.push('Overall Summary');
    lines.push('-'.repeat(40));
    lines.push(`Checked: ${s.checked} | Average Grade: ${s.averageGrade}`);
    if (Object.keys(s.missingHeaders).length > 0) {
      lines.push('Most missing headers:');
      const sorted = Object.entries(s.missingHeaders).sort((a, b) => b[1] - a[1]);
      for (const [h, n] of sorted.slice(0, 5)) lines.push(`  ${h}: missing ${n}x`);
    }
  }

  return lines.join('\n');
}

module.exports = {
  SECURITY_HEADERS,
  checkHeaders,
  checkMultiple,
  gradeHeaders,
  formatReport,
  formatTable,
  summary,
  fetchHeaders,
};
