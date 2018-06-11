#!/usr/bin/env node
'use strict';

/**
 * @fileoverview CLI for headercheck - HTTP security header analyzer.
 * @author idirdev
 */

const { checkMultiple, formatReport, formatTable } = require('../src/index.js');

const args = process.argv.slice(2);
if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log('Usage: headercheck <url...> [--json] [--table] [--verbose]');
  console.log('');
  console.log('Options:');
  console.log('  --json      Output results as JSON');
  console.log('  --table     Output as table (default)');
  console.log('  --verbose   Show all headers including present ones');
  console.log('  -h, --help  Show this help message');
  process.exit(0);
}

const urls    = [];
let json      = false;
let verbose   = false;

for (const arg of args) {
  if (arg === '--json')    json = true;
  else if (arg === '--table') { /* default */ }
  else if (arg === '--verbose') verbose = true;
  else if (!arg.startsWith('--')) urls.push(arg);
}

if (urls.length === 0) {
  console.error('Error: at least one URL is required.');
  process.exit(1);
}

(async () => {
  const results = await checkMultiple(urls, {});
  if (json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    console.log(formatReport(results));
  }
  const hasF = results.some(r => r.grade === 'F' || r.grade === 'E');
  process.exit(hasF ? 1 : 0);
})();
