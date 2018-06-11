'use strict';

const chalk = require('chalk');
const Table = require('cli-table3');

const STATUS_ICONS = {
  pass: chalk.green('PASS'),
  warn: chalk.yellow('WARN'),
  fail: chalk.red('FAIL'),
};

const GRADE_COLORS = {
  A: chalk.green.bold,
  B: chalk.green,
  C: chalk.yellow,
  D: chalk.yellow.bold,
  E: chalk.red,
  F: chalk.red.bold,
};

/**
 * Format analysis results as a colored table.
 * @param {Object} analysis - Output from analyze()
 * @param {Object} meta - { url, statusCode, redirectChain }
 * @param {string} lang - 'en' or 'fr'
 * @returns {string} Formatted output string
 */
function formatTable(analysis, meta, lang) {
  if (!lang) lang = 'en';
  const lines = [];

  lines.push('');
  lines.push(chalk.bold.cyan('='.repeat(60)));
  lines.push(chalk.bold.cyan(lang === 'fr' ? '  HEADERCHECK - Analyse de securite' : '  HEADERCHECK - Security Analysis'));
  lines.push(chalk.bold.cyan('='.repeat(60)));
  lines.push('');

  // Target info
  lines.push(chalk.white.bold((lang === 'fr' ? 'URL: ' : 'URL: ') + meta.url));
  lines.push(chalk.white('Status: ' + meta.statusCode));
  if (meta.redirectChain && meta.redirectChain.length > 0) {
    lines.push(chalk.dim((lang === 'fr' ? 'Redirections: ' : 'Redirects: ') + meta.redirectChain.length));
  }
  lines.push('');

  // Score
  const gradeColor = GRADE_COLORS[analysis.grade] || chalk.white;
  lines.push(chalk.bold((lang === 'fr' ? 'Score: ' : 'Score: ')) + gradeColor(analysis.score + '/100 (' + analysis.grade + ')'));
  lines.push(
    chalk.green(analysis.summary.pass + (lang === 'fr' ? ' passe' : ' passed')) + '  ' +
    chalk.yellow(analysis.summary.warn + (lang === 'fr' ? ' avertissement' : ' warning') + (analysis.summary.warn !== 1 ? 's' : '')) + '  ' +
    chalk.red(analysis.summary.fail + (lang === 'fr' ? ' echec' : ' failed') + (analysis.summary.fail !== 1 ? 's' : ''))
  );
  lines.push('');

  // Results table
  const table = new Table({
    head: [
      chalk.white.bold(lang === 'fr' ? 'En-tete' : 'Header'),
      chalk.white.bold('Status'),
      chalk.white.bold(lang === 'fr' ? 'Details' : 'Details'),
      chalk.white.bold(lang === 'fr' ? 'Points' : 'Points'),
    ],
    colWidths: [28, 8, 50, 10],
    wordWrap: true,
    style: { head: [], border: ['grey'] },
  });

  for (const r of analysis.results) {
    table.push([
      chalk.white(r.name),
      STATUS_ICONS[r.status] || r.status,
      r.message,
      r.points + '/' + r.maxPoints,
    ]);
  }

  lines.push(table.toString());

  // Recommendations
  const recs = analysis.results.filter(function(r) { return r.recommendation; });
  if (recs.length > 0) {
    lines.push('');
    lines.push(chalk.bold.yellow(lang === 'fr' ? 'Recommandations:' : 'Recommendations:'));
    lines.push(chalk.yellow('-'.repeat(40)));
    for (const r of recs) {
      const icon = r.status === 'fail' ? chalk.red('[!]') : chalk.yellow('[~]');
      lines.push(icon + ' ' + chalk.bold(r.name) + ': ' + r.recommendation);
    }
  }

  lines.push('');
  return lines.join('\n');
}

/**
 * Format analysis results as JSON.
 */
function formatJson(analysis, meta) {
  return JSON.stringify({
    url: meta.url,
    statusCode: meta.statusCode,
    redirectChain: meta.redirectChain,
    score: analysis.score,
    grade: analysis.grade,
    summary: analysis.summary,
    results: analysis.results,
  }, null, 2);
}

module.exports = { formatTable, formatJson };
