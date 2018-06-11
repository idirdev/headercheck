'use strict';

const { rules } = require('./rules');

/**
 * Analyze HTTP headers against security rules.
 * @param {Object} headers - Lowercase header key-value pairs
 * @param {string} lang - Language code ('en' or 'fr')
 * @returns {Object} Analysis results with score, grade, and per-rule details
 */
function analyze(headers, lang) {
  if (!lang) lang = 'en';
  const normalizedHeaders = {};
  for (const key of Object.keys(headers)) {
    normalizedHeaders[key.toLowerCase()] = headers[key];
  }

  let earnedPoints = 0;
  let totalWeight = 0;
  const results = [];

  for (const rule of rules) {
    totalWeight += rule.weight;
    const headerValue = normalizedHeaders[rule.header] || null;
    const checkResult = rule.check(headerValue);

    let points = 0;
    if (checkResult.status === 'pass') {
      points = rule.weight;
    } else if (checkResult.status === 'warn') {
      points = Math.floor(rule.weight * 0.5);
    }
    earnedPoints += points;

    results.push({
      id: rule.id,
      name: rule.name,
      header: rule.header,
      value: headerValue,
      severity: rule.severity,
      status: checkResult.status,
      message: checkResult.message[lang] || checkResult.message.en,
      description: rule.description[lang] || rule.description.en,
      recommendation: checkResult.status !== 'pass'
        ? (rule.recommendation[lang] || rule.recommendation.en)
        : null,
      points: points,
      maxPoints: rule.weight,
    });
  }

  const percentage = totalWeight > 0 ? Math.round((earnedPoints / totalWeight) * 100) : 0;
  const grade = computeGrade(percentage);

  return {
    score: percentage,
    grade: grade,
    earnedPoints: earnedPoints,
    totalPoints: totalWeight,
    results: results,
    summary: {
      pass: results.filter(function(r) { return r.status === 'pass'; }).length,
      warn: results.filter(function(r) { return r.status === 'warn'; }).length,
      fail: results.filter(function(r) { return r.status === 'fail'; }).length,
      total: results.length,
    },
  };
}

/**
 * Compute letter grade from percentage score.
 */
function computeGrade(pct) {
  if (pct >= 90) return 'A';
  if (pct >= 80) return 'B';
  if (pct >= 65) return 'C';
  if (pct >= 50) return 'D';
  if (pct >= 30) return 'E';
  return 'F';
}

module.exports = { analyze, computeGrade };
