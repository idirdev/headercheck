'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');

const MAX_REDIRECTS = 10;
const DEFAULT_TIMEOUT = 15000;

/**
 * Fetch HTTP response headers from a URL, following redirects.
 * @param {string} targetUrl - The URL to check
 * @param {Object} opts - Options: { timeout, maxRedirects, method }
 * @returns {Promise<Object>} { url, statusCode, headers, redirectChain }
 */
function fetchHeaders(targetUrl, opts) {
  if (!opts) opts = {};
  const timeout = opts.timeout || DEFAULT_TIMEOUT;
  const maxRedirects = opts.maxRedirects || MAX_REDIRECTS;
  const method = (opts.method || 'HEAD').toUpperCase();

  return new Promise(function(resolve, reject) {
    const redirectChain = [];
    let currentUrl = normalizeUrl(targetUrl);
    let redirectCount = 0;

    function doRequest(url) {
      let parsed;
      try {
        parsed = new URL(url);
      } catch (err) {
        return reject(new Error('Invalid URL: ' + url));
      }

      const transport = parsed.protocol === 'https:' ? https : http;
      const requestOpts = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: method,
        timeout: timeout,
        headers: {
          'User-Agent': 'headercheck/1.0.0',
          'Accept': '*/*',
        },
        rejectUnauthorized: true,
      };

      const req = transport.request(requestOpts, function(res) {
        // Consume response body to free up socket
        res.resume();

        const statusCode = res.statusCode;
        const headers = res.headers;

        if (statusCode >= 300 && statusCode < 400 && headers.location) {
          if (redirectCount >= maxRedirects) {
            return reject(new Error('Too many redirects (max ' + maxRedirects + ')'));
          }
          redirectCount++;
          const nextUrl = resolveRedirect(url, headers.location);
          redirectChain.push({ url: url, statusCode: statusCode, location: nextUrl });
          currentUrl = nextUrl;
          return doRequest(nextUrl);
        }

        // If HEAD returns 405, retry with GET
        if (statusCode === 405 && method === 'HEAD') {
          return fetchHeaders(targetUrl, Object.assign({}, opts, { method: 'GET' }))
            .then(resolve)
            .catch(reject);
        }

        resolve({
          url: currentUrl,
          statusCode: statusCode,
          headers: headers,
          redirectChain: redirectChain,
        });
      });

      req.on('timeout', function() {
        req.destroy();
        reject(new Error('Request timed out after ' + timeout + 'ms'));
      });

      req.on('error', function(err) {
        if (err.code === 'ENOTFOUND') {
          reject(new Error('DNS lookup failed for ' + parsed.hostname));
        } else if (err.code === 'ECONNREFUSED') {
          reject(new Error('Connection refused: ' + url));
        } else if (err.code === 'CERT_HAS_EXPIRED' || err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
          reject(new Error('SSL certificate error: ' + err.message));
        } else {
          reject(err);
        }
      });

      req.end();
    }

    doRequest(currentUrl);
  });
}

/**
 * Normalize a URL string, adding https:// if no protocol is specified.
 */
function normalizeUrl(input) {
  let url = input.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }
  return url;
}

/**
 * Resolve a redirect location against the current URL.
 */
function resolveRedirect(currentUrl, location) {
  try {
    return new URL(location, currentUrl).href;
  } catch (e) {
    return location;
  }
}

module.exports = { fetchHeaders, normalizeUrl };
