'use strict';

const SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
};

const rules = [
  {
    id: 'csp',
    header: 'content-security-policy',
    name: 'Content-Security-Policy',
    severity: SEVERITY.CRITICAL,
    weight: 15,
    description: {
      en: 'Prevents XSS, clickjacking, and code injection attacks',
      fr: 'Empeche les attaques XSS, clickjacking et injection de code',
    },
    check(value) {
      if (!value) {
        return { status: 'fail', message: { en: 'Header missing', fr: 'En-tete absent' } };
      }
      const lower = value.toLowerCase();
      const hasUnsafeInline = lower.includes("'unsafe-inline'");
      const hasUnsafeEval = lower.includes("'unsafe-eval'");
      const hasDefaultSrc = lower.includes('default-src');
      const hasScriptSrc = lower.includes('script-src');
      if (hasUnsafeEval && hasUnsafeInline) {
        return { status: 'warn', message: { en: "Present but uses 'unsafe-inline' and 'unsafe-eval'", fr: "Present mais utilise 'unsafe-inline' et 'unsafe-eval'" } };
      }
      if (hasUnsafeInline) {
        return { status: 'warn', message: { en: "Present but uses 'unsafe-inline'", fr: "Present mais utilise 'unsafe-inline'" } };
      }
      if (hasUnsafeEval) {
        return { status: 'warn', message: { en: "Present but uses 'unsafe-eval'", fr: "Present mais utilise 'unsafe-eval'" } };
      }
      if (!hasDefaultSrc && !hasScriptSrc) {
        return { status: 'warn', message: { en: 'Present but missing default-src or script-src directive', fr: 'Present mais sans directive default-src ou script-src' } };
      }
      return { status: 'pass', message: { en: 'Well configured', fr: 'Bien configure' } };
    },
    recommendation: {
      en: "Set a strict CSP. At minimum: default-src 'self'; script-src 'self'",
      fr: "Definir une CSP stricte. Au minimum: default-src 'self'; script-src 'self'",
    },
  },
  {
    id: 'x-frame-options',
    header: 'x-frame-options',
    name: 'X-Frame-Options',
    severity: SEVERITY.HIGH,
    weight: 10,
    description: {
      en: 'Prevents clickjacking by controlling iframe embedding',
      fr: 'Empeche le clickjacking en controlant integration en iframe',
    },
    check(value) {
      if (!value) {
        return { status: 'fail', message: { en: 'Header missing', fr: 'En-tete absent' } };
      }
      const upper = value.toUpperCase().trim();
      if (upper === 'DENY' || upper === 'SAMEORIGIN') {
        return { status: 'pass', message: { en: 'Set to ' + upper, fr: 'Defini sur ' + upper } };
      }
      if (upper.startsWith('ALLOW-FROM')) {
        return { status: 'warn', message: { en: 'ALLOW-FROM is deprecated and not supported by all browsers', fr: 'ALLOW-FROM est obsolete et non supporte par tous les navigateurs' } };
      }
      return { status: 'warn', message: { en: 'Unexpected value: ' + value, fr: 'Valeur inattendue: ' + value } };
    },
    recommendation: {
      en: 'Set X-Frame-Options to DENY or SAMEORIGIN',
      fr: 'Definir X-Frame-Options sur DENY ou SAMEORIGIN',
    },
  },
  {
    id: 'x-content-type-options',
    header: 'x-content-type-options',
    name: 'X-Content-Type-Options',
    severity: SEVERITY.HIGH,
    weight: 10,
    description: {
      en: 'Prevents MIME type sniffing',
      fr: 'Empeche le reniflage de type MIME',
    },
    check(value) {
      if (!value) {
        return { status: 'fail', message: { en: 'Header missing', fr: 'En-tete absent' } };
      }
      if (value.toLowerCase().trim() === 'nosniff') {
        return { status: 'pass', message: { en: 'Correctly set to nosniff', fr: 'Correctement defini sur nosniff' } };
      }
      return { status: 'warn', message: { en: 'Unexpected value: ' + value, fr: 'Valeur inattendue: ' + value } };
    },
    recommendation: {
      en: 'Set X-Content-Type-Options: nosniff',
      fr: 'Definir X-Content-Type-Options: nosniff',
    },
  },
  {
    id: 'hsts',
    header: 'strict-transport-security',
    name: 'Strict-Transport-Security',
    severity: SEVERITY.CRITICAL,
    weight: 15,
    description: {
      en: 'Forces HTTPS connections and prevents downgrade attacks',
      fr: 'Force les connexions HTTPS et empeche les attaques par downgrade',
    },
    check(value) {
      if (!value) {
        return { status: 'fail', message: { en: 'Header missing', fr: 'En-tete absent' } };
      }
      const lower = value.toLowerCase();
      const maxAgeMatch = lower.match(/max-age=(\d+)/);
      if (!maxAgeMatch) {
        return { status: 'warn', message: { en: 'Present but max-age directive missing', fr: 'Present mais directive max-age absente' } };
      }
      const maxAge = parseInt(maxAgeMatch[1], 10);
      const hasIncludeSub = lower.includes('includesubdomains');
      const hasPreload = lower.includes('preload');
      if (maxAge >= 31536000 && hasIncludeSub && hasPreload) {
        return { status: 'pass', message: { en: 'Excellent: max-age=' + maxAge + ', includeSubDomains, preload', fr: 'Excellent: max-age=' + maxAge + ', includeSubDomains, preload' } };
      }
      if (maxAge >= 31536000) {
        return { status: 'pass', message: { en: 'Good: max-age=' + maxAge + (hasIncludeSub ? ', includeSubDomains' : ''), fr: 'Bon: max-age=' + maxAge + (hasIncludeSub ? ', includeSubDomains' : '') } };
      }
      if (maxAge < 2592000) {
        return { status: 'warn', message: { en: 'max-age too short (' + maxAge + 's). Recommended: >= 31536000 (1 year)', fr: 'max-age trop court (' + maxAge + 's). Recommande: >= 31536000 (1 an)' } };
      }
      return { status: 'pass', message: { en: 'Acceptable: max-age=' + maxAge, fr: 'Acceptable: max-age=' + maxAge } };
    },
    recommendation: {
      en: 'Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      fr: 'Definir Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    },
  },
  {
    id: 'x-xss-protection',
    header: 'x-xss-protection',
    name: 'X-XSS-Protection',
    severity: SEVERITY.LOW,
    weight: 5,
    description: {
      en: 'Legacy XSS filter (deprecated in modern browsers but still useful)',
      fr: 'Filtre XSS historique (obsolete mais encore utile)',
    },
    check(value) {
      if (!value) {
        return { status: 'warn', message: { en: 'Header missing', fr: 'En-tete absent' } };
      }
      const trimmed = value.trim();
      if (trimmed === '0') {
        return { status: 'warn', message: { en: 'XSS filter explicitly disabled', fr: 'Filtre XSS explicitement desactive' } };
      }
      if (trimmed.startsWith('1') && trimmed.includes('mode=block')) {
        return { status: 'pass', message: { en: 'Enabled with mode=block', fr: 'Active avec mode=block' } };
      }
      if (trimmed === '1') {
        return { status: 'pass', message: { en: 'Enabled', fr: 'Active' } };
      }
      return { status: 'warn', message: { en: 'Unexpected value: ' + value, fr: 'Valeur inattendue: ' + value } };
    },
    recommendation: {
      en: 'Set X-XSS-Protection: 1; mode=block',
      fr: 'Definir X-XSS-Protection: 1; mode=block',
    },
  },
  {
    id: 'referrer-policy',
    header: 'referrer-policy',
    name: 'Referrer-Policy',
    severity: SEVERITY.MEDIUM,
    weight: 8,
    description: {
      en: 'Controls how much referrer information is sent with requests',
      fr: 'Controle la quantite de referrer envoyee avec les requetes',
    },
    check(value) {
      if (!value) {
        return { status: 'fail', message: { en: 'Header missing', fr: 'En-tete absent' } };
      }
      const secure = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
      const lower = value.toLowerCase().trim();
      if (secure.includes(lower)) {
        return { status: 'pass', message: { en: 'Secure policy: ' + lower, fr: 'Politique securisee: ' + lower } };
      }
      if (lower === 'no-referrer-when-downgrade') {
        return { status: 'pass', message: { en: 'Acceptable policy (browser default)', fr: 'Politique acceptable (defaut navigateur)' } };
      }
      if (lower === 'unsafe-url' || lower === 'origin-when-cross-origin') {
        return { status: 'warn', message: { en: 'Weak policy: ' + lower + ' may leak sensitive paths', fr: 'Politique faible: ' + lower + ' peut exposer les chemins sensibles' } };
      }
      return { status: 'warn', message: { en: 'Unknown policy: ' + value, fr: 'Politique inconnue: ' + value } };
    },
    recommendation: {
      en: 'Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer',
      fr: 'Definir Referrer-Policy sur strict-origin-when-cross-origin ou no-referrer',
    },
  },
  {
    id: 'permissions-policy',
    header: 'permissions-policy',
    name: 'Permissions-Policy',
    severity: SEVERITY.MEDIUM,
    weight: 8,
    description: {
      en: 'Controls which browser features the site can use',
      fr: 'Controle quelles fonctionnalites du navigateur le site peut utiliser',
    },
    check(value) {
      if (!value) {
        return { status: 'fail', message: { en: 'Header missing', fr: 'En-tete absent' } };
      }
      const lower = value.toLowerCase();
      const features = ['camera', 'microphone', 'geolocation', 'payment'];
      const restricted = features.filter(function(f) {
        return lower.includes(f + '=()') || lower.includes(f + '=self');
      });
      if (restricted.length >= 3) {
        return { status: 'pass', message: { en: 'Strong policy: ' + restricted.length + ' sensitive features restricted', fr: 'Politique forte: ' + restricted.length + ' fonctionnalites restreintes' } };
      }
      if (restricted.length >= 1) {
        return { status: 'pass', message: { en: 'Partial policy: ' + restricted.length + ' features restricted', fr: 'Politique partielle: ' + restricted.length + ' fonctionnalites restreintes' } };
      }
      return { status: 'warn', message: { en: 'Present but does not restrict key features', fr: 'Present mais ne restreint pas les fonctionnalites cles' } };
    },
    recommendation: {
      en: 'Set Permissions-Policy to restrict camera, microphone, geolocation, payment',
      fr: 'Definir Permissions-Policy pour restreindre camera, microphone, geolocation, payment',
    },
  },
  {
    id: 'cache-control',
    header: 'cache-control',
    name: 'Cache-Control',
    severity: SEVERITY.MEDIUM,
    weight: 7,
    description: {
      en: 'Controls caching behavior to prevent sensitive data leaks',
      fr: 'Controle le comportement du cache pour eviter les fuites de donnees',
    },
    check(value) {
      if (!value) {
        return { status: 'warn', message: { en: 'Header missing', fr: 'En-tete absent' } };
      }
      const lower = value.toLowerCase();
      if (lower.includes('no-store')) {
        return { status: 'pass', message: { en: 'Secure: no-store prevents caching', fr: 'Securise: no-store empeche la mise en cache' } };
      }
      if (lower.includes('private') || lower.includes('no-cache')) {
        return { status: 'pass', message: { en: 'Acceptable caching policy', fr: 'Politique de cache acceptable' } };
      }
      if (lower.includes('public')) {
        return { status: 'warn', message: { en: 'Public caching may expose sensitive data', fr: 'Le cache public peut exposer des donnees sensibles' } };
      }
      return { status: 'pass', message: { en: 'Present: ' + value, fr: 'Present: ' + value } };
    },
    recommendation: {
      en: 'For sensitive pages: Cache-Control: no-store, no-cache, must-revalidate',
      fr: 'Pour les pages sensibles: Cache-Control: no-store, no-cache, must-revalidate',
    },
  },
  {
    id: 'server',
    header: 'server',
    name: 'Server',
    severity: SEVERITY.LOW,
    weight: 6,
    description: {
      en: 'Server header may expose software version information',
      fr: 'En-tete Server peut exposer la version du logiciel serveur',
    },
    check(value) {
      if (!value) {
        return { status: 'pass', message: { en: 'Not exposed (good)', fr: 'Non expose (bien)' } };
      }
      if (/\d+\.\d+/.test(value)) {
        return { status: 'fail', message: { en: 'Exposes server version: ' + value, fr: 'Expose la version du serveur: ' + value } };
      }
      return { status: 'warn', message: { en: 'Server identified: ' + value, fr: 'Serveur identifie: ' + value } };
    },
    recommendation: {
      en: 'Remove or obfuscate the Server header to hide implementation details',
      fr: 'Supprimer ou masquer en-tete Server pour cacher les details implementation',
    },
  },
  {
    id: 'x-powered-by',
    header: 'x-powered-by',
    name: 'X-Powered-By',
    severity: SEVERITY.LOW,
    weight: 6,
    description: {
      en: 'Exposes backend technology stack information',
      fr: 'Expose les informations sur la pile technologique backend',
    },
    check(value) {
      if (!value) {
        return { status: 'pass', message: { en: 'Not exposed (good)', fr: 'Non expose (bien)' } };
      }
      return { status: 'fail', message: { en: 'Exposes technology: ' + value, fr: 'Expose la technologie: ' + value } };
    },
    recommendation: {
      en: 'Remove X-Powered-By header (e.g. app.disable("x-powered-by") in Express)',
      fr: 'Supprimer X-Powered-By (ex: app.disable("x-powered-by") dans Express)',
    },
  },
];

module.exports = { rules, SEVERITY };
