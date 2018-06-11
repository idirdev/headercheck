# headercheck

> HTTP Security Header Analyzer CLI / Analyseur CLI de securite des en-tetes HTTP

---

## English

### What is headercheck?

**headercheck** is a command-line tool that analyzes HTTP response headers for security best practices. It checks 10 critical security headers, gives a security score (A-F), and provides actionable recommendations.

### Checks performed

| Header | Severity |
|---|---|
| Content-Security-Policy | Critical |
| Strict-Transport-Security (HSTS) | Critical |
| X-Frame-Options | High |
| X-Content-Type-Options | High |
| Referrer-Policy | Medium |
| Permissions-Policy | Medium |
| Cache-Control | Medium |
| X-XSS-Protection | Low |
| Server (exposure) | Low |
| X-Powered-By (exposure) | Low |

### Installation

\`\`\`bash
npm install -g headercheck
\`\`\`

### Usage

\`\`\`bash
# Basic scan
headercheck https://example.com

# French output
headercheck https://example.com --lang fr

# JSON output
headercheck https://example.com --format json

# Custom timeout (ms)
headercheck https://example.com --timeout 30000
\`\`\`

### Programmatic usage

\`\`\`javascript
const { check } = require('headercheck');

async function run() {
  const result = await check('https://example.com', { lang: 'en', format: 'json' });
  console.log(result.analysis.grade); // 'A', 'B', 'C', 'D', 'E', or 'F'
  console.log(result.analysis.score); // 0-100
}

run();
\`\`\`

### Grading scale

| Grade | Score |
|---|---|
| A | 90-100 |
| B | 80-89 |
| C | 65-79 |
| D | 50-64 |
| E | 30-49 |
| F | 0-29 |

### Exit codes

- **0**: Grade A, B, or C
- **1**: Grade D or E
- **2**: Grade F
- **3**: Error (network, DNS, timeout)

---

## Francais

### Qu'est-ce que headercheck ?

**headercheck** est un outil en ligne de commande qui analyse les en-tetes de reponse HTTP pour les bonnes pratiques de securite. Il verifie 10 en-tetes de securite critiques, attribue un score (A-F) et fournit des recommandations concretes.

### Verifications effectuees

| En-tete | Severite |
|---|---|
| Content-Security-Policy | Critique |
| Strict-Transport-Security (HSTS) | Critique |
| X-Frame-Options | Haute |
| X-Content-Type-Options | Haute |
| Referrer-Policy | Moyenne |
| Permissions-Policy | Moyenne |
| Cache-Control | Moyenne |
| X-XSS-Protection | Basse |
| Server (exposition) | Basse |
| X-Powered-By (exposition) | Basse |

### Installation

\`\`\`bash
npm install -g headercheck
\`\`\`

### Utilisation

\`\`\`bash
# Scan de base
headercheck https://example.com

# Sortie en francais
headercheck https://example.com --lang fr

# Sortie JSON
headercheck https://example.com --format json

# Timeout personnalise (ms)
headercheck https://example.com --timeout 30000
\`\`\`

### Utilisation programmatique

\`\`\`javascript
const { check } = require('headercheck');

async function run() {
  const result = await check('https://example.com', { lang: 'fr', format: 'json' });
  console.log(result.analysis.grade); // 'A', 'B', 'C', 'D', 'E', ou 'F'
  console.log(result.analysis.score); // 0-100
}

run();
\`\`\`

### Echelle de notation

| Note | Score |
|---|---|
| A | 90-100 |
| B | 80-89 |
| C | 65-79 |
| D | 50-64 |
| E | 30-49 |
| F | 0-29 |

### Codes de sortie

- **0** : Note A, B ou C
- **1** : Note D ou E
- **2** : Note F
- **3** : Erreur (reseau, DNS, timeout)

---

## License

MIT - idirdev
