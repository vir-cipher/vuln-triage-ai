# Target OSS Projects for Vulnerability Triage Experiment

## Selection criteria (applied to all candidates)

1. **Language coverage** — at least Python, C, and JavaScript represented
   (differentiates from Java-only prior art in arXiv:2601.22952).
2. **Fix-commit density** — project must have ≥10 documented security-fix
   commits with clear before/after diffs.
3. **Semgrep coverage** — Semgrep must have rules for the project primary language.
4. **Public CVE trail** — each vulnerability has a public CVE ID linking to a fix commit.
5. **Diversity of vulnerability types** — across the 5 projects, cover at least
   3 distinct CWE categories (injection, memory corruption, auth bypass, etc.).

---

## Selected Projects

### 1. Django

- **Repository:** https://github.com/django/django
- **Language:** Python
- **Fix-commit density:** 100+ CVEs documented at
  docs.djangoproject.com/en/6.0/releases/security/. Multiple security releases
  per year (6 in 2025 alone). Each CVE has a dedicated fix commit per branch.
- **Vulnerability types:** SQL injection (CVE-2025-64459), XSS, CSRF bypass,
  open redirect, path traversal, DoS (CVE-2025-64458), header injection.
- **Semgrep rules:** ~100+ Django-specific rules (django.security.*).
- **Rationale:** Most popular Python web framework. Fix commits are clean  (security-only, not mixed with feature work). Vulnerability types map
  directly to Semgrep OWASP rule sets. The Django security team documents each
  fix with affected versions, severity, and the exact commit SHA — ideal for
  git archaeology.

### 2. curl

- **Repository:** https://github.com/curl/curl
- **Language:** C
- **Fix-commit density:** 200+ CVE references at curl.se/docs/security.html.
  18 CVEs fixed in curl 8.21.0 alone (June 2026). Each CVE links to the exact
  fix commit.
- **Vulnerability types:** buffer overflow, use-after-free (CVE-2026-9080),
  double-free (CVE-2026-8925), authentication bypass (CVE-2026-8932, mTLS
  reuse), CRLF injection, integer overflow.
- **Semgrep rules:** C-language rules for memory-unsafe patterns (strcpy,
  sprintf, unbounded memcpy), null-pointer dereference, format-string bugs.
- **Rationale:** Deployed on ~30 billion devices. The 25-year security history
  gives the richest git archaeology of any C project. Daniel Stenberg documents
  each CVE meticulously with root cause, affected versions, and the fix diff.
  C memory bugs are the archetype of "Semgrep catches the pattern, but is it
  exploitable?" — perfect for triage evaluation.

### 3. OpenSSL

- **Repository:** https://github.com/openssl/openssl
- **Language:** C
- **Fix-commit density:** 70+ CVEs at openssl-library.org/news/vulnerabilities/.
  12 vulnerabilities fixed in a January 2026 release including a high-severity
  RCE (CVE-2025-15467).- **Vulnerability types:** stack buffer overflow (CVE-2025-15467,
  CVE-2025-11187), NULL pointer dereference (CVE-2023-0217), memory leak,
  integer overflow, X.509 certificate handling errors, timing side-channels.
- **Semgrep rules:** C-language rules for buffer operations, pointer arithmetic,
  and crypto-specific anti-patterns.
- **Rationale:** The most scrutinized cryptographic library. Vulnerability types
  include both simple memory bugs (Semgrep-detectable) and subtle crypto logic
  errors (likely false negatives) — this mix is exactly what the context-curve
  experiment needs. Higher context levels should help with subtle ones; the
  question is whether they also introduce noise that hurts on simple ones.

### 4. Pillow

- **Repository:** https://github.com/python-pillow/Pillow
- **Language:** Python + C (codec extensions)
- **Fix-commit density:** 20+ CVEs. Notable: CVE-2025-48379 (heap buffer
  overflow in DDS codec, C), CVE-2024-28219 (buffer overflow in _imagingcms.c),
  CVE-2023-50447 (code execution via ImageMath.eval, Python).
- **Vulnerability types:** heap buffer overflow (C codecs), integer overflow,
  code execution via eval (Python), denial of service (decompression bombs).
- **Semgrep rules:** Python rules (eval, exec, unsafe deserialization) + C rules
  (buffer overflow, unbounded copy).
- **Rationale:** Bridges two languages in one project — the same repo has
  Python-level logic bugs AND C-extension memory bugs. This lets the
  context-curve experiment compare how context helps differently for high-level
  vs low-level vulnerabilities within the same project. The codebase is small
  enough (~50k LOC) for complete mining.

### 5. Node.js
- **Repository:** https://github.com/nodejs/node
- **Language:** JavaScript + C++
- **Fix-commit density:** Multiple security releases per year (July 2025:
  CVE-2025-27210, CVE-2025-27209; January 2026: 8 vulnerabilities including
  3 high-severity). Each release has tagged commits.
- **Vulnerability types:** HTTP request smuggling (header parsing), path
  traversal (CVE-2025-23084, Windows device names), permission model bypass,
  HashDoS (CVE-2025-27209), denial of service, memory exposure.
- **Semgrep rules:** JavaScript/TypeScript rules for injection, path traversal,
  prototype pollution, and Node-specific patterns (child_process, fs, eval).
- **Rationale:** Provides the JavaScript leg of the cross-language experiment.
  HTTP parser vulnerabilities are particularly interesting for context-level
  analysis — understanding whether a header-parsing bug is exploitable requires
  cross-file context (how the parser output flows into routing), making it a
  natural test case for the context-optimality curve.

---

## Language Coverage Summary

| Language   | Projects                | Count |
|------------|-------------------------|-------|
| Python     | Django, Pillow          | 2     |
| C          | curl, OpenSSL, Pillow*  | 3     |
| JavaScript | Node.js                 | 1     |

*Pillow C extensions count toward C coverage; its Python code toward Python.

**Cross-language differentiation vs prior art:** Sifting the Noise
(arXiv:2601.22952) evaluated only Java projects using OWASP Benchmark.Our 5 projects span Python, C, and JavaScript — three languages with
fundamentally different vulnerability profiles (memory safety vs injection
vs prototype pollution).

## Vulnerability Type Diversity

| CWE Category                 | Projects with this type          |
|------------------------------|----------------------------------|
| Injection (SQLi, XSS, CRLF) | Django, curl                     |
| Memory corruption (BOF, UAF) | curl, OpenSSL, Pillow            |
| Auth/access control bypass   | curl, Node.js                    |
| Path traversal               | Django, Node.js                  |
| Denial of service            | Django, OpenSSL, Node.js, Pillow |
| Code execution               | OpenSSL, Pillow                  |

6 distinct CWE categories across the 5 projects (threshold was 3).

## Primary Sources Consulted

- Django: https://docs.djangoproject.com/en/6.0/releases/security/
- curl: https://curl.se/docs/security.html
- OpenSSL: https://openssl-library.org/news/vulnerabilities/
- Pillow: https://www.cvedetails.com/product/27460/Python-Pillow.html
- Node.js: https://nodejs.org/en/blog/vulnerability/