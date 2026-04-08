# DevSecOps CI/CD Security Pipeline

A GitHub Actions CI/CD pipeline that integrates automated security scanning at every stage of the development lifecycle. Built with a deliberately vulnerable Flask application to demonstrate how each security tool detects real-world vulnerabilities — then remediated to achieve a fully passing pipeline.

## Pipeline Architecture

```
Developer pushes code to GitHub
              │
              ▼
┌────────────────────────────────────────────────────────────────┐
│                  GitHub Actions Pipeline                       │
│                                                                │
│  ┌──────────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │  Secret Scanning │  │  SAST Scan   │  │ Dependency Scan │   │
│  │  (TruffleHog)    │  │  (Semgrep)   │  │ (Trivy)         │   │
│  └────────┬─────────┘  └──────┬───────┘  └───────┬─────────┘   │
│           │                  │                   │             │
│           └──────────────────┼───────────────────┘             │
│                              │                                 │
│                    All three must pass                         │
│                              │                                 │
│                              ▼                                 │
│                   ┌──────────────────┐                         │
│                   │  Build Docker    │                         │
│                   │  Image           │                         │
│                   └────────┬─────────┘                         │
│                            │                                   │
│                            ▼                                   │
│                   ┌──────────────────┐                         │
│                   │  Container Scan  │                         │
│                   │  (Trivy)         │                         │
│                   └────────┬─────────┘                         │
│                            │                                   │
│  ┌─────────────────┐       │                                   │
│  │  IaC Scan       │       │                                   │
│  │  (Checkov)      ├───────┤                                   │
│  └─────────────────┘       │                                   │
│                            ▼                                   │
│                   ┌──────────────────┐                         │
│                   │  Security        │                         │
│                   │  Summary         │                         │
│                   └──────────────────┘                         │
└────────────────────────────────────────────────────────────────┘
```

**Security gates** enforce that code must pass all scans before it can be built into a deployable image. If any scan finds HIGH or CRITICAL issues, the pipeline blocks downstream stages — vulnerable code never gets built into a deployable artifact.

## Security Tools

| Tool | Category | What It Scans | How It Works |
|------|----------|---------------|--------------|
| **TruffleHog** | Secret Detection | Git history and files for leaked credentials | Pattern matching + entropy analysis to find API keys, passwords, tokens |
| **Semgrep** | SAST (Static Application Security Testing) | Source code for vulnerability patterns | Parses code into ASTs and uses taint tracking to follow untrusted input to dangerous operations |
| **Trivy** (filesystem mode) | SCA (Software Composition Analysis) | `requirements.txt` against CVE databases | Matches package names + versions against the National Vulnerability Database |
| **Trivy** (image mode) | Container Scanning | Docker image OS-level packages | Scans every package installed in the container's base image for known CVEs |
| **Checkov** | IaC (Infrastructure as Code) Scanning | Dockerfile for security misconfigurations | Validates configuration against a library of security best-practice checks |

## Vulnerability Findings & Remediation

The project was built in two phases: first with intentional vulnerabilities to demonstrate scanner detection, then remediated to demonstrate the fix for each finding.

### Phase 1: Intentional Vulnerabilities Planted

#### Application Code (`app.py`)

| # | Vulnerability | Description | Scanner |
|---|--------------|-------------|---------|
| 1 | Hardcoded Secrets | API key and database password stored directly in source code | TruffleHog |
| 2 | SQL Injection | User input inserted into SQL queries via string formatting instead of parameterized queries | Semgrep |
| 3 | Server-Side Template Injection (SSTI) | User input passed directly to `render_template_string()`, enabling remote code execution | Semgrep |
| 4 | Cross-Site Scripting (XSS) | User input concatenated into raw HTML strings | Semgrep |
| 5 | Debug Mode Enabled | Flask debug mode exposes interactive debugger to attackers | Semgrep |

#### Infrastructure (`Dockerfile`)

| # | Vulnerability | Description | Scanner |
|---|--------------|-------------|---------|
| 6 | Running as Root | No `USER` directive — container processes run with root privileges | Checkov, Semgrep |
| 7 | No HEALTHCHECK | Missing health monitoring — Docker can't detect if the app is unresponsive | Checkov |
| 8 | Outdated Base Image | `python:3.9-slim` contains OS-level packages with known CVEs | Trivy (container scan) |

#### Dependencies (`requirements.txt`)

| # | Vulnerability | Description | Scanner |
|---|--------------|-------------|---------|
| 9 | Outdated Packages | Deliberately pinned to old versions of Flask, Werkzeug, Jinja2, requests, and PyYAML with known CVEs | Trivy (dependency scan) |

### Phase 1 Results: Scanner Findings

**Semgrep (SAST) — 11 Blocking Findings:**

| Category | Count | Details |
|----------|-------|---------|
| SQL Injection | 4 | Taint tracking followed user input from `request.get_json()` through `.format()` string building to `conn.execute()` |
| Template Injection / XSS | 3 | User input concatenated into HTML string and passed to `render_template_string()` |
| Insecure Configuration | 3 | Hardcoded `DEBUG = True`, debug mode in `app.run()`, server bound to `0.0.0.0` with debugger |
| Dockerfile | 1 | Container running as root with no `USER` directive |

**Trivy SCA — 3 HIGH CVEs:**

| CVE | Package | Description |
|-----|---------|-------------|
| CVE-2023-30861 | Flask 2.2.0 | Session cookie disclosure via response caching — attacker can hijack user sessions |
| CVE-2023-25577 | Werkzeug 2.2.0 | High resource usage parsing multipart form data — Denial of Service |
| CVE-2024-34069 | Werkzeug 2.2.0 | Code execution through the debugger — Remote Code Execution |

**Checkov (IaC) — 2 Failed Checks:**

| Check ID | Description |
|----------|-------------|
| CKV_DOCKER_2 | No `HEALTHCHECK` instruction defined |
| CKV_DOCKER_3 | No non-root `USER` created for the container |

**Pipeline gate in action:** The Docker image build was blocked because SAST and dependency scans failed upstream. The container scan was also skipped. This demonstrates the security gate working as designed.

### Phase 2: Remediation

Every finding was fixed with industry-standard practices:

| Vulnerability | Fix Applied | Security Principle |
|--------------|-------------|-------------------|
| Hardcoded secrets | Replaced with `os.environ.get()` to load from environment variables | Separation of config from code |
| SQL injection | Replaced `.format()` with parameterized queries (`?` placeholders) | Parameterized queries — the #1 SQL injection defense |
| SSTI / XSS | Replaced `render_template_string()` with safe `jsonify()` responses | Never mix user input with template compilation |
| Debug mode | Moved to environment variable, defaults to off | Secure by default |
| Running as root | Added `useradd` and `USER appuser` directive | Principle of least privilege |
| No HEALTHCHECK | Added HEALTHCHECK using Python `urllib` | Enable automated health monitoring and recovery |
| Outdated base image | Updated `python:3.9-slim` → `python:3.12-slim` | Minimize known vulnerabilities in OS packages |
| Outdated dependencies | Updated all packages to latest stable versions | Patch known CVEs |
| `0.0.0.0` host binding | Added `nosemgrep` inline suppression with justification comment | Informed risk acceptance — required for Docker networking |

### Phase 2 Results: All Gates Passing

```
✅ Secret Scanning (TruffleHog)    — no leaked credentials
✅ SAST (Semgrep)                  — 0 findings (down from 11)
✅ Dependency Scan (Trivy)         — no known CVEs in packages
✅ Build Docker Image              — built successfully
✅ Container Scan (Trivy)          — no HIGH/CRITICAL CVEs in image
✅ IaC Scan (Checkov)              — all checks passing
✅ Security Summary                — all gates passed
```

## Git History

The commit history tells the full story of the project lifecycle:

```
7ec6ee7  Suppress Semgrep false positive for 0.0.0.0 host binding
c15d8de  Fix Dockerfile: add non-root user and HEALTHCHECK
170e905  Fix dependency vulnerabilities: update all packages to latest versions
a114f54  Fix SAST findings: SQL injection, SSTI, debug mode, hardcoded secrets
b6582e1  Add README documenting pipeline architecture and security findings
f86ab9c  Show Semgrep findings in plain text in Actions log
5096e0c  Fix Trivy action version to 0.35.0
5b142a0  Initial commit: Flask app with DevSecOps security pipeline
```

## Project Structure

```
├── .github/workflows/
│   └── security-pipeline.yml   # CI/CD pipeline with 6 security stages
├── app.py                      # Flask REST API (remediated)
├── Dockerfile                  # Container definition (hardened)
├── requirements.txt            # Python dependencies (patched)
├── .dockerignore               # Files excluded from Docker builds
├── .gitignore                  # Files excluded from version control
└── README.md                   # This file
```

## Technologies

- **Application:** Python, Flask
- **Containerization:** Docker
- **CI/CD:** GitHub Actions
- **SAST:** Semgrep
- **SCA / Container Scanning:** Trivy
- **Secret Detection:** TruffleHog
- **IaC Scanning:** Checkov

## What I Learned

- How to integrate security scanning tools into a CI/CD pipeline as automated gates that block vulnerable code from being deployed
- The difference between SAST (analyzing source code patterns via AST parsing and taint tracking) and SCA (checking dependency versions against CVE databases)
- How Semgrep traces untrusted user input from HTTP request sources through data transformations to dangerous sinks like SQL queries — across multiple lines of code
- Why container scanning and dependency scanning are separate concerns — your application packages may be clean while the base OS image has vulnerable system libraries
- How IaC scanning catches infrastructure misconfigurations like running containers as root or missing health checks
- The principle of defense in depth — multiple overlapping scanners catch different vulnerability categories, and some issues (like running as root) get flagged by more than one tool
- How to triage scanner findings — distinguishing real vulnerabilities from context-dependent false positives and documenting suppression decisions with inline comments
- How security gates use job dependencies (`needs`) in GitHub Actions to enforce a build order where vulnerable code never reaches the Docker image build stage
