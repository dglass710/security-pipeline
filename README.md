# DevSecOps CI/CD Security Pipeline

A GitHub Actions CI/CD pipeline that integrates automated security scanning at every stage of the development lifecycle. Built with a deliberately vulnerable Flask application to demonstrate how each security tool detects real-world vulnerabilities.

## Pipeline Architecture

```
Developer pushes code to GitHub
              │
              ▼
┌──────────────────────────────────────────────────────────────┐
│                  GitHub Actions Pipeline                      │
│                                                              │
│  ┌─────────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Secret Scanning │  │  SAST Scan   │  │ Dependency Scan │  │
│  │  (TruffleHog)   │  │  (Semgrep)   │  │ (Trivy)        │  │
│  └────────┬────────┘  └──────┬───────┘  └───────┬────────┘  │
│           │                  │                   │           │
│           └──────────────────┼───────────────────┘           │
│                              │                               │
│                    All three must pass                        │
│                              │                               │
│                              ▼                               │
│                   ┌──────────────────┐                       │
│                   │  Build Docker    │                       │
│                   │  Image           │                       │
│                   └────────┬─────────┘                       │
│                            │                                 │
│                            ▼                                 │
│                   ┌──────────────────┐                       │
│                   │  Container Scan  │                       │
│                   │  (Trivy)         │                       │
│                   └────────┬─────────┘                       │
│                            │                                 │
│  ┌─────────────────┐       │                                 │
│  │  IaC Scan       │       │                                 │
│  │  (Checkov)      ├───────┤                                 │
│  └─────────────────┘       │                                 │
│                            ▼                                 │
│                   ┌──────────────────┐                       │
│                   │  Security        │                       │
│                   │  Summary         │                       │
│                   └──────────────────┘                       │
└──────────────────────────────────────────────────────────────┘
```

**Security gates** enforce that code must pass all scans before it can be built into a deployable image. If any scan finds HIGH or CRITICAL issues, the pipeline blocks downstream stages.

## Security Tools

| Tool | Category | What It Scans | How It Works |
|------|----------|---------------|--------------|
| **TruffleHog** | Secret Detection | Git history and files for leaked credentials | Pattern matching + entropy analysis to find API keys, passwords, tokens |
| **Semgrep** | SAST (Static Application Security Testing) | Source code for vulnerability patterns | Parses code into ASTs and uses taint tracking to follow untrusted input to dangerous operations |
| **Trivy** (filesystem mode) | SCA (Software Composition Analysis) | `requirements.txt` against CVE databases | Matches package names + versions against the National Vulnerability Database |
| **Trivy** (image mode) | Container Scanning | Docker image OS-level packages | Scans every package installed in the container's base image for known CVEs |
| **Checkov** | IaC (Infrastructure as Code) Scanning | Dockerfile for security misconfigurations | Validates configuration against a library of security best-practice checks |

## Intentional Vulnerabilities

The Flask application and Dockerfile contain deliberate security issues to demonstrate scanner capabilities:

### Application Code (`app.py`)

| # | Vulnerability | Description | Scanner |
|---|--------------|-------------|---------|
| 1 | Hardcoded Secrets | API key and database password stored directly in source code | TruffleHog |
| 2 | SQL Injection | User input inserted into SQL queries via string formatting instead of parameterized queries | Semgrep |
| 3 | Server-Side Template Injection (SSTI) | User input passed directly to `render_template_string()`, enabling remote code execution | Semgrep |
| 4 | Cross-Site Scripting (XSS) | User input concatenated into raw HTML strings | Semgrep |
| 5 | Debug Mode Enabled | Flask debug mode exposes interactive debugger to attackers | Semgrep |

### Infrastructure (`Dockerfile`)

| # | Vulnerability | Description | Scanner |
|---|--------------|-------------|---------|
| 6 | Running as Root | No `USER` directive — container processes run with root privileges | Checkov, Semgrep |
| 7 | No HEALTHCHECK | Missing health monitoring — Docker can't detect if the app is unresponsive | Checkov |
| 8 | Outdated Base Image | `python:3.9-slim` contains OS-level packages with known CVEs | Trivy (container scan) |

### Dependencies (`requirements.txt`)

| # | Vulnerability | Description | Scanner |
|---|--------------|-------------|---------|
| 9 | Outdated Packages | Deliberately pinned to old versions of Flask, Werkzeug, Jinja2, requests, and PyYAML with known CVEs | Trivy (dependency scan) |

## Pipeline Results

### TruffleHog (Secret Detection) — Passed

TruffleHog did not flag the hardcoded secrets in `app.py`. The fake credentials did not match its high-confidence detection patterns. In a real scenario with actual API keys (AWS, Stripe, GitHub tokens, etc.), TruffleHog reliably detects them using both regex patterns and entropy analysis.

### Semgrep (SAST) — Failed: 11 Findings

Semgrep identified 11 blocking findings across the application code and Dockerfile:

**SQL Injection (4 findings)**
- `app.py:166-168` — User input from `request.get_json()` flows into a SQL query built with `.format()`. Multiple rules detected the tainted data flow from request to database execution.
- `app.py:169` — Execution of a dynamically constructed query variable.

**Template Injection & XSS (3 findings)**
- `app.py:225` — User input from `request.args.get()` concatenated directly into an HTML string (XSS).
- `app.py:226` — Tainted template string passed to `render_template_string()` (SSTI — enables remote code execution).

**Insecure Configuration (3 findings)**
- `app.py:47` — Hardcoded `DEBUG = True` in Flask config.
- `app.py:249` — `debug=True` in `app.run()` exposes the Werkzeug debugger.
- `app.py:249` — `host="0.0.0.0"` exposes the debug server on all network interfaces.

**Dockerfile (1 finding)**
- `Dockerfile:101` — No `USER` directive; container runs as root.

### Trivy Dependency Scan (SCA) — Failed: 3 HIGH CVEs

| CVE | Package | Severity | Description | Fixed In |
|-----|---------|----------|-------------|----------|
| CVE-2023-30861 | Flask 2.2.0 | HIGH | Session cookie disclosure via response caching — attacker can hijack user sessions | 2.2.5, 2.3.2 |
| CVE-2023-25577 | Werkzeug 2.2.0 | HIGH | High resource usage when parsing multipart form data — Denial of Service | 2.2.3 |
| CVE-2024-34069 | Werkzeug 2.2.0 | HIGH | Code execution through the debugger — Remote Code Execution on developer machines | 3.0.3 |

### Trivy Container Scan — Skipped

The Docker image build was **gated behind** the SAST and dependency scans. Because both failed, the build was skipped — demonstrating the security gate working as intended. Vulnerable code never gets built into a deployable artifact.

### Checkov (IaC Scan) — 23 Passed, 2 Failed (Soft-Fail)

**Failed Checks:**

| Check ID | Description |
|----------|-------------|
| CKV_DOCKER_2 | No `HEALTHCHECK` instruction defined |
| CKV_DOCKER_3 | No non-root `USER` created for the container |

**Notable Passing Checks:**

| Check ID | What It Verified |
|----------|-----------------|
| CKV_DOCKER_1 | Port 22 (SSH) is not exposed |
| CKV_DOCKER_7 | Base image uses a pinned version tag (not `latest`) |
| CKV_DOCKER_10 | WORKDIR uses an absolute path |
| CKV2_DOCKER_1 | `sudo` is not used in the Dockerfile |
| CKV2_DOCKER_2-6, 12-16 | Certificate validation is not disabled for any package manager or tool |

Checkov runs in soft-fail mode — it reports findings without blocking the pipeline, since many IaC checks are best-practice recommendations rather than confirmed vulnerabilities.

## Project Structure

```
├── .github/workflows/
│   └── security-pipeline.yml   # CI/CD pipeline with 6 security stages
├── app.py                      # Flask REST API (intentionally vulnerable)
├── Dockerfile                  # Container definition (intentionally misconfigured)
├── requirements.txt            # Python dependencies (intentionally outdated)
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

- How to integrate security scanning tools into a CI/CD pipeline as automated gates
- The difference between SAST (analyzing source code patterns) and SCA (checking dependencies against CVE databases)
- How Semgrep uses abstract syntax trees and taint tracking to trace user input from HTTP requests to dangerous operations like SQL queries
- Why container scanning is a separate concern from dependency scanning — your app's packages may be clean while the base OS image has vulnerabilities
- How IaC scanning catches infrastructure misconfigurations like running containers as root or missing health checks
- The principle of defense in depth — multiple overlapping tools catch different categories of vulnerability, and some issues (like running as root) get flagged by more than one scanner
