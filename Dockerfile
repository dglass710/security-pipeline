# =============================================================================
# Dockerfile — Instructions for building our app into a Docker container
# =============================================================================
# A Dockerfile is like a recipe. Docker reads it top-to-bottom and builds
# an "image" — a portable, self-contained package with our app + all its
# dependencies. You can then run that image anywhere Docker is installed.
#
# Our security tools will scan this file in two ways:
#   1. Checkov (IaC scanner): checks if the Dockerfile follows best practices
#   2. Trivy (container scanner): scans the BUILT image for OS-level vulns
# =============================================================================

# ---------------------------------------------------------------------------
# 🚨 INTENTIONAL VULNERABILITY #6: Using an old, bloated base image
# ---------------------------------------------------------------------------
# "python:3.9-slim" is a Debian-based image with just enough to run Python.
# But we're pinning an old version. Trivy will find CVEs in the OS packages.
#
# Best practice: use the latest patched version, or even better, use
# "python:3.12-alpine" (Alpine Linux is much smaller = fewer vulnerabilities).
# ---------------------------------------------------------------------------
FROM python:3.9-slim

# ---------------------------------------------------------------------------
# Set the working directory inside the container
# ---------------------------------------------------------------------------
# All subsequent commands (COPY, RUN, CMD) will execute relative to /app.
# This is like doing "cd /app" — keeps things organized.
# ---------------------------------------------------------------------------
WORKDIR /app

# ---------------------------------------------------------------------------
# Copy dependency file first, then install
# ---------------------------------------------------------------------------
# We copy requirements.txt BEFORE copying the rest of the code. Why?
# Docker caches each layer (step). If requirements.txt hasn't changed,
# Docker reuses the cached "pip install" layer instead of re-downloading
# everything. This makes rebuilds MUCH faster during development.
# ---------------------------------------------------------------------------
COPY requirements.txt .

# ---------------------------------------------------------------------------
# Install Python dependencies
# ---------------------------------------------------------------------------
# pip install -r requirements.txt reads the file and installs everything.
# --no-cache-dir tells pip not to save downloaded packages locally
# (saves space in the Docker image since we won't need them again).
# ---------------------------------------------------------------------------
RUN pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Copy the rest of our application code into the container
# ---------------------------------------------------------------------------
# The first '.' means "current directory on the host" (where Dockerfile is).
# The second '.' means "current WORKDIR in the container" (/app).
# ---------------------------------------------------------------------------
COPY . .

# ---------------------------------------------------------------------------
# Tell Docker which port our app listens on
# ---------------------------------------------------------------------------
# EXPOSE doesn't actually publish the port — it's documentation.
# You still need -p 5000:5000 when running the container.
# Think of it as a label: "this container expects traffic on port 5000."
# ---------------------------------------------------------------------------
EXPOSE 5000

# ---------------------------------------------------------------------------
# 🚨 INTENTIONAL VULNERABILITY #7: Running as root
# ---------------------------------------------------------------------------
# By default, Docker runs everything as the root user. If an attacker
# exploits our app, they'd have ROOT ACCESS inside the container.
#
# Checkov should flag this. The fix is to create a non-root user:
#   RUN useradd --create-home appuser
#   USER appuser
#
# We're intentionally NOT doing that so Checkov has something to find.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 🚨 INTENTIONAL VULNERABILITY #8: No HEALTHCHECK defined
# ---------------------------------------------------------------------------
# A HEALTHCHECK tells Docker how to verify the container is working.
# Without it, Docker assumes the container is healthy as long as the
# process is running — even if the app is deadlocked or returning errors.
#
# Checkov should flag this missing best practice.
# Good HEALTHCHECK example:
#   HEALTHCHECK --interval=30s --timeout=3s \
#     CMD curl -f http://localhost:5000/ || exit 1
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# The command to run when the container starts
# ---------------------------------------------------------------------------
# CMD specifies the default command. Here we just run our Flask app.
# In production you'd use Gunicorn instead:
#   CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000"]
# ---------------------------------------------------------------------------
CMD ["python", "app.py"]
