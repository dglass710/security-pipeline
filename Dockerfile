# =============================================================================
# Dockerfile — Instructions for building our app into a Docker container
#                              (REMEDIATED version)
# =============================================================================
# A Dockerfile is like a recipe. Docker reads it top-to-bottom and builds
# an "image" — a portable, self-contained package with our app + all its
# dependencies. You can then run that image anywhere Docker is installed.
#
# Our security tools scan this file in two ways:
#   1. Checkov (IaC scanner): checks if the Dockerfile follows best practices
#   2. Trivy (container scanner): scans the BUILT image for OS-level vulns
#
# Changes from the vulnerable version:
#   - Updated base image from python:3.9-slim to python:3.12-slim
#   - Added a non-root user (FIX for Checkov CKV_DOCKER_3)
#   - Added a HEALTHCHECK (FIX for Checkov CKV_DOCKER_2)
# =============================================================================

# ---------------------------------------------------------------------------
# FIX #6: Updated base image (was: python:3.9-slim)
# ---------------------------------------------------------------------------
# python:3.12-slim uses a newer Debian with more recent OS packages,
# which means fewer known CVEs for Trivy to find during container scanning.
#
# Why "slim" and not "alpine"?
#   - Alpine uses musl libc instead of glibc, which can cause subtle
#     compatibility issues with some Python packages.
#   - "slim" is Debian-based but stripped down — a good middle ground
#     between compatibility and image size.
# ---------------------------------------------------------------------------
FROM python:3.12-slim

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
# FIX #7: Create and switch to a non-root user (was: running as root)
# ---------------------------------------------------------------------------
# By default, Docker runs everything as root. If an attacker exploits the
# app, they'd have root privileges inside the container.
#
# 'useradd' creates a new Linux user called "appuser".
#   --create-home: gives them a home directory (some apps need this)
#   --shell /bin/bash: sets their default shell
#
# 'USER appuser' tells Docker: "from this point on, run everything as
# appuser, not root." This applies to the CMD below AND to anyone who
# later runs 'docker exec' into the container.
#
# This is the principle of LEAST PRIVILEGE — give processes only the
# minimum permissions they need. A web app doesn't need root access.
# ---------------------------------------------------------------------------
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

# ---------------------------------------------------------------------------
# FIX #8: Add a HEALTHCHECK (was: missing entirely)
# ---------------------------------------------------------------------------
# HEALTHCHECK tells Docker how to verify the container is actually working.
#
# How it works:
#   --interval=30s : Check every 30 seconds
#   --timeout=3s   : If the check takes longer than 3 seconds, count it as failed
#   --start-period=5s : Wait 5 seconds after container start before first check
#                       (gives the app time to boot up)
#   --retries=3    : Mark as "unhealthy" after 3 consecutive failures
#
# The CMD part is the actual check:
#   python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/')"
#
# We use Python's built-in urllib instead of curl because:
#   - curl isn't installed in the slim image (we'd have to add it)
#   - Python is already available (it's a Python image!)
#   - Fewer installed tools = smaller attack surface
#
# If the health check fails, container orchestrators (Docker Compose,
# Kubernetes, ECS) can automatically restart the container.
# ---------------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/')" || exit 1

# ---------------------------------------------------------------------------
# The command to run when the container starts
# ---------------------------------------------------------------------------
# CMD specifies the default command. Here we just run our Flask app.
# In production you'd use Gunicorn instead:
#   CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000"]
# ---------------------------------------------------------------------------
CMD ["python", "app.py"]
