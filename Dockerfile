# ──────────────────────────────────────────────────────────────
# NeuralBridge — Production Docker Image
# ──────────────────────────────────────────────────────────────
# Python application only. The customer workspace is the Next.js site at the repository
# root (deployed separately, see vercel.json); it is not part of this image.
# ──────────────────────────────────────────────────────────────

# ── Python Application ──────────────────────────────────────
FROM python:3.11-slim AS production

# Security: run as non-root user
RUN groupadd -r neuralbridge && useradd -r -g neuralbridge -d /app neuralbridge

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies from the hash-pinned lock (requirements/prod.lock, generated
# by scripts/lock.sh for Python 3.11 = this base image). The lock installs with pip's own
# --require-hashes; that exact invocation was verified in a Python 3.11 venv, but this
# Dockerfile has NOT been built (no Docker daemon was available when it was changed).
# Documented fallback, the previous unpinned install (resolves newer versions over time):
#   COPY requirements/base.txt requirements/prod.txt ./
#   RUN pip install --no-cache-dir -r base.txt -r prod.txt
COPY requirements/prod.lock ./
RUN pip install --no-cache-dir --require-hashes --no-deps -r prod.lock

# Copy application source
COPY src/ /app/src/
COPY pyproject.toml README.md ./

# Install the package itself only; every dependency is already pinned by the lock above
# (--no-deps keeps pip from resolving anything new).
RUN pip install --no-cache-dir --no-deps -e .

# Copy configuration examples
COPY examples/ /app/examples/

# Set ownership
RUN chown -R neuralbridge:neuralbridge /app

USER neuralbridge

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Environment
ENV NEURALBRIDGE_ENV=production \
    NEURALBRIDGE_DEBUG=false \
    NEURALBRIDGE_HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Start the application
CMD ["uvicorn", "neuralbridge.combined:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
