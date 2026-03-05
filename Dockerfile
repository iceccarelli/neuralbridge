# ──────────────────────────────────────────────────────────────
# NeuralBridge — Multi-stage Production Docker Image
# ──────────────────────────────────────────────────────────────
# Stage 1: Build the React dashboard
# Stage 2: Build the Python application
# ──────────────────────────────────────────────────────────────

# ── Stage 1: Dashboard Build ─────────────────────────────────
FROM node:22-alpine AS dashboard-builder
WORKDIR /app/dashboard
COPY src/dashboard/package*.json ./
RUN npm install
COPY src/dashboard/ ./
RUN npm run build

# ── Stage 2: Python Application ──────────────────────────────
FROM python:3.11-slim AS production

# Security: run as non-root user
RUN groupadd -r neuralbridge && useradd -r -g neuralbridge -d /app neuralbridge

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements/base.txt requirements/prod.txt ./
RUN pip install --no-cache-dir -r base.txt -r prod.txt

# Copy application source
COPY src/ /app/src/
COPY pyproject.toml README.md ./

# Copy built dashboard
COPY --from=dashboard-builder /app/dashboard/dist /app/static/dashboard

# Install the package
RUN pip install --no-cache-dir -e .

# Copy configuration examples
COPY examples/ /app/examples/

# Set ownership
RUN chown -R neuralbridge:neuralbridge /app

USER neuralbridge

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Environment
ENV NEURALBRIDGE_ENV=production \
    NEURALBRIDGE_HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Start the application
CMD ["uvicorn", "neuralbridge.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
