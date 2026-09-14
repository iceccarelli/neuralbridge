# The assurance register, as a deployable service.
#
# Deliberately not the NeuralBridge image: this package has no runtime
# dependencies of its own beyond a web server, and shipping it alone keeps the
# attack surface of a regulatory register down to what it actually needs.

FROM python:3.12-slim AS build

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir --prefix=/install \
      'fastapi>=0.110.0' 'uvicorn[standard]>=0.27.0' 'pydantic>=2.6.0' 'httpx>=0.27.0'

FROM python:3.12-slim

# Run as a non-root user. A service holding a regulatory record has no business
# running as root, and the container does not need to write anywhere except the
# mounted volume.
RUN useradd --create-home --uid 10001 assurance

COPY --from=build /install /usr/local
COPY --chown=assurance:assurance src/assurance /app/assurance

WORKDIR /app
USER assurance

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ASSURANCE_HOST=0.0.0.0 \
    ASSURANCE_PORT=8080 \
    ASSURANCE_LEDGER=/data/art14-register.db \
    ASSURANCE_ACCOUNTS=/data/accounts.db

EXPOSE 8080

# One worker, on purpose. The evidence ledger and the account store are SQLite
# on a single volume; a second process on a second machine would fork the
# evidence chain, which is the precise failure this package was written to
# prevent. Scale by making the machine bigger, or move the stores to Postgres
# first.
CMD ["uvicorn", "assurance.api.service:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
