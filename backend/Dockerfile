# ==============================================================================
# AegisForge Backend Dockerfile (Multi-Stage Production Build)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Builder (compile dependencies & wheels)
# ------------------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies for C extensions (e.g., Capstone)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libc-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment for clean runtime extraction
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy pyproject.toml and install Python dependencies
COPY backend/pyproject.toml /build/
RUN pip install --upgrade pip setuptools wheel && \
    pip install -e /build/

# ------------------------------------------------------------------------------
# Stage 2: Hardened Runtime
# ------------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app" \
    PORT=8000

# Install minimal networking & diagnostic tools for sandbox interaction and healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iproute2 \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-built virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Create dedicated unprivileged system user and group
RUN groupadd -g 10001 aegis && \
    useradd -u 10001 -g aegis -s /bin/bash -m aegis

# Create required runtime directories and assign permissions
RUN mkdir -p /app/backend/data /app/sandbox/sample_artifacts && \
    chown -R aegis:aegis /app

# Copy application code and assets with non-root ownership
COPY --chown=aegis:aegis backend /app/backend
COPY --chown=aegis:aegis sandbox /app/sandbox

# Switch to unprivileged security user
USER aegis

EXPOSE 8000

# Healthcheck testing backend readiness
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/v1/health || exit 1

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
