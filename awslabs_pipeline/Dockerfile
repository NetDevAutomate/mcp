# AWS Labs CI Pipeline Docker Image
# Multi-stage build for security and performance

FROM public.ecr.aws/docker/library/python:3.12-alpine3.19 AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    git

# Set working directory
WORKDIR /app

# Install uv package manager
RUN pip install --no-cache-dir uv

# Copy requirements first for layer caching
COPY requirements.uv pyproject.toml ./

# Install dependencies with hash verification
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv /app/.venv && \
    /app/.venv/bin/pip install --require-hashes -r requirements.uv

# Final runtime stage
FROM public.ecr.aws/docker/library/python:3.12-alpine3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    docker-cli \
    git \
    curl && \
    update-ca-certificates

# Create application user for security
RUN addgroup -S app && \
    adduser -S app -G app -h /app

# Set working directory
WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder --chown=app:app /app/.venv /app/.venv

# Copy application code
COPY --chown=app:app . /app/

# Add virtual environment to PATH
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install act (GitHub Actions runner)
RUN curl -q https://raw.githubusercontent.com/nektos/act/master/install.sh | bash

# Health check for CI pipeline
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import awslabs_ci_tool; print('OK')" || exit 1

# Run as non-root user for security
USER app

# Create necessary directories
RUN mkdir -p /app/{artifacts,cache,reports,coverage}

# Entry point for CI tool
ENTRYPOINT ["python", "-m", "awslabs_ci_tool.cli"]
CMD ["--help"]
