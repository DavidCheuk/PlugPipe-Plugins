# MCP Guardian - Enterprise Security Proxy Dockerfile
# Multi-stage build for production deployment

# Build stage
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VERSION=1.0.0
ARG VCS_REF

# Add metadata labels
LABEL org.opencontainers.image.title="MCP Guardian" \
      org.opencontainers.image.description="Enterprise Security Proxy for Model Context Protocol" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="PlugPipe Security Team" \
      org.opencontainers.image.licenses="MIT"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim as production

# Create non-root user
RUN groupadd -r mcpguardian && useradd -r -g mcpguardian mcpguardian

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY main.py .
COPY config_template.json .
COPY plug.yaml .

# Create necessary directories
RUN mkdir -p /app/logs /app/cache /app/config && \
    chown -R mcpguardian:mcpguardian /app

# Copy PlugPipe shares (needed for plugin loading)
COPY --chown=mcpguardian:mcpguardian ../../../../shares ./shares/

# Switch to non-root user
USER mcpguardian

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Set environment variables
ENV PYTHONPATH="/app" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MCP_GUARDIAN_CONFIG="/app/config/config.json" \
    MCP_GUARDIAN_LOG_LEVEL="INFO"

# Default command
CMD ["python", "main.py", "--config", "/app/config/config.json"]