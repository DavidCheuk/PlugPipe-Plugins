FROM python:3.11-slim

LABEL maintainer="PlugPipe Project"
LABEL description="MCPGovernance - Enterprise Multi-Tenant Governance Plugin"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy plugin files
COPY . /app/

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install PlugPipe components
RUN pip install --no-cache-dir \
    fastapi>=0.104.0 \
    uvicorn>=0.24.0 \
    pydantic>=2.0.0 \
    redis>=5.0.0 \
    psutil>=5.9.0 \
    aiofiles>=23.0.0 \
    asyncpg>=0.28.0 \
    sqlalchemy>=2.0.0

# Create non-root user for security
RUN useradd -m -u 1000 mcpgovernance && \
    chown -R mcpgovernance:mcpgovernance /app

USER mcpgovernance

# Expose governance API port
EXPOSE 8090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8090/health || exit 1

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8090

# Command to run the plugin as a microservice
CMD ["python", "main.py"]