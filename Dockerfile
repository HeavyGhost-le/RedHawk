# RedHawk Security Assessment Framework - Production Dockerfile
# Multi-stage build for minimal image size

# Stage 1: Builder
FROM python:3.11-slim as builder

LABEL maintainer="RedHawk Security Team"
LABEL description="Advanced Security Reconnaissance Framework"
LABEL version="2.0"

# Set working directory
WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libssl-dev \
    libffi-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    netcat-traditional \
    nmap \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    REDHAWK_HOME=/app

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash redhawk && \
    mkdir -p /app /app/reports /app/data && \
    chown -R redhawk:redhawk /app

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=redhawk:redhawk . .

# Switch to non-root user
USER redhawk

# Create necessary directories
RUN mkdir -p reports data/subdomains data/cache logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Expose ports (if web interface is added)
EXPOSE 8080

# Default command
ENTRYPOINT ["python3"]
CMD ["scan.py", "--help"]

# Usage examples:
# Build: docker build -t redhawk:latest .
# Run: docker run -v $(pwd)/reports:/app/reports redhawk:latest scan.py example.com
# GUI: docker run -p 8080:8080 -e DISPLAY=$DISPLAY redhawk:latest --gui
# Interactive: docker run -it redhawk:latest /bin/bash
