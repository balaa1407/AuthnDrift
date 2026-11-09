# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    HOST=0.0.0.0

WORKDIR /app

# Install runtime dependencies (curl for container health check)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create an unprivileged application user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

# Copy application code with non-root ownership
COPY --chown=appuser:appuser backend/ /app/backend/
COPY --chown=appuser:appuser dashboard/ /app/dashboard/
COPY --chown=appuser:appuser keycloak/ /app/keycloak/
COPY --chown=appuser:appuser sample-data/ /app/sample-data/

# Switch to non-root user
USER appuser

# Expose the API port
EXPOSE 8000

# Container health check using the operational /api/health probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Launch the FastAPI application using Uvicorn
CMD ["uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8000"]

