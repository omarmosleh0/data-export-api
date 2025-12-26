FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY app/ .

RUN chown -R appuser:appgroup /app

USER appuser

# Expose port (Cloud Run will override with $PORT) ya3ni only for documentation
EXPOSE 8080

# --host 0.0.0.0: Accept external connections
# --port $PORT: Use Cloud Run's assigned port (flexible)
# --workers 1: Single worker (Cloud Run handles scaling)
CMD exec uvicorn main:app --host 0.0.0.0 --port $PORT --workers 1