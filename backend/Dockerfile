# Cyber Risk Pyramid - API (FastAPI + SQLite). One Uvicorn process: SQLite has a single writer and the schedulers must not be duplicated.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DB_PATH=/data/cache.sqlite \
    INTEL_TMP_DIR=/data/import_tmp

WORKDIR /app
COPY requirements-docker.txt .
RUN pip install -r requirements-docker.txt

# application code + the one bundled data file (the MITRE ATT&CK catalogue); never a local database
COPY app ./app
COPY data/mitre_attack.json ./data/mitre_attack.json

# non-root user; /data is the persistent volume (a new named volume inherits this ownership)
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin pyramid \
    && mkdir -p /data/import_tmp \
    && chown -R pyramid:pyramid /data /app
USER pyramid
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"

# exec form: Uvicorn is PID 1 (compose adds an init), receives SIGTERM and shuts down gracefully
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--timeout-graceful-shutdown", "20"]
