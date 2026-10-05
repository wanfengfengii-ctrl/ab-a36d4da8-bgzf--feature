FROM python:3.11-slim

# Application port inside the container. The listening port itself is read
# from PORT at runtime by the application; the Compose mapping can be
# overridden via HOST_PORT.
ENV PORT=8080 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv/bgzf-audit

# The service uses only the Python standard library, so there is nothing
# to install: the image is just the interpreter plus the application.
COPY app/ ./app/
COPY tests/ ./tests/
COPY scripts/ ./scripts/

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /srv/bgzf-audit
USER appuser

EXPOSE 8080

# Container-level health check used by Compose to gate the verify job.
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=12 \
    CMD python -c "import os,sys,urllib.request; port=os.environ.get('PORT','8080'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=2).status == 200 else 1)"

CMD ["python", "-m", "app.server"]
