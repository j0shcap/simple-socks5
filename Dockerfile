# Pinned to the multi-arch index digest. To refresh: docker buildx imagetools inspect python:3.13-slim
FROM python:3.13-slim@sha256:3dd7cc108ec1493442514f5c2a871af6af0ec31d768ff6e378a93340c3b3db5f

ARG LOGGING_LEVEL=info
ENV LOGGING_LEVEL=${LOGGING_LEVEL} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir --no-deps --root-user-action=ignore . \
    && rm -rf src build pyproject.toml
COPY app.py .

# Switch User (non-root)
RUN useradd -m appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 1080
# Speaks SOCKS5, so the server logs the probe at DEBUG only. Set SOCKS5_HEALTHCHECK_PORT if you change --port.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python", "-m", "simple_socks5.healthcheck"]
# Exec form so python is PID 1 and receives SIGTERM from docker stop; the program reads LOGGING_LEVEL itself.
CMD ["python", "-m", "simple_socks5", "--host", "0.0.0.0", "--port", "1080"]
