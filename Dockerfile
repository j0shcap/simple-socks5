# Pinned to the multi-arch index digest. To refresh: docker buildx imagetools inspect python:3.13-slim
FROM python:3.13-slim@sha256:3dd7cc108ec1493442514f5c2a871af6af0ec31d768ff6e378a93340c3b3db5f

ARG LOGGING_LEVEL=info
ENV LOGGING_LEVEL=${LOGGING_LEVEL} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY src/ ./src/
COPY app.py .

# Switch User (non-root)
RUN useradd -m appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 1080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('127.0.0.1',1080)); s.close()"
# Exec form so python is PID 1 and receives SIGTERM from docker stop; app.py reads LOGGING_LEVEL itself.
CMD ["python", "app.py", "--host", "0.0.0.0", "--port", "1080"]
