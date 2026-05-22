# HTTP forward proxy backend.
#
# Injects a configurable User-Agent and rate-limits forwarded traffic. The
# implementation uses only the Python standard library, so there are no
# third-party dependencies to install or pin.
FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PROXY_HOST=0.0.0.0 \
    PROXY_PORT=8899 \
    CONFIG_API_HOST=0.0.0.0 \
    CONFIG_API_PORT=8890 \
    PROXY_CONFIG_FILE=/data/proxy_config.json

WORKDIR /app

COPY proxyserver/ ./proxyserver/

# The persisted configuration lives here; mounted as a named volume in compose.
RUN mkdir -p /data

# 8899 = forward proxy, 8890 = configuration API.
EXPOSE 8899 8890

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8890/health', timeout=3)" || exit 1

ENTRYPOINT ["python", "-m", "proxyserver"]
