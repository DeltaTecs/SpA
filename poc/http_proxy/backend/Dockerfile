# HTTP/HTTPS forward proxy backend.
#
# mitmproxy handles HTTP forwarding and HTTPS interception. The local Python
# entrypoint keeps the configuration API running alongside mitmdump.
FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PROXY_HOST=0.0.0.0 \
    PROXY_PORT=8899 \
    CONFIG_API_HOST=0.0.0.0 \
    CONFIG_API_PORT=8890 \
    PROXY_CONFIG_FILE=/data/proxy_config.json \
    MITMPROXY_CONF_DIR=/mitmproxy

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY proxyserver/ ./proxyserver/

# /data holds persisted UI settings. /mitmproxy holds the generated CA certs.
RUN mkdir -p /data /mitmproxy

# 8899 = forward proxy, 8890 = configuration API.
EXPOSE 8899 8890

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8890/health', timeout=3)" || exit 1

ENTRYPOINT ["python", "-m", "proxyserver"]
