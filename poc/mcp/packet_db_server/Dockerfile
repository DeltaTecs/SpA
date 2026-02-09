FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src/ /app/src/
COPY scripts/ /app/scripts/

ENV PYTHONPATH=/app/src

# Default: run as SSE server so it can be reached from outside the container.
ENV MCP_TRANSPORT=sse \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8765

EXPOSE 8765

CMD ["python", "-m", "packet_db_server.server"]
