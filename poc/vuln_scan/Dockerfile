FROM nvidia/cuda:12.4.1-base-ubuntu22.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    ca-certificates \
    zstd \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://ollama.com/install.sh -o /tmp/install.sh \
    && sed -i 's/systemctl/echo "skipping systemctl"/g' /tmp/install.sh \
    && bash /tmp/install.sh \
    && rm /tmp/install.sh

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Application code is mounted by docker-compose so source edits do not require a rebuild.
ENV PYTHONPATH=/app/src

CMD ["bash", "-lc", "sleep infinity"]
