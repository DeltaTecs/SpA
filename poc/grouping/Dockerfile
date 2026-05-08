FROM nvidia/cuda:12.4.1-base-ubuntu22.04

# Install system dependencies first (rarely changes - good cache layer)
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    ca-certificates \
    zstd \
    && rm -rf /var/lib/apt/lists/*

# Download Ollama using the install script with workarounds for Docker
# This layer is cached as long as the base image and system deps don't change
RUN curl -fsSL https://ollama.com/install.sh -o /tmp/install.sh \
    && sed -i 's/systemctl/echo "skipping systemctl"/g' /tmp/install.sh \
    && bash /tmp/install.sh \
    && rm /tmp/install.sh

# Set working directory
WORKDIR /app

# Copy and install Python dependencies separately for better caching
# Only re-runs if requirements.txt changes
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Application code is mounted via docker-compose volumes, not copied.
# This means grouping module changes do not trigger rebuilds.

# Set Python path
ENV PYTHONPATH=/app/src

# Default command - sleep infinity to keep container running
CMD ["bash", "-lc", "sleep infinity"]
