FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install tshark, python3, pip and dependencies
# Ubuntu 24.04 repositories contain tshark 4.2.x
RUN apt-get update && apt-get install -y \
    tshark \
    python3 \
    python3-pip \
    python3-venv \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Set up Python virtual environment
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install Python libraries
RUN pip install --no-cache-dir scapy psycopg2-binary cryptography

WORKDIR /app

# Keep container running
CMD ["tail", "-f", "/dev/null"]
