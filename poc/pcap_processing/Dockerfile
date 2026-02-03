FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install tshark, python3, pip and dependencies
# Add Wireshark PPA for latest version (4.4+) with TLS 1.3 decryption fixes
RUN apt-get update && apt-get install -y \
    software-properties-common \
    gnupg \
    && add-apt-repository -y ppa:wireshark-dev/stable \
    && apt-get update && apt-get install -y \
    tshark \
    python3 \
    python3-pip \
    python3-venv \
    libpq-dev \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Set up Python virtual environment
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install Python libraries
RUN pip install --no-cache-dir scapy psycopg2-binary cryptography brotli zstandard erlpack

WORKDIR /app

ENTRYPOINT ["/usr/bin/tini", "--"]

# Keep container running
CMD ["tail", "-f", "/dev/null"]
