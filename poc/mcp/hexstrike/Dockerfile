# syntax=docker/dockerfile:1.7

FROM golang:1.25-bookworm AS go-tools

ARG DEBIAN_FRONTEND=noninteractive
ARG TRIVY_VERSION=0.70.0
ARG TRUFFLEHOG_VERSION=3.95.2
ARG TERRASCAN_VERSION=1.19.9

ENV HEXSTRIKE_HOME=/opt/hexstrike-ai \
    HEXSTRIKE_VENV=/opt/hexstrike-venv \
    PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/opt/secbin \
    PATH=/opt/secbin:/usr/local/go/bin:${PATH}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p "${PIPX_BIN_DIR}"

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.14.0

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.8.0

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/projectdiscovery/katana/cmd/katana@v1.6.1

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.3

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/owasp-amass/amass/v4/cmd/amass@v4.2.0

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/OJ/gobuster/v3@v3.8.2

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/ffuf/ffuf/v2@v2.1.0

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/hahwul/dalfox/v2@v2.13.0

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/jaeles-project/jaeles@beta-v0.17.1

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/hakluke/hakrawler@61905593d82e8bac87ff7a7cca32b2adde42bb60

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/lc/gau/v2/cmd/gau@v2.2.4

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/tomnomnom/waybackurls@v0.1.0

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/tomnomnom/anew@v0.1.1

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/tomnomnom/qsreplace@v0.0.3

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOBIN="${PIPX_BIN_DIR}" go install github.com/haccer/subjack@b53899ce6230767beb1c4a9f879c6ebba23a98fa

RUN set -eux; \
    tmp_dir="$(mktemp -d)"; \
    cd "${tmp_dir}"; \
    curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"; \
    grep "  trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -; \
    mkdir trivy; \
    tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -C trivy; \
    install -m 0755 trivy/trivy "${PIPX_BIN_DIR}/trivy"; \
    cd /; \
    rm -rf "${tmp_dir}"

RUN set -eux; \
    tmp_dir="$(mktemp -d)"; \
    cd "${tmp_dir}"; \
    curl -fsSLO "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz"; \
    curl -fsSLO "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt"; \
    grep "  trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz$" "trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt" | sha256sum -c -; \
    mkdir trufflehog; \
    tar -xzf "trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" -C trufflehog; \
    install -m 0755 trufflehog/trufflehog "${PIPX_BIN_DIR}/trufflehog"; \
    cd /; \
    rm -rf "${tmp_dir}"

RUN set -eux; \
    tmp_dir="$(mktemp -d)"; \
    cd "${tmp_dir}"; \
    curl -fsSLO "https://github.com/tenable/terrascan/releases/download/v${TERRASCAN_VERSION}/terrascan_${TERRASCAN_VERSION}_Linux_x86_64.tar.gz"; \
    curl -fsSLO "https://github.com/tenable/terrascan/releases/download/v${TERRASCAN_VERSION}/checksums.txt"; \
    grep "  terrascan_${TERRASCAN_VERSION}_Linux_x86_64.tar.gz$" checksums.txt | sha256sum -c -; \
    mkdir terrascan; \
    tar -xzf "terrascan_${TERRASCAN_VERSION}_Linux_x86_64.tar.gz" -C terrascan; \
    install -m 0755 terrascan/terrascan "${PIPX_BIN_DIR}/terrascan"; \
    cd /; \
    rm -rf "${tmp_dir}"

FROM python:3.11-slim-bookworm AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG HEXSTRIKE_ARCHIVE_BASE=https://github.com/0x4m4/hexstrike-ai/archive
ARG HEXSTRIKE_REF=9b8c780f324ce5145a322bfa23c98886f8424ba3
ARG DIRSEARCH_REPO=https://github.com/maurosoria/dirsearch.git
ARG DIRSEARCH_REF=v0.4.3

ENV HEXSTRIKE_HOME=/opt/hexstrike-ai \
    HEXSTRIKE_VENV=/opt/hexstrike-venv \
    PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/opt/secbin \
    PATH=/opt/secbin:/opt/hexstrike-venv/bin:${PATH}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      curl \
      git \
      libffi-dev \
      libssl-dev \
      pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv "${HEXSTRIKE_VENV}"

RUN "${HEXSTRIKE_VENV}/bin/pip" install --no-cache-dir --upgrade pip "setuptools<81" wheel

RUN "${HEXSTRIKE_VENV}/bin/pip" install --no-cache-dir \
      "flask>=2.3.0,<4.0.0" \
      "requests>=2.31.0,<3.0.0" \
      "psutil>=5.9.0,<6.0.0" \
      "fastmcp>=0.2.0,<1.0.0" \
      "mcp>=1.2.0" \
      "beautifulsoup4>=4.12.0,<5.0.0" \
      "selenium>=4.15.0,<5.0.0" \
      "webdriver-manager>=4.0.0,<5.0.0" \
      "aiohttp>=3.8.0,<4.0.0" \
      "mitmproxy>=9.0.0,<11.0.0"

RUN set -eux; \
    mkdir -p "${HEXSTRIKE_HOME}"; \
    curl -fsSL "${HEXSTRIKE_ARCHIVE_BASE}/${HEXSTRIKE_REF}.tar.gz" \
      | tar -xz --strip-components=1 -C "${HEXSTRIKE_HOME}"

RUN git clone --depth 1 --branch "${DIRSEARCH_REF}" "${DIRSEARCH_REPO}" /opt/dirsearch

RUN "${HEXSTRIKE_VENV}/bin/pip" install --no-cache-dir -r /opt/dirsearch/requirements.txt

RUN set -eux; \
    mkdir -p "${PIPX_BIN_DIR}"; \
    printf '%s\n' \
      '#!/usr/bin/env bash' \
      'exec /opt/hexstrike-venv/bin/python /opt/dirsearch/dirsearch.py "$@"' \
      > "${PIPX_BIN_DIR}/dirsearch"; \
    chmod +x "${PIPX_BIN_DIR}/dirsearch"

RUN python -m pip install --no-cache-dir pipx

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps arjun || echo "Skipped failed Python tool install: arjun"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps paramspider || echo "Skipped failed Python tool install: paramspider"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps wafw00f || echo "Skipped failed Python tool install: wafw00f"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps uro || echo "Skipped failed Python tool install: uro"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps shodan || echo "Skipped failed Python tool install: shodan"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps censys || echo "Skipped failed Python tool install: censys"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps prowler || echo "Skipped failed Python tool install: prowler"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps ScoutSuite || echo "Skipped failed Python tool install: ScoutSuite"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps checkov || echo "Skipped failed Python tool install: checkov"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps kube-hunter || echo "Skipped failed Python tool install: kube-hunter"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps sslyze || echo "Skipped failed Python tool install: sslyze"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps hashid || echo "Skipped failed Python tool install: hashid"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps sherlock-project || echo "Skipped failed Python tool install: sherlock-project"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps social-analyzer || echo "Skipped failed Python tool install: social-analyzer"

RUN PIPX_HOME="${PIPX_HOME}" PIPX_BIN_DIR="${PIPX_BIN_DIR}" python -m pipx install --include-deps spiderfoot || echo "Skipped failed Python tool install: spiderfoot"

RUN set -eux; \
    find "${PIPX_HOME}" -type d -name "__pycache__" -prune -exec rm -rf {} +; \
    rm -rf /root/.cache/pip

FROM python:3.11-slim-bookworm

ARG DEBIAN_FRONTEND=noninteractive
ARG PROTONVPN_RELEASE_VERSION=1.0.8
ARG PROTONVPN_RELEASE_SHA256=0b14e71586b22e498eb20926c48c7b434b751149b1f2af9902ef1cfe6b03e180

ENV HEXSTRIKE_HOME=/opt/hexstrike-ai \
    HEXSTRIKE_VENV=/opt/hexstrike-venv \
    HEXSTRIKE_MODE=api \
    HEXSTRIKE_PORT=8888 \
    HEXSTRIKE_BASH_MCP_PORT=8766 \
    HEXSTRIKE_STARTUP_TIMEOUT=60 \
    PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/opt/secbin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/secbin:/opt/hexstrike-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      chromium \
      chromium-driver \
      curl \
      dnsutils \
      iproute2 \
      iputils-ping \
      jq \
      netcat-openbsd \
      openssl \
      procps \
      tini \
      unzip \
      wget \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    apt-get update; \
    protonvpn_release="protonvpn-stable-release_${PROTONVPN_RELEASE_VERSION}_all.deb"; \
    curl -fsSLo "/tmp/${protonvpn_release}" "https://repo.protonvpn.com/debian/dists/stable/main/binary-all/${protonvpn_release}"; \
    echo "${PROTONVPN_RELEASE_SHA256}  /tmp/${protonvpn_release}" | sha256sum -c -; \
    apt-get install -y --no-install-recommends "/tmp/${protonvpn_release}"; \
    rm -f "/tmp/${protonvpn_release}"; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    apt-get update; \
    systemctl_path="$(command -v systemctl || true)"; \
    restore_systemctl() { \
      if [[ -n "${systemctl_path}" && -x "${systemctl_path}.real" ]]; then \
        mv -f "${systemctl_path}.real" "${systemctl_path}"; \
      fi; \
    }; \
    trap restore_systemctl EXIT; \
    if [[ -n "${systemctl_path}" ]]; then \
      mv "${systemctl_path}" "${systemctl_path}.real"; \
      printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "${systemctl_path}"; \
      chmod +x "${systemctl_path}"; \
    fi; \
    apt-get install -y --no-install-recommends \
      dbus \
      gnome-keyring \
      network-manager \
      openvpn \
      proton-vpn-cli \
      wireguard-tools; \
    restore_systemctl; \
    trap - EXIT; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    apt-get update; \
    category_tools=( \
      nmap masscan amass fierce dnsenum theharvester responder enum4linux-ng arp-scan nbtscan \
      samba-common-bin smbmap gobuster feroxbuster dirsearch ffuf dirb nikto sqlmap wpscan \
      arjun wafw00f whatweb wfuzz commix testssl.sh sslscan sslyze \
      john hashcat hashid hash-identifier \
      recon-ng spiderfoot sherlock trufflehog \
      trivy kube-hunter kube-bench checkov terrascan awscli kubectl helm \
      seclists wordlists \
    ); \
    installable=(); \
    for pkg in "${category_tools[@]}"; do \
      if apt-cache show "${pkg}" >/dev/null 2>&1; then \
        installable+=("${pkg}"); \
      else \
        echo "Skipping unavailable apt package: ${pkg}"; \
      fi; \
    done; \
    if ((${#installable[@]})); then \
      apt-get install -y --no-install-recommends "${installable[@]}"; \
    fi; \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/hexstrike-ai /opt/hexstrike-ai
COPY --from=builder /opt/hexstrike-venv /opt/hexstrike-venv
COPY --from=builder /opt/dirsearch /opt/dirsearch
COPY --from=builder /opt/pipx /opt/pipx
COPY --from=builder /opt/secbin /opt/secbin
COPY --from=go-tools /opt/secbin /opt/secbin
COPY bash_mcp_server.py /usr/local/bin/hexstrike-bash-mcp
COPY entrypoint.sh /usr/local/bin/hexstrike-entrypoint

RUN set -eux; \
    chmod +x /usr/local/bin/hexstrike-bash-mcp; \
    chmod +x /usr/local/bin/hexstrike-entrypoint; \
    mkdir -p /workspace /tmp/hexstrike

WORKDIR /workspace

EXPOSE 8888 8766

HEALTHCHECK --interval=30s --timeout=10s --start-period=45s --retries=3 \
  CMD case "${HEXSTRIKE_MODE}" in bash-mcp|shell-mcp|command-mcp) nc -z 127.0.0.1 "${HEXSTRIKE_BASH_MCP_PORT}" ;; *) curl -fsS "http://127.0.0.1:${HEXSTRIKE_PORT}/health" >/dev/null ;; esac

ENTRYPOINT ["tini", "--", "hexstrike-entrypoint"]
CMD []
