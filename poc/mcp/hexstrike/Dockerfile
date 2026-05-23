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
      "defusedxml>=0.7.1,<1.0.0" \
      "dnspython>=2.6.0,<3.0.0" \
      "html5lib>=1.1,<2.0.0" \
      "jsbeautifier>=1.15.0,<2.0.0" \
      "jsonschema>=4.20.0,<5.0.0" \
      "lxml>=5.2.0,<6.0.0" \
      "openapi-spec-validator>=0.7.0,<1.0.0" \
      "PyJWT>=2.8.0,<3.0.0" \
      "PyYAML>=6.0.0,<7.0.0" \
      "selenium>=4.15.0,<5.0.0" \
      "tldextract>=5.1.0,<6.0.0" \
      "urlextract>=1.9.0,<2.0.0" \
      "webdriver-manager>=4.0.0,<5.0.0" \
      "aiohttp>=3.8.0,<4.0.0" \
      "mitmproxy>=9.0.0,<11.0.0" \
      "xmltodict>=0.13.0,<1.0.0"

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
ARG ASSETNOTE_WORDLIST_DATE=2026_01_27
ARG ASSETNOTE_AUTOMATED_BASE=https://wordlists-cdn.assetnote.io/data/automated

ENV HEXSTRIKE_HOME=/opt/hexstrike-ai \
    HEXSTRIKE_VENV=/opt/hexstrike-venv \
    HEXSTRIKE_MODE=api \
    HEXSTRIKE_PORT=8888 \
    HEXSTRIKE_BASH_MCP_PORT=8766 \
    HEXSTRIKE_MCP_HTTP_PORT=8767 \
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
RUN "${HEXSTRIKE_VENV}/bin/python" -c "import bs4, defusedxml, dns.resolver, html5lib, jsbeautifier, jsonschema, jwt, lxml, openapi_spec_validator, requests, tldextract, urlextract, xmltodict, yaml"
COPY bash_mcp_server.py /usr/local/bin/hexstrike-bash-mcp
COPY cli_tools_catalog.py /usr/local/bin/cli_tools_catalog.py
COPY http_mcp_bridge.py /usr/local/bin/hexstrike-http-mcp
COPY entrypoint.sh /usr/local/bin/hexstrike-entrypoint
COPY test/ /app/test/

# HexStrike defaults come from Kali-style wordlist paths, while Debian packages
# install some bundled dictionaries under tool-specific directories. Keep the
# high-signal web discovery wordlists at stable, explicit paths.
RUN set -eux; \
    seclists_dir="/usr/share/seclists/Discovery/Web-Content"; \
    assetnote_dir="/usr/share/wordlists/assetnote"; \
    mkdir -p /usr/share/wordlists; \
    mkdir -p "${seclists_dir}" "${assetnote_dir}"; \
    ensure_wordlist() { \
      local dest="$1"; \
      local url="$2"; \
      shift 2; \
      if [[ -s "${dest}" ]]; then \
        return 0; \
      fi; \
      if [[ -s "${dest}.gz" ]]; then \
        gzip -dc "${dest}.gz" > "${dest}"; \
      fi; \
      for source in "$@"; do \
        if [[ -s "${source}" ]]; then \
          cp "${source}" "${dest}"; \
          return 0; \
        fi; \
        if [[ -s "${source}.gz" ]]; then \
          gzip -dc "${source}.gz" > "${dest}"; \
          return 0; \
        fi; \
      done; \
      if [[ ! -s "${dest}" ]]; then \
        curl -fsSL "${url}" -o "${dest}.tmp"; \
        test -s "${dest}.tmp"; \
        mv "${dest}.tmp" "${dest}"; \
      fi; \
    }; \
    if [[ ! -e /usr/share/wordlists/dirb ]]; then \
      ln -s /usr/share/dirb/wordlists /usr/share/wordlists/dirb; \
    fi; \
    if [[ ! -e /usr/share/wordlists/SecLists ]]; then \
      ln -s /usr/share/seclists /usr/share/wordlists/SecLists; \
    fi; \
    if [[ ! -e /usr/share/SecLists ]]; then \
      ln -s /usr/share/seclists /usr/share/SecLists; \
    fi; \
    ensure_wordlist \
      "${seclists_dir}/raft-medium-directories.txt" \
      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"; \
    ensure_wordlist \
      "${seclists_dir}/raft-medium-words-lowercase.txt" \
      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-words-lowercase.txt"; \
    ensure_wordlist \
      "${seclists_dir}/directory-list-2.3-medium.txt" \
      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt" \
      "${seclists_dir}/DirBuster-2007_directory-list-2.3-medium.txt" \
      "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt" \
      "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"; \
    ensure_wordlist \
      "${assetnote_dir}/httparchive_directories_1m_${ASSETNOTE_WORDLIST_DATE}.txt" \
      "${ASSETNOTE_AUTOMATED_BASE}/httparchive_directories_1m_${ASSETNOTE_WORDLIST_DATE}.txt"; \
    ensure_wordlist \
      "${assetnote_dir}/httparchive_apiroutes_${ASSETNOTE_WORDLIST_DATE}.txt" \
      "${ASSETNOTE_AUTOMATED_BASE}/httparchive_apiroutes_${ASSETNOTE_WORDLIST_DATE}.txt"; \
    ensure_wordlist \
      "${assetnote_dir}/httparchive_parameters_top_1m_${ASSETNOTE_WORDLIST_DATE}.txt" \
      "${ASSETNOTE_AUTOMATED_BASE}/httparchive_parameters_top_1m_${ASSETNOTE_WORDLIST_DATE}.txt"; \
    ln -sf "httparchive_directories_1m_${ASSETNOTE_WORDLIST_DATE}.txt" "${assetnote_dir}/httparchive_directories_1m.txt"; \
    ln -sf "httparchive_apiroutes_${ASSETNOTE_WORDLIST_DATE}.txt" "${assetnote_dir}/httparchive_apiroutes.txt"; \
    ln -sf "httparchive_parameters_top_1m_${ASSETNOTE_WORDLIST_DATE}.txt" "${assetnote_dir}/httparchive_parameters_top_1m.txt"; \
    mkdir -p /usr/share/wordlists/dirbuster /usr/share/wordlists/dirsearch; \
    if [[ ! -e /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt ]]; then \
      ln -s "${seclists_dir}/directory-list-2.3-medium.txt" /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; \
    fi; \
    if [[ ! -e /usr/share/wordlists/dirsearch/common.txt ]]; then \
      ln -s /opt/dirsearch/db/dicc.txt /usr/share/wordlists/dirsearch/common.txt; \
    fi; \
    test -r /usr/share/wordlists/dirb/common.txt; \
    test -r /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; \
    test -r /usr/share/wordlists/dirsearch/common.txt; \
    test -r "${seclists_dir}/raft-medium-directories.txt"; \
    test -r "${seclists_dir}/raft-medium-words-lowercase.txt"; \
    test -r "${seclists_dir}/directory-list-2.3-medium.txt"; \
    test -r "${assetnote_dir}/httparchive_directories_1m.txt"; \
    test -r "${assetnote_dir}/httparchive_apiroutes.txt"; \
    test -r "${assetnote_dir}/httparchive_parameters_top_1m.txt"

RUN set -eux; \
    chmod +x /usr/local/bin/hexstrike-bash-mcp; \
    chmod +x /usr/local/bin/hexstrike-http-mcp; \
    chmod +x /usr/local/bin/hexstrike-entrypoint; \
    mkdir -p /workspace /tmp/hexstrike

WORKDIR /workspace

EXPOSE 8888 8766

HEALTHCHECK --interval=30s --timeout=10s --start-period=45s --retries=3 \
  CMD case "${HEXSTRIKE_MODE}" in bash-mcp|shell-mcp|command-mcp) nc -z 127.0.0.1 "${HEXSTRIKE_BASH_MCP_PORT}" ;; mcp-http|http-mcp|streamable-mcp) nc -z 127.0.0.1 "${HEXSTRIKE_MCP_HTTP_PORT}" ;; *) curl -fsS "http://127.0.0.1:${HEXSTRIKE_PORT}/health" >/dev/null ;; esac

ENTRYPOINT ["tini", "--", "hexstrike-entrypoint"]
CMD []
