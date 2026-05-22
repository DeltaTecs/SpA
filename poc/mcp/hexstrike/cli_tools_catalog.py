"""Curated catalogue of the CLI security tools installed in the HexStrike image.

This module backs the Bash MCP server's ``list_cli_tools`` and
``cli_tool_usage`` tools, used by the phase-two "bash mode" analysis. In bash
mode the analysis LLM is given no HexStrike MCP scanning tools; instead it runs
the underlying binaries itself through the ``bash`` tool. This catalogue tells
it which binaries exist (the same ones HexStrike would otherwise invoke) and how
to call them safely.

Every example is intentionally low-impact: by project policy it sets a custom
HTTP ``User-Agent`` and a request rate limit whenever the tool supports them.
``list_cli_tools`` only ever reports binaries actually present on ``PATH``, so a
catalogue entry for a tool that is not installed is simply skipped at runtime.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass


# Example User-Agent used in every catalogue example. It is intentionally an
# honest, identifiable string rather than a spoofed browser.
EXAMPLE_USER_AGENT = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"


@dataclass(frozen=True)
class CliTool:
    """One CLI security tool HexStrike can invoke."""

    binary: str
    category: str
    description: str
    # A short, copy-pasteable example. It sets a custom HTTP User-Agent and a
    # request rate limit wherever the tool supports them.
    example: str
    # Arguments that make the tool print its own help text, used by the
    # ``detailed`` mode of ``cli_tool_usage``. Whitespace-separated; an empty
    # string means "run the binary with no arguments" (only safe for tools that
    # print usage and exit instead of waiting on stdin).
    help_arg: str = "--help"


# The catalogue. Grouped by category purely for readability; ``list_cli_tools``
# regroups available tools by the ``category`` field.
CLI_TOOLS: tuple[CliTool, ...] = (
    # --- Network & port scanning --------------------------------------------
    CliTool(
        "nmap",
        "Network & port scanning",
        "Port scanner with service, version and NSE script detection.",
        'nmap -sV -T2 --max-rate 5 --scan-delay 100ms --script http-headers '
        f'--script-args http.useragent="{EXAMPLE_USER_AGENT}" -p 80,443 TARGET',
        help_arg="-h",
    ),
    CliTool(
        "masscan",
        "Network & port scanning",
        "Internet-scale asynchronous TCP port scanner.",
        "masscan -p80,443 TARGET --rate 100",
    ),
    CliTool(
        "naabu",
        "Network & port scanning",
        "Fast SYN/CONNECT port scanner (ProjectDiscovery).",
        "naabu -host TARGET -top-ports 100 -rate 100",
        help_arg="-h",
    ),
    CliTool(
        "rustscan",
        "Network & port scanning",
        "Fast port scanner that pipes open ports into nmap.",
        "rustscan -a TARGET --ulimit 5000 -- -sV",
        help_arg="-h",
    ),
    CliTool(
        "arp-scan",
        "Network & port scanning",
        "Layer-2 ARP host discovery on the local network.",
        "arp-scan --interval 50 --retry 1 --localnet",
    ),
    # --- DNS & subdomain recon ----------------------------------------------
    CliTool(
        "amass",
        "DNS & subdomain recon",
        "OWASP Amass: subdomain enumeration and DNS mapping.",
        "amass enum -d TARGET -max-dns-queries 50",
        help_arg="enum -h",
    ),
    CliTool(
        "subfinder",
        "DNS & subdomain recon",
        "Passive subdomain discovery (ProjectDiscovery).",
        "subfinder -d TARGET -rate-limit 10 -silent",
        help_arg="-h",
    ),
    CliTool(
        "dnsx",
        "DNS & subdomain recon",
        "DNS resolution and probing toolkit (ProjectDiscovery).",
        "dnsx -d TARGET -rate-limit 50 -silent",
        help_arg="-h",
    ),
    CliTool(
        "dnsenum",
        "DNS & subdomain recon",
        "DNS record enumeration and zone-transfer checks.",
        "dnsenum --threads 2 TARGET",
    ),
    CliTool(
        "fierce",
        "DNS & subdomain recon",
        "DNS reconnaissance and subdomain scanning.",
        "fierce --domain TARGET",
        help_arg="-h",
    ),
    CliTool(
        "subjack",
        "DNS & subdomain recon",
        "Subdomain takeover detection.",
        "subjack -w subdomains.txt -t 20 -timeout 10 -ssl",
        help_arg="-h",
    ),
    # --- HTTP probing & crawling --------------------------------------------
    CliTool(
        "httpx",
        "HTTP probing & crawling",
        "HTTP prober: titles, status codes, tech detection (ProjectDiscovery).",
        f'httpx -u http://TARGET -H "User-Agent: {EXAMPLE_USER_AGENT}" '
        "-rate-limit 20 -title -status-code -tech-detect",
        help_arg="-h",
    ),
    CliTool(
        "katana",
        "HTTP probing & crawling",
        "Web crawler / spider (ProjectDiscovery).",
        f'katana -u http://TARGET -H "User-Agent: {EXAMPLE_USER_AGENT}" '
        "-rate-limit 20 -depth 2",
        help_arg="-h",
    ),
    CliTool(
        "hakrawler",
        "HTTP probing & crawling",
        "Fast web endpoint crawler.",
        f'echo http://TARGET | hakrawler -h "User-Agent: {EXAMPLE_USER_AGENT}" -t 2 -d 2',
        help_arg="-help",
    ),
    CliTool(
        "gau",
        "HTTP probing & crawling",
        "getallurls: fetch a host's known URLs from web archives.",
        "gau --threads 2 TARGET",
    ),
    CliTool(
        "waybackurls",
        "HTTP probing & crawling",
        "Fetch a host's historical URLs from the Wayback Machine.",
        "echo TARGET | waybackurls",
    ),
    CliTool(
        "whatweb",
        "HTTP probing & crawling",
        "Web technology fingerprinting.",
        f'whatweb --user-agent="{EXAMPLE_USER_AGENT}" --wait=1 http://TARGET',
    ),
    CliTool(
        "wafw00f",
        "HTTP probing & crawling",
        "Web application firewall (WAF) fingerprinting.",
        "wafw00f http://TARGET",
        help_arg="-h",
    ),
    # --- Content & parameter discovery --------------------------------------
    CliTool(
        "gobuster",
        "Content & parameter discovery",
        "Brute-force web paths, DNS names and virtual hosts.",
        "gobuster dir -u http://TARGET "
        "-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt "
        f'-a "{EXAMPLE_USER_AGENT}" --delay 100ms',
        help_arg="dir --help",
    ),
    CliTool(
        "ffuf",
        "Content & parameter discovery",
        "Fast web fuzzer for paths, parameters and virtual hosts.",
        "ffuf -u http://TARGET/FUZZ "
        "-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt "
        f'-H "User-Agent: {EXAMPLE_USER_AGENT}" -rate 20',
        help_arg="-h",
    ),
    CliTool(
        "feroxbuster",
        "Content & parameter discovery",
        "Recursive web content discovery.",
        "feroxbuster -u http://TARGET "
        "-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt "
        f'--user-agent "{EXAMPLE_USER_AGENT}" --rate-limit 20',
    ),
    CliTool(
        "dirb",
        "Content & parameter discovery",
        "Classic recursive web content scanner.",
        f'dirb http://TARGET /usr/share/wordlists/dirb/common.txt -a "{EXAMPLE_USER_AGENT}" -z 100',
        help_arg="",
    ),
    CliTool(
        "dirsearch",
        "Content & parameter discovery",
        "Web path scanner.",
        f'dirsearch -u http://TARGET --user-agent "{EXAMPLE_USER_AGENT}" --delay 0.2',
        help_arg="-h",
    ),
    CliTool(
        "wfuzz",
        "Content & parameter discovery",
        "Web application fuzzer.",
        f'wfuzz --hc 404 -H "User-Agent: {EXAMPLE_USER_AGENT}" -s 0.2 '
        "-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt "
        "http://TARGET/FUZZ",
    ),
    CliTool(
        "arjun",
        "Content & parameter discovery",
        "HTTP query and body parameter discovery.",
        f'arjun -u http://TARGET --headers "User-Agent: {EXAMPLE_USER_AGENT}" -d 1 --stable',
        help_arg="-h",
    ),
    CliTool(
        "paramspider",
        "Content & parameter discovery",
        "Mine parameter names from web archives.",
        "paramspider -d TARGET",
        help_arg="-h",
    ),
    CliTool(
        "qsreplace",
        "Content & parameter discovery",
        "Rewrite URL query-string values (reads URLs from stdin).",
        'cat urls.txt | qsreplace "PAYLOAD"',
    ),
    CliTool(
        "uro",
        "Content & parameter discovery",
        "Filter and deduplicate noisy URL lists (reads URLs from stdin).",
        "cat urls.txt | uro",
        help_arg="-h",
    ),
    CliTool(
        "anew",
        "Content & parameter discovery",
        "Append only new, unique lines to a file (reads from stdin).",
        "cat new.txt | anew known.txt",
        help_arg="-h",
    ),
    # --- Vulnerability scanners ---------------------------------------------
    CliTool(
        "nuclei",
        "Vulnerability scanners",
        "Template-based vulnerability scanner (ProjectDiscovery).",
        f'nuclei -u http://TARGET -H "User-Agent: {EXAMPLE_USER_AGENT}" -rate-limit 20',
        help_arg="-h",
    ),
    CliTool(
        "nikto",
        "Vulnerability scanners",
        "Web server misconfiguration and vulnerability scanner.",
        f'nikto -h http://TARGET -useragent "{EXAMPLE_USER_AGENT}" -Pause 1',
        help_arg="-Help",
    ),
    CliTool(
        "sqlmap",
        "Vulnerability scanners",
        "Automated SQL injection detection and exploitation.",
        f'sqlmap -u "http://TARGET/?id=1" --user-agent="{EXAMPLE_USER_AGENT}" '
        "--delay=1 --batch --level=1",
        help_arg="-h",
    ),
    CliTool(
        "wpscan",
        "Vulnerability scanners",
        "WordPress security scanner.",
        f'wpscan --url http://TARGET --user-agent "{EXAMPLE_USER_AGENT}" --throttle 1000',
    ),
    CliTool(
        "dalfox",
        "Vulnerability scanners",
        "Parameter-based XSS scanner.",
        f'dalfox url http://TARGET --user-agent "{EXAMPLE_USER_AGENT}" --delay 200',
    ),
    CliTool(
        "jaeles",
        "Vulnerability scanners",
        "Signature-based web vulnerability scanner.",
        "jaeles scan -c 5 -u http://TARGET",
        help_arg="scan -h",
    ),
    CliTool(
        "commix",
        "Vulnerability scanners",
        "Command-injection detection and exploitation.",
        f'commix --url="http://TARGET/?id=1" --user-agent="{EXAMPLE_USER_AGENT}" '
        "--delay=1 --batch",
        help_arg="-h",
    ),
    # --- TLS / SSL ----------------------------------------------------------
    CliTool(
        "testssl.sh",
        "TLS/SSL",
        "Thorough TLS/SSL configuration and cipher scanner.",
        "testssl.sh https://TARGET",
    ),
    CliTool(
        "sslscan",
        "TLS/SSL",
        "Quick TLS/SSL protocol and cipher scan.",
        "sslscan TARGET",
    ),
    CliTool(
        "sslyze",
        "TLS/SSL",
        "TLS/SSL configuration analyzer.",
        "sslyze TARGET",
    ),
    # --- SMB & Windows ------------------------------------------------------
    CliTool(
        "enum4linux-ng",
        "SMB & Windows",
        "Modern SMB / Windows host enumeration.",
        "enum4linux-ng -A TARGET",
        help_arg="-h",
    ),
    CliTool(
        "enum4linux",
        "SMB & Windows",
        "Classic SMB / Windows enumeration.",
        "enum4linux -a TARGET",
        help_arg="-h",
    ),
    CliTool(
        "nbtscan",
        "SMB & Windows",
        "NetBIOS name scanner.",
        "nbtscan TARGET/24",
        help_arg="-h",
    ),
    CliTool(
        "smbmap",
        "SMB & Windows",
        "Enumerate SMB shares and permissions.",
        "smbmap -H TARGET",
        help_arg="-h",
    ),
    CliTool(
        "rpcclient",
        "SMB & Windows",
        "MS-RPC client for Windows enumeration.",
        'rpcclient -U "" -N TARGET',
    ),
    # --- Secrets, containers & IaC ------------------------------------------
    CliTool(
        "trivy",
        "Secrets, containers & IaC",
        "Vulnerability, secret and misconfiguration scanner.",
        "trivy fs --scanners vuln,secret .",
    ),
    CliTool(
        "trufflehog",
        "Secrets, containers & IaC",
        "Find leaked secrets and credentials.",
        "trufflehog filesystem .",
    ),
    CliTool(
        "checkov",
        "Secrets, containers & IaC",
        "Static analysis for infrastructure-as-code misconfigurations.",
        "checkov -d .",
    ),
    CliTool(
        "terrascan",
        "Secrets, containers & IaC",
        "Detect infrastructure-as-code security violations.",
        "terrascan scan -d .",
    ),
    CliTool(
        "kube-hunter",
        "Secrets, containers & IaC",
        "Kubernetes cluster penetration testing.",
        "kube-hunter --remote TARGET",
    ),
    # --- Credential attacks -------------------------------------------------
    CliTool(
        "hydra",
        "Credential attacks",
        "Network logon brute-forcer.",
        "hydra -l admin -P passwords.txt -t 4 TARGET http-get /",
        help_arg="-h",
    ),
    CliTool(
        "john",
        "Credential attacks",
        "John the Ripper password hash cracker.",
        "john --wordlist=passwords.txt hashes.txt",
        help_arg="",
    ),
    CliTool(
        "hashcat",
        "Credential attacks",
        "GPU-accelerated password hash cracker.",
        "hashcat -m 0 -a 0 hashes.txt passwords.txt",
    ),
    CliTool(
        "hashid",
        "Credential attacks",
        "Identify the type of a password hash.",
        'hashid "HASH"',
    ),
    # --- Forensics & utilities ----------------------------------------------
    CliTool(
        "exiftool",
        "Forensics & utilities",
        "Read and write file metadata.",
        "exiftool suspicious_file",
        help_arg="",
    ),
)

# Order categories are first introduced in CLI_TOOLS; used to group output.
_CATEGORY_ORDER: tuple[str, ...] = tuple(
    dict.fromkeys(tool.category for tool in CLI_TOOLS)
)
_CLI_TOOLS_BY_NAME: dict[str, CliTool] = {tool.binary: tool for tool in CLI_TOOLS}


def find_cli_tool(binary: str) -> CliTool | None:
    """Return the catalogue entry for ``binary``, or ``None`` if not catalogued."""
    return _CLI_TOOLS_BY_NAME.get((binary or "").strip())


def is_installed(binary: str) -> bool:
    """True when ``binary`` is present on ``PATH`` inside the container."""
    return shutil.which(binary) is not None


def available_cli_tools() -> list[CliTool]:
    """Catalogue entries whose binary is actually installed, in catalogue order."""
    return [tool for tool in CLI_TOOLS if is_installed(tool.binary)]


def catalogued_tool_names() -> list[str]:
    """Every binary name in the catalogue, whether installed or not."""
    return [tool.binary for tool in CLI_TOOLS]


def format_cli_tool_list() -> str:
    """Render the ``list_cli_tools`` response: installed tools grouped by category."""
    available = available_cli_tools()
    lines = [
        "CLI security tools available in this container.",
        "",
        "In bash mode you run them yourself with the `bash` tool. Call "
        '`cli_tool_usage("<binary>")` for a safe example invocation, or '
        '`cli_tool_usage("<binary>", detailed=true)` for the full --help output.',
        "",
    ]
    if not available:
        lines.append("(no catalogued CLI tools are installed)")
        return "\n".join(lines)

    by_category: dict[str, list[CliTool]] = {}
    for tool in available:
        by_category.setdefault(tool.category, []).append(tool)

    for category in _CATEGORY_ORDER:
        tools = by_category.get(category)
        if not tools:
            continue
        lines.append(f"{category}:")
        for tool in tools:
            lines.append(f"  {tool.binary} - {tool.description}")
        lines.append("")

    lines.append(f"{len(available)} tool(s) available.")
    return "\n".join(lines).rstrip() + "\n"


def format_tool_example(tool: CliTool, *, installed: bool) -> str:
    """Render the short, non-detailed ``cli_tool_usage`` response."""
    lines = [
        f"{tool.binary} - {tool.description}",
        "",
        "Example invocation (sets a custom HTTP User-Agent and a request rate "
        "limit where the tool supports them):",
        f"  {tool.example}",
        "",
        "Notes:",
        "- Replace TARGET, wordlist paths and file names with real in-scope values.",
        "- Run the command through the `bash` tool.",
        f'- For the full option list, call cli_tool_usage("{tool.binary}", detailed=true).',
    ]
    if not installed:
        lines.insert(
            1,
            f"\n(warning: `{tool.binary}` is not installed in this container)",
        )
    return "\n".join(lines)


def format_tool_help(tool: CliTool, *, help_command: str, help_text: str) -> str:
    """Render the detailed ``cli_tool_usage`` response wrapping raw --help output."""
    body = help_text.strip() or "(the tool produced no help output)"
    return "\n".join(
        [
            f"{tool.binary} - {tool.description}",
            "",
            f"$ {help_command}",
            body,
            "",
            "Reminder: keep scans low-impact - set a custom HTTP User-Agent and a "
            "request rate limit where the tool supports them. See "
            f'cli_tool_usage("{tool.binary}") for an example.',
        ]
    )
