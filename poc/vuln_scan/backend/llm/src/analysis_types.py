from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class AnalysisType:
    label: str
    description: str
    hexstrike_mcp_tools: tuple[str, ...] = ()


RECON_DOMAIN_HEXSTRIKE_MCP_TOOLS = (
    "amass_scan",
    "subfinder_scan",
    "fierce_scan",
    "dnsenum_scan",
    "wafw00f_scan",
    "httpx_probe",
    "nmap_scan",
    "nmap_advanced_scan",
    "rustscan_fast_scan",
    "masscan_high_speed",
    "nbtscan_netbios",
    "enum4linux_scan",
    "enum4linux_ng_advanced",
    "rpcclient_enumeration",
    "smbmap_scan",
    "netexec_scan",
    "gobuster_scan",
    "ffuf_scan",
    "feroxbuster_scan",
    "dirb_scan",
    "dirsearch_scan",
    "katana_crawl",
    "hakrawler_crawl",
    "gau_discovery",
    "waybackurls_discovery",
    "arjun_parameter_discovery",
    "paramspider_discovery",
    "paramspider_mining",
    "x8_parameter_discovery",
    "analyze_target_intelligence",
    "detect_technologies_ai",
    "ai_reconnaissance_workflow",
    "bugbounty_reconnaissance_workflow",
    "bugbounty_osint_gathering",
)

RECON_PORTS_HEXSTRIKE_MCP_TOOLS = (
    "nmap_scan",
    "rustscan_fast_scan",
    "masscan_high_speed",
    "nmap_advanced_scan",
    "arp_scan_discovery",
    "nbtscan_netbios",
    "fierce_scan",
    "dnsenum_scan",
    "autorecon_scan",
    "autorecon_comprehensive",
    "netexec_scan",
    "enum4linux_scan",
    "enum4linux_ng_advanced",
    "rpcclient_enumeration",
)

RECON_HTTP_PATH_API_HEXSTRIKE_MCP_TOOLS = (
    "gobuster_scan",
    "nuclei_scan",
    "dirb_scan",
    "nikto_scan",
    "sqlmap_scan",
    "wpscan_analyze",
    "ffuf_scan",
    "feroxbuster_scan",
    "dotdotpwn_scan",
    "xsser_scan",
    "wfuzz_scan",
    "dirsearch_scan",
    "katana_crawl",
    "gau_discovery",
    "waybackurls_discovery",
    "arjun_parameter_discovery",
    "paramspider_mining",
    "x8_parameter_discovery",
    "jaeles_vulnerability_scan",
    "dalfox_xss_scan",
    "httpx_probe",
    "qsreplace_parameter_replacement",
    "uro_url_filtering",
    "api_fuzzer",
    "graphql_scanner",
    "jwt_analyzer",
    "api_schema_analyzer",
    "comprehensive_api_audit",
    "hakrawler_crawl",
    "paramspider_discovery",
    "burpsuite_scan",
    "zap_scan",
    "arjun_scan",
    "wafw00f_scan",
    "burpsuite_alternative_scan",
    "http_framework_test",
    "browser_agent_inspect",
    "http_set_rules",
    "http_set_scope",
    "http_repeater",
    "http_intruder",
)


ANALYSIS_TYPES: tuple[AnalysisType, ...] = (
    AnalysisType(
        label="Recon: Domain",
        description="Perform a security analysis and discovery of all domains mentioned in the event.",
        hexstrike_mcp_tools=RECON_DOMAIN_HEXSTRIKE_MCP_TOOLS,
    ),
    AnalysisType(
        label="Recon: Ports",
        description="Perform extensive port scans on the machines mentioned in the event.",
        hexstrike_mcp_tools=RECON_PORTS_HEXSTRIKE_MCP_TOOLS,
    ),
    AnalysisType(
        label="Recon: HTTP Path/API",
        description="Perform discovery on any HTTP API or path found in the event.",
        hexstrike_mcp_tools=RECON_HTTP_PATH_API_HEXSTRIKE_MCP_TOOLS,
    ),
    AnalysisType(
        label="Authentication",
        description="Evaluate authentication, session, authorization, and access-control behavior in the event.",
        hexstrike_mcp_tools=(),
    ),
    AnalysisType(
        label="Configuration",
        description=(
            "Evaluate endpoint/cloud configuration of all remote endpoints in the event. "
            "Look for HTTP configuration, exposed storage/database, exposed secrets, etc."
        ),
        hexstrike_mcp_tools=(),
    ),
)

DEFAULT_ANALYSIS_TYPE = ANALYSIS_TYPES[0].label
ANALYSIS_TYPE_DESCRIPTIONS = {item.label: item.description for item in ANALYSIS_TYPES}
ANALYSIS_TYPE_HEXSTRIKE_MCP_TOOLS = {
    item.label: item.hexstrike_mcp_tools for item in ANALYSIS_TYPES
}
ALLOWED_ANALYSIS_TYPES = frozenset(ANALYSIS_TYPE_DESCRIPTIONS)


def hexstrike_mcp_tools_for_analysis_types(analysis_types: Sequence[str]) -> frozenset[str]:
    tools: set[str] = set()
    for analysis_type in analysis_types:
        tools.update(ANALYSIS_TYPE_HEXSTRIKE_MCP_TOOLS.get(analysis_type, ()))
    return frozenset(tools)


def phase_two_scan_type_rows() -> tuple[tuple[str, str], ...]:
    return tuple((item.label, item.description) for item in ANALYSIS_TYPES)
