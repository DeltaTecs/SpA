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
    "masscan_high_speed",
    "nbtscan_netbios",
    "rpcclient_enumeration",
    "netexec_scan",
    "gobuster_scan",
    "ffuf_scan",
    "feroxbuster_scan",
    "dirb_scan",
    "dirsearch_scan",
    "katana_crawl",
    "hakrawler_crawl",
    "arjun_parameter_discovery",
    "paramspider_discovery",
    "paramspider_mining",
    "x8_parameter_discovery",
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

AUTHENTICATION_HEXSTRIKE_MCP_TOOLS = (
    "api_fuzzer",
    "graphql_scanner",
    "jwt_analyzer",
    "api_schema_analyzer",
    "comprehensive_api_audit",
    "http_framework_test",
    "browser_agent_inspect",
    "http_set_rules",
    "http_set_scope",
    "http_repeater",
    "http_intruder",
    "burpsuite_scan",
    "burpsuite_alternative_scan",
    "zap_scan",
    "nuclei_scan",
    "jaeles_vulnerability_scan",
    "dalfox_xss_scan",
    "arjun_parameter_discovery",
    "arjun_scan",
    "paramspider_discovery",
    "paramspider_mining",
    "x8_parameter_discovery",
    "qsreplace_parameter_replacement",
    "analyze_target_intelligence",
)

CONFIGURATION_HEXSTRIKE_MCP_TOOLS = (
    "nuclei_scan",
    "nikto_scan",
    "wpscan_analyze",
    "wafw00f_scan",
    "httpx_probe",
    "http_framework_test",
    "browser_agent_inspect",
    "http_set_rules",
    "http_set_scope",
    "http_repeater",
    "burpsuite_scan",
    "burpsuite_alternative_scan",
    "zap_scan",
    "graphql_scanner",
    "api_schema_analyzer",
    "jwt_analyzer",
    "comprehensive_api_audit",
    "api_fuzzer",
    "checkov_iac_scan",
    "terrascan_iac_scan",
    "prowler_scan",
    "scout_suite_assessment",
    "cloudmapper_analysis",
    "trivy_scan",
    "clair_vulnerability_scan",
    "falco_runtime_monitoring",
    "exiftool_extract",
    "analyze_target_intelligence",
    "format_tool_output_visual",
)

POST_RECON_HEXSTRIKE_MCP_TOOLS = (
    "gobuster_scan",
    "checkov_iac_scan",
    "terrascan_iac_scan",
    "create_file",
    "modify_file",
    "delete_file",
    "list_files",
    "generate_payload",
    "install_python_package",
    "execute_python_script",
    "dirb_scan",
    "nikto_scan",
    "sqlmap_scan",
    "metasploit_run",
    "hydra_attack",
    "wpscan_analyze",
    "ffuf_scan",
    "subfinder_scan",
    "rustscan_fast_scan",
    "autorecon_comprehensive",
    "msfvenom_generate",
    "feroxbuster_scan",
    "dotdotpwn_scan",
    "xsser_scan",
    "wfuzz_scan",
    "dirsearch_scan",
    "katana_crawl",
    "arjun_parameter_discovery",
    "paramspider_mining",
    "x8_parameter_discovery",
    "jaeles_vulnerability_scan",
    "dalfox_xss_scan",
    "httpx_probe",
    "anew_data_processing",
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
    "fierce_scan",
    "generate_exploit_from_cve",
    "browser_agent_inspect",
    "http_set_rules",
    "http_set_scope",
    "http_repeater",
    "http_intruder",
    "burpsuite_alternative_scan",
)


# Label of the user-defined analysis type. Unlike the fixed types above, its
# goal description and tool exposure are supplied per run: the goal comes from
# a free-text field and the tools from one of the custom tool sets below.
CUSTOM_ANALYSIS_TYPE = "Custom"

# MCP server categories used by custom tool sets that constrain whole servers
# instead of just selecting a HexStrike allow-list.
CUSTOM_TOOL_CATEGORY_DATABASE = "database"
CUSTOM_TOOL_CATEGORY_SEARCH = "search"
CUSTOM_TOOL_CATEGORY_BASH = "bash"

# HexStrike MCP tool sets selectable for a "Custom" analysis. Keys are labels
# shown in the UI dropdown; each maps to one of the tool tuples above so the
# custom type reuses the exact same tool lists as the fixed types.
CUSTOM_HEXSTRIKE_TOOL_SETS: dict[str, tuple[str, ...]] = {
    "Network": RECON_PORTS_HEXSTRIKE_MCP_TOOLS,
    "Domain": RECON_DOMAIN_HEXSTRIKE_MCP_TOOLS,
    "HTTP/API": RECON_HTTP_PATH_API_HEXSTRIKE_MCP_TOOLS,
    "Authentication": AUTHENTICATION_HEXSTRIKE_MCP_TOOLS,
    "Configuration": CONFIGURATION_HEXSTRIKE_MCP_TOOLS,
    "Post-Recon General": POST_RECON_HEXSTRIKE_MCP_TOOLS,
}

# Custom MCP server exposure sets. These intentionally disable HexStrike tools
# and restrict the phase-two run to the listed non-HexStrike server categories.
CUSTOM_MCP_SERVER_TOOL_SETS: dict[str, tuple[str, ...]] = {
    "Database": (CUSTOM_TOOL_CATEGORY_DATABASE,),
    "Database+Search": (
        CUSTOM_TOOL_CATEGORY_DATABASE,
        CUSTOM_TOOL_CATEGORY_SEARCH,
    ),
    "Database+Search+Bash": (
        CUSTOM_TOOL_CATEGORY_DATABASE,
        CUSTOM_TOOL_CATEGORY_SEARCH,
        CUSTOM_TOOL_CATEGORY_BASH,
    ),
}
CUSTOM_TOOL_SETS = (
    *CUSTOM_HEXSTRIKE_TOOL_SETS,
    *CUSTOM_MCP_SERVER_TOOL_SETS,
)
ALLOWED_CUSTOM_TOOL_SETS = frozenset(CUSTOM_TOOL_SETS)


ANALYSIS_TYPES: tuple[AnalysisType, ...] = (
    AnalysisType(
        label="Recon: Domain",
        description="Perform a security analysis and discovery of all domains mentioned in the event. Do not go beyond domain level scanning. Give a detailed domain level report.",
        hexstrike_mcp_tools=RECON_DOMAIN_HEXSTRIKE_MCP_TOOLS,
    ),
    AnalysisType(
        label="Recon: Ports",
        description="Perform extensive port scans on the machines mentioned in the event. Do not go beyond network level scanning. Give a detailed network level report.",
        hexstrike_mcp_tools=RECON_PORTS_HEXSTRIKE_MCP_TOOLS,
    ),
    AnalysisType(
        label="Recon: HTTP Path/API",
        description="Perform discovery on any HTTP API or path found in the event. Give a detailed HTTP path/API level report.",
        hexstrike_mcp_tools=RECON_HTTP_PATH_API_HEXSTRIKE_MCP_TOOLS,
    ),
    AnalysisType(
        label="Authentication",
        description="Evaluate authentication, session, authorization, and access-control behavior in the event. Also, look specifically for an authentication bypass. Give a detailed authentication focues report.",
        hexstrike_mcp_tools=AUTHENTICATION_HEXSTRIKE_MCP_TOOLS,
    ),
    AnalysisType(
        label="Configuration",
        description=(
            "Evaluate endpoint/cloud configuration of all remote endpoints in the event. "
            "Look for HTTP configuration, exposed storage/database, exposed secrets, etc. Give a detailed configuration report."
        ),
        hexstrike_mcp_tools=CONFIGURATION_HEXSTRIKE_MCP_TOOLS,
    ),
    AnalysisType(
        label="Post Recon - Explorative",
        description=(
            "Do not perform network scans or http analysis. "
            "Do not focus on authentication mechanisms. "
            "Perform a broad, explorative analysis of the remote service. "
            "Think outside the box and try new approaches. Do not get stuck in one finding. Findings do not need to be quaranteed confirmed, suspicions are sufficient. Give a detailed explorative report."
        ),
        hexstrike_mcp_tools=POST_RECON_HEXSTRIKE_MCP_TOOLS,
    ),
    AnalysisType(
        label="Post Recon - High Impact",
        description=(
            "Do not perform network scans or http analysis. "
            "Preform an in-depth analysis on a single finding. Try to confirm the finding and find an exploit path."),
        hexstrike_mcp_tools=POST_RECON_HEXSTRIKE_MCP_TOOLS,
    ),
    AnalysisType(
        label=CUSTOM_ANALYSIS_TYPE,
        description=(
            "Run a user-defined analysis. The goal is supplied by the user at "
            "scan time and replaces this description; the enabled MCP tools "
            "come from the user-selected tool set."
        ),
        # Tools are resolved per run from the selected custom tool-set entry
        # rather than from a fixed list.
        hexstrike_mcp_tools=(),
    ),
)

DEFAULT_ANALYSIS_TYPE = ANALYSIS_TYPES[0].label
ANALYSIS_TYPE_DESCRIPTIONS = {item.label: item.description for item in ANALYSIS_TYPES}
ANALYSIS_TYPE_HEXSTRIKE_MCP_TOOLS = {
    item.label: item.hexstrike_mcp_tools for item in ANALYSIS_TYPES
}
ALLOWED_ANALYSIS_TYPES = frozenset(ANALYSIS_TYPE_DESCRIPTIONS)


def description_for_analysis_type(
    analysis_type: str, *, custom_goal: str = ""
) -> str:
    """Resolve the goal description used to brief the LLM for an analysis type.

    The ``Custom`` type has no fixed description: the user-supplied
    ``custom_goal`` takes its place. Every other type uses its static
    description.
    """
    if analysis_type == CUSTOM_ANALYSIS_TYPE:
        return custom_goal.strip()
    return ANALYSIS_TYPE_DESCRIPTIONS.get(analysis_type, "")


def hexstrike_mcp_tools_for_analysis_types(
    analysis_types: Sequence[str], *, custom_tool_set: str = ""
) -> frozenset[str]:
    """Union of HexStrike MCP tools enabled by the selected analysis types.

    The ``Custom`` type draws HexStrike tools from ``custom_tool_set`` when it
    names one of :data:`CUSTOM_HEXSTRIKE_TOOL_SETS`. Server-category custom
    tool sets (for example ``Database``) intentionally contribute no HexStrike
    tools.
    """
    tools: set[str] = set()
    for analysis_type in analysis_types:
        if analysis_type == CUSTOM_ANALYSIS_TYPE:
            tools.update(CUSTOM_HEXSTRIKE_TOOL_SETS.get(custom_tool_set, ()))
        else:
            tools.update(ANALYSIS_TYPE_HEXSTRIKE_MCP_TOOLS.get(analysis_type, ()))
    return frozenset(tools)


def custom_tool_set_server_categories(custom_tool_set: str) -> frozenset[str] | None:
    """Return the MCP server categories selected by a custom tool set.

    ``None`` means the tool set does not constrain whole MCP server categories;
    this is the case for the HexStrike-oriented custom tool sets.
    """
    categories = CUSTOM_MCP_SERVER_TOOL_SETS.get(custom_tool_set)
    if categories is None:
        return None
    return frozenset(categories)


def custom_server_categories_for_analysis_types(
    analysis_types: Sequence[str], *, custom_tool_set: str = ""
) -> frozenset[str] | None:
    """Return MCP server categories to expose for the selected analysis types.

    Only the ``Custom`` analysis type can request a whole-server tool set. A
    return value of ``None`` means normal phase-two server exposure applies.
    """
    if CUSTOM_ANALYSIS_TYPE not in analysis_types:
        return None
    return custom_tool_set_server_categories(custom_tool_set)


def phase_two_scan_type_rows() -> tuple[tuple[str, str], ...]:
    return tuple((item.label, item.description) for item in ANALYSIS_TYPES)
