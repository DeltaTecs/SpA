"""Catalogue of MCP toolsets the pentest flow can expose to the model.

Each entry pairs an :class:`~llm.McpToolset` with a coarse *category*
(``db | search | bash | hexstrike``) so the UI can group the selectable tools and
the approver can recognise the read-only tools that may be exempt from approval.

Toolsets are built fresh per call (mirroring
:func:`app.tasks.base.build_default_toolsets`) so each concurrent pentest session
owns its own MCP connections.

Entries that can spawn long-running OS processes (the active HexStrike tooling)
carry a :class:`StopSpec` describing how to terminate those processes when a job
is cancelled; :func:`terminate_tool_processes` consults it.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import List, Literal, Optional, Set
from urllib.parse import urlsplit, urlunsplit

import httpx

from llm import CallBudget, McpToolset, ToolSpec
from llm.client import Toolset

from .config import Settings
from .toolsets import build_tavily_toolset

logger = logging.getLogger(__name__)

#: Stable toolset names. Defined once so :func:`build_catalog` and the
#: name -> category map below can never drift apart.
PACKET_DB_TOOLSET = "packet-db"
TAVILY_TOOLSET = "tavily"
HEXSTRIKE_BASH_TOOLSET = "hexstrike-bash"
HEXSTRIKE_TOOLS_TOOLSET = "hexstrike-tools"

#: Coarse category of each toolset (``db | search | bash | hexstrike``). Drives UI
#: grouping, approval exemption (db + search are read-only), and the classification
#: of a captured transcript step so the Tool Transcript page can filter DB/search noise.
TOOLSET_CATEGORIES: dict[str, str] = {
    PACKET_DB_TOOLSET: "db",
    TAVILY_TOOLSET: "search",
    HEXSTRIKE_BASH_TOOLSET: "bash",
    HEXSTRIKE_TOOLS_TOOLSET: "hexstrike",
}

#: Categories considered read-only / low-risk. Tools in these categories may be
#: exempted from approval via the "allow DB tools & web search without approval"
#: option.
EXEMPT_CATEGORIES = frozenset({"db", "search"})


def category_for_toolset(name: Optional[str]) -> str:
    """Coarse category for a toolset name (``"other"`` for anything unrecognised).

    Used to classify a recorded transcript step by the toolset that owned the call.
    """
    return TOOLSET_CATEGORIES.get(name or "", "other")

#: HexStrike's MCP server exposes a broad toolbox. Keep the pentest surface
#: intentionally smaller so operators only select tools supported by this flow.
HEXSTRIKE_PENTEST_TOOLS = frozenset(
    {
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
        "amass_scan",
        "fierce_scan",
        "dnsenum_scan",
        "wafw00f_scan",
        "httpx_probe",
        "nmap_scan",
        "nmap_advanced_scan",
        "masscan_high_speed",
        "nbtscan_netbios",
        "rpcclient_enumeration",
        "netexec_scan",
        "dirsearch_scan",
        "katana_crawl",
        "hakrawler_crawl",
        "arjun_parameter_discovery",
        "paramspider_discovery",
        "paramspider_mining",
        "x8_parameter_discovery",
        "jaeles_vulnerability_scan",
        "dalfox_xss_scan",
        "anew_data_processing",
        "qsreplace_parameter_replacement",
        "uro_url_filtering",
        "api_fuzzer",
        "graphql_scanner",
        "jwt_analyzer",
        "api_schema_analyzer",
        "comprehensive_api_audit",
        "burpsuite_scan",
        "zap_scan",
        "arjun_scan",
        "generate_exploit_from_cve",
        "browser_agent_inspect",
        "http_set_rules",
        "http_set_scope",
        "http_repeater",
        "http_intruder",
        "burpsuite_alternative_scan",
    }
)

#: How long to wait for a server to kill its tool processes (the HexStrike
#: servers escalate SIGTERM -> SIGKILL with a few seconds in between).
STOP_TIMEOUT_SECONDS = 20.0


@dataclass(frozen=True)
class StopSpec:
    """How to terminate a toolset's running tool processes.

    ``kind="tool"`` invokes a regular MCP tool by name (full handshake), e.g.
    hexstrike-bash's ``stop_active_bash``. ``kind="admin"`` posts to an
    authenticated HTTP admin endpoint outside the MCP protocol.
    """

    kind: Literal["tool", "admin"]
    name: str


@dataclass(frozen=True)
class CatalogEntry:
    """One configured MCP toolset and the category it belongs to."""

    name: str
    category: str  # db | search | bash | hexstrike
    #: The toolset. Usually a raw :class:`~llm.McpToolset`, but the ``search``
    #: (Tavily) entry is the cost-controlled wrapper from
    #: :func:`app.toolsets.build_tavily_toolset`. Only stop-capable entries
    #: (hexstrike) are accessed via ``.url`` in :func:`terminate_tool_processes`,
    #: and those are always raw ``McpToolset`` — so the wider type is safe.
    toolset: Toolset
    #: How to kill this server's tool processes on termination (``None`` if the
    #: server only serves quick, read-only calls with nothing to stop).
    stop: Optional[StopSpec] = None


def build_catalog(
    settings: Settings, *, budget: CallBudget | None = None
) -> List[CatalogEntry]:
    """Build every MCP toolset that is configured, tagged with its category.

    ``packet-db`` is always present; the others appear only when their URL/key is
    configured (Tavily search, hexstrike bash, hexstrike tools). The Tavily entry
    is assembled with cost controls (caching, parameter clamping, optional
    per-job ``budget``) via :func:`app.toolsets.build_tavily_toolset`; tool
    availability still follows the operator's selection (``restrict_tools=False``).
    """
    entries: List[CatalogEntry] = [
        CatalogEntry(
            PACKET_DB_TOOLSET,
            TOOLSET_CATEGORIES[PACKET_DB_TOOLSET],
            McpToolset(
                settings.mcp_packet_db_url, name=PACKET_DB_TOOLSET, timeout=settings.mcp_timeout
            ),
        )
    ]
    if settings.tavily_url:
        entries.append(
            CatalogEntry(
                TAVILY_TOOLSET,
                TOOLSET_CATEGORIES[TAVILY_TOOLSET],
                build_tavily_toolset(settings, budget=budget, restrict_tools=False),
            )
        )
    if settings.hexstrike_bash_url:
        entries.append(
            CatalogEntry(
                HEXSTRIKE_BASH_TOOLSET,
                TOOLSET_CATEGORIES[HEXSTRIKE_BASH_TOOLSET],
                McpToolset(
                    settings.hexstrike_bash_url,
                    name=HEXSTRIKE_BASH_TOOLSET,
                    timeout=settings.mcp_timeout,
                ),
                # The bash server exposes a `stop_active_bash` MCP tool that kills
                # any running command process groups it started.
                stop=StopSpec("tool", "stop_active_bash"),
            )
        )
    if settings.hexstrike_tools_url:
        entries.append(
            CatalogEntry(
                HEXSTRIKE_TOOLS_TOOLSET,
                TOOLSET_CATEGORIES[HEXSTRIKE_TOOLS_TOOLSET],
                McpToolset(
                    settings.hexstrike_tools_url,
                    name=HEXSTRIKE_TOOLS_TOOLSET,
                    timeout=settings.mcp_timeout,
                ),
                # The admin endpoint terminates managed scanners and their
                # stdio MCP wrappers without exposing stop as an MCP tool.
                stop=StopSpec("admin", "/admin/tools/stop"),
            )
        )
    return entries


def list_selectable_tool_specs(entry: CatalogEntry) -> List[ToolSpec]:
    """List the tools this pentest flow permits an operator to select."""
    specs = entry.toolset.list_tool_specs()
    if entry.category != "hexstrike":
        return specs
    return [spec for spec in specs if spec.name in HEXSTRIKE_PENTEST_TOOLS]


@dataclass(frozen=True)
class CatalogTools:
    """Result of enumerating the catalogue once before a job runs."""

    #: Requested tool names that exist in the selectable catalogue.
    allowed_names: Set[str] = field(default_factory=set)
    #: Read-only (db + search) tool names eligible for approval exemption.
    exempt_names: Set[str] = field(default_factory=set)
    #: Categories that contain at least one selected (allowed) tool — i.e. the
    #: only toolsets a session actually needs to connect to.
    needed_categories: Set[str] = field(default_factory=set)


def enumerate_catalog(
    settings: Settings, *, allowed: Set[str], include_exempt: bool
) -> CatalogTools:
    """Discover catalogue tools once, resiliently, before fanning out sessions.

    A toolset that cannot be reached is skipped (logged), so an unselected or
    down active-tooling server never aborts the job. Returns the exempt tool
    names, sanitized allowed names, and the set of categories that actually hold
    a selected tool, so each session only connects to the toolsets it needs.
    """
    selected: Set[str] = set()
    exempt: Set[str] = set()
    needed: Set[str] = set()
    for entry in build_catalog(settings):
        try:
            names = {spec.name for spec in list_selectable_tool_specs(entry)}
        except Exception as exc:  # noqa: BLE001 - one bad server must not abort the job
            logger.warning("Skipping toolset '%s' (could not list tools): %s", entry.name, exc)
            continue
        if include_exempt and entry.category in EXEMPT_CATEGORIES:
            exempt |= names
        selected_here = names & allowed
        if selected_here:
            selected |= selected_here
            needed.add(entry.category)
    return CatalogTools(
        allowed_names=selected,
        exempt_names=exempt,
        needed_categories=needed,
    )


# --- termination -------------------------------------------------------------


@dataclass(frozen=True)
class ToolTermination:
    """The outcome of asking one toolset's server to kill its tool processes."""

    name: str
    category: str
    ok: bool
    detail: str = ""


def terminate_tool_processes(settings: Settings) -> List[ToolTermination]:
    """Ask every stop-capable MCP server to kill its running tool processes.

    Used when an operator terminates a job. Each server is signalled
    best-effort: an unreachable or failing server is reported with ``ok=False``
    rather than aborting the others. The HexStrike servers stop processes
    server-wide (they do not track per-session), so this kills active tool
    processes for *any* job sharing those servers — acceptable for a hard stop.
    Read-only servers (db, search) have no ``StopSpec`` and are skipped.
    """
    results: List[ToolTermination] = []
    for entry in build_catalog(settings):
        if entry.stop is None:
            continue
        try:
            if entry.stop.kind == "tool":
                detail = entry.toolset.call_tool(entry.stop.name, {})
            else:
                detail = _post_admin_stop(
                    entry.toolset.url,
                    entry.stop.name,
                    settings.hexstrike_tools_admin_token,
                )
            logger.info("Stopped tool processes for '%s': %s", entry.name, detail)
            results.append(ToolTermination(entry.name, entry.category, True, detail))
        except Exception as exc:  # noqa: BLE001 - one bad server must not block the rest
            logger.warning("Could not stop tool processes for '%s': %s", entry.name, exc)
            results.append(ToolTermination(entry.name, entry.category, False, str(exc)))
    return results


def _post_admin_stop(mcp_url: str, path: str, token: Optional[str]) -> str:
    """Ask the HexStrike bridge admin endpoint to stop active tool processes."""
    if not token:
        raise RuntimeError("HEXSTRIKE_TOOLS_ADMIN_TOKEN is not configured")

    parsed = urlsplit(mcp_url)
    url = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
    response = httpx.post(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        },
        timeout=STOP_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    result = response.json()
    if not isinstance(result, dict):
        raise RuntimeError("HexStrike admin stop response is not a JSON object")
    return str(result["message"]) if result.get("message") else json.dumps(result)
