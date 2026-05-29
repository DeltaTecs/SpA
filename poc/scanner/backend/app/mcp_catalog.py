"""Catalogue of MCP toolsets the pentest flow can expose to the model.

Each entry pairs an :class:`~llm.McpToolset` with a coarse *category*
(``db | search | bash | hexstrike``) so the UI can group the selectable tools and
the approver can recognise the read-only tools that may be exempt from approval.

Toolsets are built fresh per call (mirroring
:func:`app.tasks.base.build_default_toolsets`) so each concurrent pentest session
owns its own MCP connections.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Set

from llm import McpToolset

from .config import Settings

logger = logging.getLogger(__name__)

#: Categories considered read-only / low-risk. Tools in these categories may be
#: exempted from approval via the "allow DB tools & web search without approval"
#: option.
EXEMPT_CATEGORIES = frozenset({"db", "search"})


@dataclass(frozen=True)
class CatalogEntry:
    """One configured MCP toolset and the category it belongs to."""

    name: str
    category: str  # db | search | bash | hexstrike
    toolset: McpToolset


def build_catalog(settings: Settings) -> List[CatalogEntry]:
    """Build every MCP toolset that is configured, tagged with its category.

    ``packet-db`` is always present; the others appear only when their URL/key is
    configured (Tavily search, hexstrike bash, hexstrike tools).
    """
    entries: List[CatalogEntry] = [
        CatalogEntry(
            "packet-db",
            "db",
            McpToolset(settings.mcp_packet_db_url, name="packet-db", timeout=settings.mcp_timeout),
        )
    ]
    if settings.tavily_url:
        entries.append(
            CatalogEntry(
                "tavily",
                "search",
                McpToolset(settings.tavily_url, name="tavily", timeout=settings.mcp_timeout),
            )
        )
    if settings.hexstrike_bash_url:
        entries.append(
            CatalogEntry(
                "hexstrike-bash",
                "bash",
                McpToolset(
                    settings.hexstrike_bash_url, name="hexstrike-bash", timeout=settings.mcp_timeout
                ),
            )
        )
    if settings.hexstrike_tools_url:
        entries.append(
            CatalogEntry(
                "hexstrike-tools",
                "hexstrike",
                McpToolset(
                    settings.hexstrike_tools_url,
                    name="hexstrike-tools",
                    timeout=settings.mcp_timeout,
                ),
            )
        )
    return entries


@dataclass(frozen=True)
class CatalogTools:
    """Result of enumerating the catalogue once before a job runs."""

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
    names and the set of categories that actually hold a selected tool, so each
    session only connects to the toolsets it needs.
    """
    exempt: Set[str] = set()
    needed: Set[str] = set()
    for entry in build_catalog(settings):
        try:
            names = {spec.name for spec in entry.toolset.list_tool_specs()}
        except Exception as exc:  # noqa: BLE001 - one bad server must not abort the job
            logger.warning("Skipping toolset '%s' (could not list tools): %s", entry.name, exc)
            continue
        if include_exempt and entry.category in EXEMPT_CATEGORIES:
            exempt |= names
        if names & allowed:
            needed.add(entry.category)
    return CatalogTools(exempt_names=exempt, needed_categories=needed)
