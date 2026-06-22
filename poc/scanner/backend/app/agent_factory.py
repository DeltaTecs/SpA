"""Shared construction of LLM providers and tool-review reviewers.

Both the pentest runner and the guided-analysis runner build an agent provider
(and, in automatic review mode, a reviewer LLM) the same way. These helpers keep
that construction in one place so the two runners stay consistent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from llm import ProviderFactory
from llm.provider.base import BaseProvider

from .config import Settings
from .providers import validate_reasoning_effort
from .schemas import ReviewerConfig

if TYPE_CHECKING:  # only for typing; the runtime import is deferred (see below)
    from .pentest.approver import ReviewerClient


def build_provider(
    provider: str,
    model: Optional[str],
    reasoning_effort: Optional[str],
    cfg: Settings,
) -> BaseProvider:
    """Create an LLM provider (raises ValueError on a missing key / bad effort)."""
    api_key = cfg.api_key_for(provider)
    validate_reasoning_effort(provider, reasoning_effort)
    return ProviderFactory.create(
        provider,
        api_key=api_key,
        model=model,
        reasoning_effort=reasoning_effort,
        timeout=cfg.llm_timeout,
    )


def build_reviewer(reviewer: ReviewerConfig, cfg: Settings) -> "ReviewerClient":
    """Create the one-shot tool-call reviewer used in automatic review mode."""
    # Deferred import: app.pentest.__init__ imports its runner, which imports this
    # module, so importing app.pentest.approver at module load would cycle.
    from .pentest.approver import ReviewerClient

    provider = build_provider(reviewer.provider, reviewer.model, reviewer.reasoning_effort, cfg)
    getattr(provider, "client", None)  # warm the lazily-built SDK client
    return ReviewerClient(provider, max_iterations=reviewer.max_iterations)
