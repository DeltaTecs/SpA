from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisType:
    label: str
    description: str


ANALYSIS_TYPES: tuple[AnalysisType, ...] = (
    AnalysisType(
        label="Recon: Domain",
        description="Perform a security analysis and discovery of all domains mentioned in the event.",
    ),
    AnalysisType(
        label="Recon: Ports",
        description="Perform extensive port scans on the machines mentioned in the event.",
    ),
    AnalysisType(
        label="Recon: HTTP Path/API",
        description="Perform discovery on any HTTP API or path found in the event.",
    ),
    AnalysisType(
        label="Authentication",
        description="Evaluate authentication, session, authorization, and access-control behavior in the event.",
    ),
    AnalysisType(
        label="Configuration",
        description=(
            "Evaluate endpoint/cloud configuration of all remote endpoints in the event. "
            "Look for HTTP configuration, exposed storage/database, exposed secrets, etc."
        ),
    ),
)

DEFAULT_ANALYSIS_TYPE = ANALYSIS_TYPES[0].label
ANALYSIS_TYPE_DESCRIPTIONS = {item.label: item.description for item in ANALYSIS_TYPES}
ALLOWED_ANALYSIS_TYPES = frozenset(ANALYSIS_TYPE_DESCRIPTIONS)
