"""Typed schemas for frontend-friendly principal labeling."""

from __future__ import annotations

from typing import Literal

from typing_extensions import NotRequired, TypedDict

from .core import ArtifactEnvelope, Principal

LabelConfidence = Literal["high", "medium", "low"]


class PrincipalPermission(TypedDict):
    function: str
    effect_labels: list[str]
    role: int | None
    authority_public: bool
    controller: NotRequired[str]


class PrincipalProfile(Principal):
    """A core principal plus the labeling enrichment the policy stage adds.
    ``display_name`` is REQUIRED here: a labeled principal always has a name
    to show, which is why it stays off the bare core identity."""

    display_name: str
    labels: list[str]
    confidence: LabelConfidence
    graph_context: list[str]
    controller_context: list[str]
    permissions: list[PrincipalPermission]


class PrincipalLabels(ArtifactEnvelope):
    principals: list[PrincipalProfile]
