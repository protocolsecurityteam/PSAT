"""Typed schemas for frontend-friendly principal labeling."""

from __future__ import annotations

from typing import Literal, TypedDict

from typing_extensions import NotRequired

from .control_tracking import ResolvedControllerType

LabelConfidence = Literal["high", "medium", "low"]


class PrincipalPermission(TypedDict):
    function: str
    effect_labels: list[str]
    role: int | None
    authority_public: bool
    controller: NotRequired[str]


class PrincipalProfile(TypedDict):
    address: str
    resolved_type: ResolvedControllerType
    display_name: str
    labels: list[str]
    confidence: LabelConfidence
    details: dict[str, object]
    graph_context: list[str]
    controller_context: list[str]
    permissions: list[PrincipalPermission]


class PrincipalLabels(TypedDict):
    schema_version: str
    contract_address: str
    contract_name: str
    principals: list[PrincipalProfile]
