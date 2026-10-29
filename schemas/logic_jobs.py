"""Bounded requests for the explicit logic jobs; providers and credentials are server-owned."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StringConstraints, field_validator

Address = Annotated[str, StringConstraints(pattern=r"^0x[a-fA-F0-9]{40}$")]
Signature = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class LogicRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GenerateRequest(LogicRequest):
    address: Address
    chain_id: StrictInt = Field(gt=0)
    block: StrictInt | None = Field(default=None, ge=0)
    related_addresses: list[Address] = Field(default_factory=list, max_length=32)
    context_chars: StrictInt = Field(default=48_000, ge=1, le=64_000)

    @field_validator("address")
    @classmethod
    def normalize(cls, value: str) -> str:
        if int(value, 16) == 0:
            raise ValueError("zero is not a deployment address")
        return value.lower()

    @field_validator("related_addresses")
    @classmethod
    def normalize_related(cls, values: list[str]) -> list[str]:
        return sorted({cls.normalize(value) for value in values})


class AssessRequest(LogicRequest):
    formula_job_id: UUID
    max_requests: StrictInt = Field(default=8, ge=0, le=256)
    cache_only: StrictBool = False
    direct_reads: StrictInt = Field(default=64, ge=0, le=4096)
    solver_ms: StrictInt = Field(default=250, ge=0, le=5000)
    solver_queries: StrictInt = Field(default=256, ge=0, le=4096)


class EnumerateRequest(LogicRequest):
    assessment_job_id: UUID
    functions: list[Signature] = Field(min_length=1, max_length=256)
    members: StrictInt = Field(default=256, ge=0, le=4096)
    solver_ms: StrictInt = Field(default=1000, ge=0, le=10_000)

    @field_validator("functions")
    @classmethod
    def unique_functions(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values):
            raise ValueError("duplicate function selection")
        return values
