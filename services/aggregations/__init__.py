"""Aggregation services building larger response payloads: ``build_*(session) -> dict``.

Nothing here imports FastAPI.
"""

from .analysis_detail import build_analysis_detail
from .audits_pipeline import build_audits_pipeline
from .company_overview import CompanyNotFound, build_company_overview
from .contract_audit_timeline import build_contract_audit_timeline
from .fleet import build_fleet_status

__all__ = [
    "CompanyNotFound",
    "build_analysis_detail",
    "build_audits_pipeline",
    "build_company_overview",
    "build_contract_audit_timeline",
    "build_fleet_status",
]
