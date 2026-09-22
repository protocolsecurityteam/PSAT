"""Proof expansion retains the publication's eligibility boundary."""

from schemas.temporal_assessment import ClaimKind, EvidenceKind
from services.assessment.impact import _proof


def _claim(identifier, prerequisites=(), evidence=()):
    return {
        "id": identifier,
        "kind": ClaimKind.configuration,
        "scope": {"kind": "point", "at": {"block_number": "100"}},
        "proposition": {"value": identifier},
        "claims": list(prerequisites),
        "evidence": list(evidence),
    }


def test_proof_expands_transitive_evidence_and_payload():
    claims = {
        "root": _claim("root", ["middle"]),
        "middle": _claim("middle", ["leaf"]),
        "leaf": _claim("leaf", evidence=["reading"]),
    }
    evidence = {
        "reading": {
            "kind": EvidenceKind.chain_read,
            "source": {"method": "getMinDelay"},
            "block_number": "100",
            "block_hash": "0xabc",
            "transaction_hash": None,
            "log_index": None,
            "payload": "payload:one",
        }
    }
    proof = _proof(
        claims["root"], claims, evidence, {"payload:one": {"id": "payload:one", "data": {"value": "172800"}}}
    )
    assert proof["complete"] is True
    leaf = proof["prerequisites"][0]["prerequisites"][0]
    assert leaf["evidence"][0]["payload"]["data"] == {"value": "172800"}


def test_proof_marks_missing_and_cyclic_prerequisites_incomplete():
    root = _claim("root", ["missing", "cycle"])
    cycle = _claim("cycle", ["root"])
    proof = _proof(root, {"root": root, "cycle": cycle}, {}, {})
    assert proof["complete"] is False
    assert proof["prerequisites"][0]["unavailable"] == "not eligible in publication"
    assert proof["prerequisites"][1]["prerequisites"][0]["unavailable"] == "cycle"


def test_proof_response_budget_marks_payload_unavailable():
    root = _claim("root", evidence=["reading"])
    evidence = {
        "reading": {
            "kind": EvidenceKind.chain_read,
            "source": {},
            "block_number": "1",
            "block_hash": "0xabc",
            "transaction_hash": None,
            "log_index": None,
            "payload": "payload:one",
        }
    }
    proof = _proof(
        root,
        {"root": root},
        evidence,
        {
            "payload:one": {"id": "payload:one", "byte_length": 20, "data": {"value": "172800"}},
        },
        [0],
    )
    assert proof["complete"] is False
    assert proof["evidence"][0]["payload"]["unavailable"] == "response payload limit reached"


def test_unsupported_leaf_does_not_look_complete():
    leaf = _claim("leaf")
    proof = _proof(leaf, {"leaf": leaf}, {}, {})
    assert proof["complete"] is False
    assert "no linked evidence" in proof["issues"][0]
