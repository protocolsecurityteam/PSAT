from tests.support.live_helpers import company_analysis_job_ids, finite_alternative_members


def test_cold_company_uses_contract_descendants_and_deduplicates_inventory():
    descendants = [
        {"job_id": "discovery", "address": None},
        {"job_id": "contract", "address": "0xabc", "request": {"chain": "ethereum"}},
    ]
    contracts = [{"job_id": "contract", "address": "0xabc", "impl_job_id": "implementation"}]
    assert company_analysis_job_ids(descendants, contracts) == ["contract", "implementation"]


def test_warm_company_finds_reused_analyses_without_new_contract_descendants():
    descendants = [{"job_id": "discovery", "address": None, "status": "completed"}]
    contracts = [{"job_id": "reused", "address": "0xabc", "chain": "ethereum"}]
    assert company_analysis_job_ids(descendants, contracts) == ["reused"]


def test_company_candidates_exclude_other_chains_and_missing_analysis_references():
    descendants = [{"job_id": "base-child", "address": "0xabc", "request": {"chain": "base"}}]
    contracts = [
        {"job_id": "base-job", "address": "0xabc", "chain": "base", "impl_job_id": "base-impl"},
        {"address": "0xdef", "chain": "ethereum", "job_id": None},
        {"job_id": "discovery", "address": None},
    ]
    assert company_analysis_job_ids(descendants, contracts) == []


def test_nested_finite_alternatives_preserve_members_without_minting_external_callers():
    cap = {
        "kind": "OR",
        "children": [
            {"kind": "finite_set", "members": ["0xABC"]},
            {
                "kind": "OR",
                "children": [
                    {"kind": "finite_set", "members": ["0xabc", "0xdef"]},
                    {"kind": "external_check_only", "check": {"target_address": "0x999"}},
                ],
            },
        ],
    }
    assert finite_alternative_members(cap) == {"0xabc", "0xdef"}


def test_intersection_is_not_mistaken_for_an_alternative_union():
    assert finite_alternative_members({"kind": "AND", "children": []}) is None


def test_quorum_alternative_requires_group_principal_assertions():
    assert finite_alternative_members({"kind": "OR", "children": [{"kind": "threshold_group"}]}) is None
