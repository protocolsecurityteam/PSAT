"""Dump REAL prod predicate_trees + state_var_values for the cofinite e2e fixtures.

Source of truth = the prod analysis artifacts (the real static pipeline's output from
real verified on-chain source). Read-only. Writes tests/fixtures/cofinite/*.json.
Run manually with prod env; the test consumes only the committed JSON (no network).
"""

import json
import os
import sys

sys.path.insert(0, "/home/riley/PSAT")
from db.models import SessionLocal
from db.queue import get_artifact
from services.resolution.capability_resolver import _load_state_var_values

# (name, address, job_id, [function signatures to keep] or None for all)
TARGETS = [
    (
        "boring_vault",
        "0xca8711daf13d852ed2121e4be3894dae366039e4",
        "69af56b4-f5c1-4f5a-824f-0d994880e8ce",
        ["transfer(address,uint256)", "transferFrom(address,address,uint256)"],
    ),
    (
        "teller",
        "0x63ede83cbb1c8d90ba52e9497e6c1226a673e884",
        "442a91d7-ed0f-4b68-a924-305c5001ca0f",
        ["beforeTransfer(address,address,address)"],  # the only tree BoringVault.transfer inlines
    ),
    (
        "weeth",
        "0x2d10683e941275d502173053927ad6066e6afd6b",
        "53f9aaa8-8c37-43b8-8c01-6323a24886ff",
        [
            "recoverERC20(address,address,uint256)",
            "recoverERC721(address,address,uint256)",
            "recoverETH(address,uint256)",
        ],
    ),
    (
        "roles_authority",
        "0x02904af5c3be78481528e0f01780439f024109a6",
        "31a232c8-e935-417f-bbf0-5ea970785d6c",
        ["setUserRole(address,uint8,bool)"],
    ),
    (
        "accountant",
        "0x04b8136820598a4e50bee21b8b6a23fe25df9bd8",
        "ec2bd476-0796-4f5a-93f4-749eae9cb4b8",
        ["updateExchangeRate(uint96)", "setRateProviderData(ERC20,bool,address)"],
    ),
    (
        "node_operator_manager",
        "0xfcc674fc9a0602692d2a91905e7e978ae6ee2caf",
        None,
        ["registerNodeOperator(bytes,uint64)"],
    ),
]
# Each ``keep`` is exactly the signatures the e2e test asserts on (the trees resolve
# independently and inlining pulls from the *callee's* artifact, so siblings are dead
# weight). Trimming was verified to change 0 resolver output for the kept functions.

OUT = "/home/riley/PSAT/tests/fixtures/cofinite"
os.makedirs(OUT, exist_ok=True)


def find_job(s, addr):
    from sqlalchemy import text

    r = s.execute(
        text("""
        select j.id::text from contracts c join jobs j on j.id=c.job_id
        join artifacts a on a.job_id=j.id and a.name='predicate_trees'
        where lower(c.address)=:a and j.status='completed' order by j.id desc limit 1
    """),
        {"a": addr.lower()},
    ).fetchone()
    return r[0] if r else None


with SessionLocal() as s:
    for name, addr, job_id, keep in TARGETS:
        if job_id is None:
            job_id = find_job(s, addr)
        art = get_artifact(s, job_id, "predicate_trees")
        if not isinstance(art, dict) or "trees" not in art:
            print(f"!! {name} {addr}: no predicate_trees ({job_id})")
            continue
        trees = art["trees"]
        if keep:
            trees = {k: v for k, v in trees.items() if k in keep}
            missing = [k for k in keep if k not in art["trees"]]
            if missing:
                print(f"!! {name}: missing tree keys {missing}; available sample: {list(art['trees'])[:8]}")
        svs = _load_state_var_values(s, addr, job_id=job_id)
        payload = {
            "name": name,
            "address": addr.lower(),
            "job_id": job_id,
            "contract": art.get("contract", addr.lower()),
            "schema_version": art.get("schema_version"),
            "trees": trees,
            "canonical_signatures": art.get("canonical_signatures"),
            "state_var_values": svs,
        }
        path = f"{OUT}/{name}.json"
        with open(path, "w") as fh:
            json.dump(payload, fh, indent=1, sort_keys=True)
        print(f"OK {name}: {len(trees)} trees, {len(svs)} state vars -> {path}")
        # show the function sigs we kept for canary contracts (to pick assertions)
        if keep is None and name in ("weeth", "roles_authority", "accountant", "node_operator_manager", "teller"):
            sigs = [
                k
                for k in trees
                if any(
                    t in k.lower()
                    for t in (
                        "recover",
                        "setuserrole",
                        "beforetransfer",
                        "registernodeoperator",
                        "pause",
                        "setrate",
                        "updateexchange",
                    )
                )
            ]
            print(f"    candidate sigs: {sigs[:12]}")
print("DONE")
