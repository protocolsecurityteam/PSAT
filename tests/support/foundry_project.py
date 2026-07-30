"""Shared helper: scaffold a minimal Foundry project the static pipeline can
compile. Used by the claims integration/matcher tests that drive
``collect_contract_analysis_with_artifacts`` over a single hand-written source."""

from __future__ import annotations

import json
from pathlib import Path


def write_foundry_project(tmp_path: Path, contract_name: str, source_code: str) -> Path:
    """Write ``src/<contract_name>.sol`` plus the ``contract_meta.json`` sidecar
    the pipeline expects, pinned to solc 0.8.19 with no build output."""
    project_dir = tmp_path / contract_name
    (project_dir / "src").mkdir(parents=True)
    (project_dir / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\nsolc_version = "0.8.19"\n'
    )
    (project_dir / "src" / f"{contract_name}.sol").write_text(source_code)
    (project_dir / "contract_meta.json").write_text(
        json.dumps(
            {
                "address": "0x1111111111111111111111111111111111111111",
                "contract_name": contract_name,
                "compiler_version": "v0.8.19+commit.7dd6d404",
            }
        )
        + "\n"
    )
    return project_dir
