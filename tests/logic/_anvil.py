"""Contracts compiled with solc, deployed on a throwaway anvil, and read through the engine's ``Chain``."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from eth_abi.abi import encode

from services.logic.decide import Chain
from tests.fuzz.authority import solc_path
from tests.support.anvil import ACCOUNT0, _start_anvil, _terminate, rpc, send

SOLC = "0.8.27"


class Deployment:
    """One anvil and the contracts deployed on it: Slither's view of each (by name) and its address."""

    def __init__(self, url: str, root: Path, source: str):
        from slither import Slither

        self.url = url
        path = root / "C.sol"
        path.write_text(source)
        solc = str(solc_path(SOLC))
        out = subprocess.run(
            [solc, "--combined-json", "abi,bin", str(path)], capture_output=True, text=True, check=True
        ).stdout
        self.compiled = {name.split(":")[-1]: c for name, c in json.loads(out)["contracts"].items()}
        self.slither = {c.name: c for c in Slither(str(path), solc=solc).contracts}
        self.at: dict[str, int] = {}

    def deploy(self, name: str, types: tuple = (), values: tuple = ()) -> int:
        values = tuple("0x" + format(v, "040x") if t == "address" else v for t, v in zip(types, values))
        data = "0x" + self.compiled[name]["bin"] + encode(list(types), list(values)).hex()
        receipt = send(self.url, ACCOUNT0, data)
        assert receipt["status"] == "0x1", name
        self.at[name] = int(receipt["contractAddress"], 16)
        return self.at[name]

    def send(self, name: str, data: str, sender: str = ACCOUNT0) -> None:
        receipt = send(self.url, sender, data, to="0x" + format(self.at[name], "040x"))
        assert receipt["status"] == "0x1"

    def chain(self) -> Chain:
        block = int(rpc(self.url, "eth_blockNumber", []), 16)

        def batch(calls: list) -> list:
            out = []
            for method, params in calls:
                try:
                    out.append(rpc(self.url, method, params))
                except RuntimeError:
                    out.append(None)
            return out

        return Chain(lambda method, params: rpc(self.url, method, params), block, batch)

    def contracts(self, *names: str) -> dict[int, Any]:
        return {self.at[n]: self.slither[n] for n in names}


@pytest.fixture(scope="module")
def anvil(tmp_path_factory):
    if solc_path(SOLC) is None or shutil.which("anvil") is None:
        pytest.skip("solc or anvil not installed")
    proc, port = _start_anvil()
    try:
        yield f"http://127.0.0.1:{port}", tmp_path_factory.mktemp("anvil")
    finally:
        _terminate(proc)
