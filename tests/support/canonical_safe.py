from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import requests
from eth_abi.abi import decode, encode
from eth_account import Account
from eth_utils.crypto import keccak

from schemas.contract_analysis import ContractAnalysis
from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
from tests.support.label_corpus import _solc_select_binary

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "safe_v1_4_1"
ZERO = "0x" + "00" * 20
EXEC = "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"
TX_TYPES = ["address", "uint256", "bytes", "uint8", "uint256", "uint256", "uint256", "address", "address"]
MNEMONIC = "test test test test test test test test test test test junk"


def calldata(signature, values=()):
    types = signature.split("(", 1)[1][:-1].split(",") if not signature.endswith("()") else []
    return "0x" + (keccak(text=signature)[:4] + encode(types, list(values))).hex()


def rpc(url, method, params):
    response = requests.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=15)
    response.raise_for_status()
    body = response.json()
    if "error" in body:
        raise RuntimeError(body["error"])
    return body["result"]


def send(url, sender, data, to=None, *, value=0):
    tx = {"from": sender, "data": data, "gas": hex(8_000_000)}
    if value:
        tx["value"] = hex(value)
    if to is not None:
        tx["to"] = to
    tx_hash = rpc(url, "eth_sendTransaction", [tx])
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        receipt = rpc(url, "eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            return receipt
        time.sleep(0.02)
    raise AssertionError("Anvil did not mine the transaction")


def call(url, address, signature, values=(), returns=(), sender=None, block="latest"):
    tx = {"to": address, "data": calldata(signature, values)}
    if sender is not None:
        tx["from"] = sender
    result = rpc(url, "eth_call", [tx, block])
    return decode(list(returns), bytes.fromhex(result[2:])) if returns else result


@dataclass
class SafeDeployment:
    url: str
    address: str
    target: str
    owners: list[str]
    relayer: str
    project: Path
    analysis: ContractAnalysis
    trees: dict
    effects: dict
    broken: bool

    def args(self, value=42):
        return [self.target, 0, bytes.fromhex(calldata("setValue(uint256)", [value])[2:]), 0, 0, 0, 0, ZERO, ZERO]

    def signatures(self, args, indices=(0, 1, 2)):
        nonce = call(self.url, self.address, "nonce()", returns=["uint256"])[0]
        digest = call(
            self.url,
            self.address,
            "getTransactionHash(" + ",".join(TX_TYPES + ["uint256"]) + ")",
            args + [nonce],
            ["bytes32"],
        )[0]
        Account.enable_unaudited_hdwallet_features()
        keys = [Account.from_mnemonic(MNEMONIC, account_path=f"m/44'/60'/0'/0/{i}") for i in indices]
        keys.sort(key=lambda key: int(key.address, 16))
        return b"".join(bytes(Account.unsafe_sign_hash(digest, private_key=key.key).signature) for key in keys)

    def value(self):
        return call(self.url, self.target, "value()", returns=["uint256"])[0]

    def configure(self, signature, values):
        args = self.args()
        args[0] = self.address
        args[2] = bytes.fromhex(calldata(signature, values)[2:])
        signatures = self.signatures(args)
        receipt = send(self.url, self.relayer, calldata(EXEC, args + [signatures]), self.address)
        assert int(receipt["status"], 16) == 1


def deploy_safe(
    root: Path, url: str, *, broken: bool, version: str = "1.4.1", l2: bool = False, compiler: str = "0.8.25"
) -> SafeDeployment:
    fixture = FIXTURE.parent / ("safe_v" + version.replace(".", "_"))
    name = "GnosisSafe" if version == "1.3.0" else "Safe"
    proxy_name = name + "Proxy"
    manifest = json.loads((fixture / "manifest.json").read_text())
    for relative, digest in manifest["sha256"].items():
        assert hashlib.sha256((fixture / relative).read_bytes()).hexdigest() == digest, relative
    project = root / ("broken" if broken else "canonical")
    shutil.copytree(fixture / "contracts", project / "src")
    if not l2:
        (project / "src" / (name + "L2.sol")).unlink(missing_ok=True)
    shutil.copy(FIXTURE / "ControlledTarget.sol", project / "src")
    if broken:
        source = project / "src" / (name + ".sol")
        text = source.read_text()
        gate = "checkSignatures(txHash, txHashData, signatures);"
        assert text.count(gate) == 1
        source.write_text(text.replace(gate, "/* authentication removed by regression mutation */"))
    solc = _solc_select_binary(compiler)
    assert solc.is_file(), f"Install solc {compiler}; CI provisions it and this regression must not skip"
    (project / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nsolc = "' + str(solc) + '"\noffline = true\noptimizer = true\n'
    )
    subprocess.run(["forge", "build"], cwd=project, check=True, capture_output=True, text=True, timeout=60)
    accounts = rpc(url, "eth_accounts", [])

    def deploy(file, name, types=(), values=()):
        artifact = json.loads((project / "out" / file / f"{name}.json").read_text())
        bytecode = artifact["bytecode"]["object"].removeprefix("0x")
        receipt = send(url, accounts[9], "0x" + bytecode + encode(list(types), list(values)).hex())
        assert int(receipt["status"], 16) == 1
        return receipt["contractAddress"].lower()

    contract_name = name + ("L2" if l2 else "")
    singleton = deploy(contract_name + ".sol", contract_name)
    address = deploy(proxy_name + ".sol", proxy_name, ["address"], [singleton])
    setup = calldata(
        "setup(address[],uint256,address,bytes,address,address,uint256,address)",
        [accounts[:8], 3, ZERO, b"", ZERO, ZERO, 0, ZERO],
    )
    assert int(send(url, accounts[9], setup, address)["status"], 16) == 1
    target = deploy("ControlledTarget.sol", "ControlledTarget", ["address"], [address])
    (project / "contract_meta.json").write_text(
        json.dumps(
            {
                "address": address,
                "contract_name": contract_name,
                "compiler_version": "v" + compiler,
                "source_verified": True,
            }
        )
    )
    analysis, trees, effects = collect_contract_analysis_with_artifacts(project)
    assert trees is not None and effects is not None
    return SafeDeployment(
        url, address, target, accounts[:8], accounts[9], project, analysis, trees, dict(effects), broken
    )
