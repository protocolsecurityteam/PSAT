"""Independent execution reproductions of the proxy dispatch review findings."""

from dataclasses import replace
from pathlib import Path

import pytest

from services.logic.expansion import expand_formula
from services.logic.formula import compile_function
from services.logic.solver import Translation
from services.logic.terms import CALLER, TRUE, mk, replace_terms, subterms
from tests.logic import _anvil as A
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

FIXTURES = Path(__file__).parent / "fixtures"


def compiled(d, impl, proxy, proxy_name, root=None, contract="Impl"):
    known = d.contracts(*d.at)
    known[proxy] = d.slither["Good" if proxy_name == "BadCopy" else "Impl"]
    fn = O.function(d, contract, "act")
    root = root or proxy
    formula = compile_function(
        d.slither[contract],
        fn,
        root,
        d.chain(),
        known,
        code_of=lambda a: impl if a == proxy else a,
        own_code={proxy: d.slither[proxy_name]}.get,
    )
    return fn, formula, known


@pytest.mark.parametrize("proxy_name", ["Clash", "BadCopy"])
def test_rejected_dispatch_never_uses_the_wrong_body(anvil, tmp_path, proxy_name):
    d = A.Deployment(anvil[0], tmp_path, (FIXTURES / "proxy_dispatch_rejections.sol").read_text())
    name = "Good" if proxy_name == "BadCopy" else "Impl"
    impl = d.deploy(name)
    proxy = d.deploy(
        proxy_name, ("address",) if proxy_name == "BadCopy" else (), (impl,) if proxy_name == "BadCopy" else ()
    )
    _, f, known = compiled(d, impl, proxy, proxy_name, contract=name)
    result = expand_formula(f, d.chain(), known).callers
    actual = O.transact(d, proxy, "act()")
    assert actual is (proxy_name == "Clash")
    if proxy_name == "Clash":
        assert result.complete and result.representation == "cofinite"
    else:
        assert result.complete and result.representation == "finite" and not result.members


def test_nested_proxy_view_does_not_receive_outer_value(anvil, tmp_path):
    d = A.Deployment(anvil[0], tmp_path, (FIXTURES / "proxy_dispatch_frames.sol").read_text())
    impl = d.deploy("Impl")
    proxy = d.deploy("P", ("address",), (impl,))
    root = d.deploy("C", ("address",), (proxy,))
    fn, f, known = compiled(d, impl, proxy, "P", root, "C")
    resources = subterms(f.success, "unknown")
    assert resources and {t[1] for t in resources} == {"unsupported:raw_call_resources"}
    for amount in (0, 1, 2):
        tr = Translation(
            d.chain(),
            known,
            root,
            f.selector,
            bindings={CALLER: O.OWNER, mk("callvalue"): amount, **{t: True for t in resources}},
        )
        assert tr.truth(f.success) is O.passes(d, root, fn, sender=O.OWNER, value=amount) is (amount == 1)
    production = expand_formula(f, d.chain(), known).callers
    O.assumes_gas(production)
    successful = replace(f, success=replace_terms(f.success, {t: TRUE for t in resources}))
    assert expand_formula(successful, d.chain(), known).callers.members == production.members


def test_discarded_delegate_is_an_effect_even_without_a_success_check(anvil, tmp_path):
    d = A.Deployment(anvil[0], tmp_path, (FIXTURES / "proxy_dispatch_frames.sol").read_text())
    impl = d.deploy("Impl")
    other = d.deploy("Extra")
    proxy = d.deploy("PExtra", ("address", "address"), (impl, other))
    _, f, known = compiled(d, impl, proxy, "PExtra")
    O.assumes_gas(expand_formula(f, d.chain(), known).callers)
    assert any(e.kind == "write" for e in f.effects)
    resources = subterms(f.success, "unknown")
    assert resources and all(t[1] == "unsupported:raw_call_resources" for t in resources)
    assert O.transact(d, proxy, "act()")
    assert int(rpc(d.url, "eth_getStorageAt", [O.hex20(proxy), "0x1", "latest"]), 16) == 2


def test_partial_copy_invalidates_the_whole_calldata_forward(anvil, tmp_path):
    from services.logic.lower import parameter

    d = A.Deployment(anvil[0], tmp_path, (FIXTURES / "proxy_partial_copy.sol").read_text())
    impl = d.deploy("Impl")
    proxy = d.deploy("P", ("address",), (impl,))
    fn, f, known = compiled(d, impl, proxy, "P")
    for args in ((7, 0), (0, 7)):
        bound = {
            CALLER: O.OWNER,
            mk("callvalue"): 0,
            **{parameter(p, i): v for i, (p, v) in enumerate(zip(fn.parameters, args))},
        }
        predicted = Translation(d.chain(), known, proxy, f.selector, bindings=bound).truth(f.success)
        actual = O.passes(d, proxy, fn, args)
        assert actual is (args[0] == 7)
        assert predicted is None or predicted is actual
    assert not expand_formula(f, d.chain(), known).callers.complete


def test_bounded_delegate_gas_is_not_assumed_sufficient(anvil, tmp_path):
    source = (FIXTURES / "proxy_partial_copy.sol").read_text()
    source = source.replace("calldatacopy(36,4,32)", "").replace("delegatecall(gas(),", "delegatecall(0,")
    d = A.Deployment(anvil[0], tmp_path, source)
    impl = d.deploy("Impl")
    proxy = d.deploy("P", ("address",), (impl,))
    fn, f, known = compiled(d, impl, proxy, "P")
    assert not O.passes(d, proxy, fn, (0, 7))
    result = expand_formula(f, d.chain(), known).callers
    assert not result.complete and result.issues
