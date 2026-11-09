"""Property tests (§18.3): P-03 and P-04 on the pure decision functions."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from kloner.decide import SignerBlock, closure, decide
from kloner.models import Verdict
from kloner.selftest import corpus as c

CERTS = [f"{i:02x}" * 32 for i in range(8)]
cert = st.sampled_from(CERTS)


def reference_closure(trusted: set[str], blocks: list[SignerBlock]) -> set[str]:
    """Independent fixpoint of R1/R2 (a different formulation than decide.closure)."""
    out = set(trusted)
    while True:
        new = set(out)
        for b in blocks:
            if b.signer in new:
                new |= set(b.lineage)
            for i in range(1, len(b.lineage)):
                if b.node_valid[i] and b.lineage[i - 1] in new:
                    new.add(b.lineage[i])
        if new == out:
            return out
        out = new


block = st.builds(
    lambda lineage, valid, signer: SignerBlock(signer, tuple(lineage), (False, *valid[: max(0, len(lineage) - 1)])),
    st.lists(cert, min_size=0, max_size=5, unique=True),
    st.lists(st.booleans(), min_size=5, max_size=5),
    cert,
)


@settings(max_examples=500, deadline=None)
@given(st.sets(cert, max_size=3), st.lists(block, max_size=4))
def test_p04_closure_admits_only_r1_r2_reachable(trusted: set[str], blocks: list[SignerBlock]) -> None:
    got = closure(trusted, blocks)
    assert set(got) == reference_closure(trusted, blocks)
    assert {k for k, v in got.items() if v == "T"} == trusted
    # Nothing outside every block's lineage can ever be admitted.
    universe = set(trusted) | {x for b in blocks for x in b.lineage}
    assert set(got) <= universe


@pytest.mark.toolchain
@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.sets(cert, min_size=1, max_size=3), st.booleans())
def test_p03_no_genuine_with_a_foreign_signer(corpus: dict[str, Any], rt: Any, trusted: set[str], swap: bool) -> None:
    facts01 = corpus["facts01"]
    V = corpus["keys"]["vendor"]
    signer = CERTS[0] if swap else V.sha256
    facts = c.replace_cert(facts01, V.sha256, signer) if swap else facts01
    anchor = c.anchor_for([corpus["keys"]["vendor"]])
    anchor.identities = [
        i.model_copy(update={"cert_sha256": t}) for t in sorted(trusted) for i in anchor.identities[:1]
    ]
    ev = decide(facts, {c.FIXTURE_PACKAGE: anchor}, rt.known_keys)
    tstar = set(closure(anchor.trusted(), []))
    if signer not in tstar:
        assert ev.verdict != Verdict.GENUINE
    assert decide(facts, {c.FIXTURE_PACKAGE: anchor}, rt.known_keys) == ev
