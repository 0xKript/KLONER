"""Heuristic lookalike signals of the impersonation sweep (§11): evidence only, never verdicts (INV-4)."""

from __future__ import annotations

from kloner.impersonation.sweep import edit_distance, lookalikes, queries, skeleton
from kloner.models import Anchor, Brand, BrandFacts, Evaluation, EvaluationFacts

OFFICIAL = "com.example.bank"


def _anchor() -> Anchor:
    return Anchor.model_construct(
        package=OFFICIAL,
        brand=Brand(
            labels=["Example Bank"],
            brand_labels=["ExampleBank"],
            keywords=["example bank"],
            icon_dhash=["ff00ff00ff00ff00"],
        ),
    )


def _signals(package: str, labels: list[str], dhashes: list[str] | None = None) -> set[str]:
    ev = Evaluation.model_construct(package=package)
    facts = EvaluationFacts.model_construct(brand=BrandFacts(labels=labels, icon_dhashes=dhashes or []))
    return {x["signal"] for x in lookalikes(ev, facts, _anchor(), label_max_edit=2, dhash_max=10)}


def test_uts39_skeleton_and_edit_distance() -> None:
    # Cyrillic IE, HA and A (U+0415, U+0445, U+0430) in place of Latin E, x, a
    spoof = chr(0x415) + chr(0x445) + chr(0x430) + "mple Bank"
    assert skeleton(spoof) == skeleton("Example Bank") and spoof != "Example Bank"
    assert skeleton("Example Bank") != skeleton("Sample Bank")
    assert edit_distance("examplebank", "exampel bank") == 2
    assert edit_distance("a", "a" * 20) == 9  # capped


def test_each_lookalike_signal() -> None:
    assert "LABEL_EDIT" in _signals("org.other.app", ["Exampel Bank"])
    spoof = chr(0x415) + chr(0x445) + chr(0x430) + "mple B" + chr(0x430) + "nk"
    assert "CONFUSABLE" in _signals("org.other.app", [spoof])
    assert "ICON_DHASH" in _signals("org.other.app", [], ["ff00ff00ff00ff01"])
    assert "PACKAGE_TYPOSQUAT" in _signals("com.examp1e.bank", [])
    assert "PACKAGE_AFFIX" in _signals("com.example.bank.update", [])
    assert _signals("org.unrelated.tool", ["Calculator"], ["0123456789abcdef"]) == set()
    assert _signals(OFFICIAL, ["Exampel Bank"]) == set()  # the official package is never a lookalike


def test_sweep_queries_come_from_the_brand_profile() -> None:
    assert queries(_anchor()) == ["Example Bank", "ExampleBank", "example bank"]
