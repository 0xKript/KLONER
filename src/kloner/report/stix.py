"""STIX 2.1 bundle (§15.5): file hashes, foreign signer fingerprints, network leads (low confidence)."""

from __future__ import annotations

import json
from typing import Any

import stix2

from kloner.report.ioc import indicators

IDENTITY = stix2.Identity(
    id="identity--5f0e6d1c-6a43-5b9a-9a8e-6b1f9e6e0a01",
    name="KLONER",
    identity_class="system",
    created="2026-01-01T00:00:00.000Z",
    modified="2026-01-01T00:00:00.000Z",
)
PATTERN = {
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "cert-sha256": "[x509-certificate:hashes.'SHA-256' = '{v}']",
    "url": "[url:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "ipv4": "[ipv4-addr:value = '{v}']",
}
CONFIDENCE = {"high": 85, "medium": 60, "low": 15}


def bundle(doc: dict[str, Any]) -> str:
    objs: list[Any] = [IDENTITY]
    when = doc["run"]["finished_utc"] or doc["run"]["started_utc"]
    for i in indicators(doc):
        pat = PATTERN.get(i["type"])
        if pat is None:
            continue
        value = i["value"].replace("\\", "\\\\").replace("'", "\\'")
        objs.append(
            stix2.Indicator(
                name=f"{i['type']} {i['value'][:80]}",
                description=i["context"],
                pattern=pat.format(v=value),
                pattern_type="stix",
                valid_from=when,
                created_by_ref=IDENTITY.id,
                confidence=CONFIDENCE[i["confidence"]],
                labels=["kloner", "lead" if i["confidence"] == "low" else "indicator"],
                allow_custom=False,
            )
        )
    b = stix2.Bundle(objects=objs, allow_custom=False)
    return json.dumps(json.loads(b.serialize()), indent=2, sort_keys=True) + "\n"
