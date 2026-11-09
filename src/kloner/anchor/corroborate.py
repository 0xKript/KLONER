"""Corroboration levels (§7.3)."""

from __future__ import annotations

from kloner.models import Anchor

CORROBORATED = "CORROBORATED"
SINGLE_OFFICIAL = "SINGLE_OFFICIAL"
USER_ASSERTED = "USER_ASSERTED"


def support(anchor: Anchor, cert: str) -> set[str]:
    """Non-USER provenance classes supporting ``cert`` directly or through the anchor lineage.

    The anchor lineage is only ever recorded from apksig-verified proof-of-rotation, so every
    certificate in it belongs to the same signing history (R1/R2).
    """
    lineage = {e.cert_sha256 for e in anchor.lineage}
    group = {cert} | (lineage if cert in lineage else set())
    classes: set[str] = set()
    for ident in anchor.identities:
        if ident.cert_sha256 in group and not ident.declared_additional:
            classes.update(ev.klass for ev in ident.evidence if ev.klass != "USER")
    return classes


def current_identities(anchor: Anchor) -> list[str]:
    if anchor.lineage:
        return [anchor.lineage[-1].cert_sha256]
    return [i.cert_sha256 for i in anchor.identities if not i.declared_additional and i.role == "current"] or [
        i.cert_sha256 for i in anchor.identities if not i.declared_additional
    ]


def level(anchor: Anchor) -> str:
    current = current_identities(anchor)
    if not current:
        return USER_ASSERTED
    n = min(len(support(anchor, c)) for c in current)
    if n >= 2:
        return CORROBORATED
    if n == 1:
        return SINGLE_OFFICIAL
    return USER_ASSERTED
