"""Parsing bounds (§9 G2, §16.3). Every parser takes a Limits and never exceeds it."""

from __future__ import annotations

from dataclasses import dataclass

GiB = 1 << 30
MiB = 1 << 20


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 1 * GiB
    max_entries: int = 200_000
    max_entry_uncompressed: int = 4 * GiB
    max_total_uncompressed: int = 8 * GiB
    max_ratio: int = 1000
    # Structure-level bounds for the native parsers.
    max_manifest_bytes: int = 16 * MiB
    max_resources_bytes: int = 256 * MiB
    max_v1_signature_files: int = 64
    max_v1_signature_bytes: int = 4 * MiB
    max_sigblock_bytes: int = 64 * MiB
    max_sigblock_pairs: int = 4096
    max_signers_per_block: int = 64
    max_certs_per_signer: int = 64
    max_lineage_nodes: int = 64
    max_bundle_members: int = 4096
    max_member_bytes: int = 1 * GiB
    max_network_json_bytes: int = 64 * MiB
    max_assetlinks_bytes: int = 1 * MiB
    max_fdroid_index_bytes: int = 512 * MiB
    max_dex_bytes: int = 512 * MiB


DEFAULT_LIMITS = Limits()
