"""Factory capability manifest: deployment-bound evidence and its read (#4485).

Implements ADR 0199 decision 3 and ADR 0204 decision 2.3 for the API: a
closed-world, deployment-bound record of what a deployed runner image and
bundle can do, with an authenticated read for later admission and validation.

The record is descriptive evidence, never a grant:

* registry hosts are probe inputs the bundle declares, not egress grants;
* connector and service declarations are recorded so admission can compare
  them against what a run may reach -- a missing declaration is absent;
* no credential value ever appears in a stored or returned manifest;
* the ``.github/`` publication restriction is recorded exactly as the
  platform refuses it (``curie_worker.publication_validation``).

Storage is an immutable, write-once row per (agent, runner image digest,
bundle digest) pair: the manifest bytes, their SHA-256 digest and the schema
version. A row whose bytes do not hash to its recorded digest is stale, and
a missing, malformed, mismatched or stale binding reads as ``environment
unknown`` -- never a ready verdict, and never a claim of a capability the
image did not probe.

The effective admission view composes this immutable deployment record with
the repository's ``.curie/verification.json`` resolved from the ticket's exact
immutable base commit (decision 4): bundle checks when the bundle declares
any, else the repository declaration from that commit, else none. An
unreadable repository file is ``unknown``, not a silent no-check success.

The admission gate that CONSUMES this evidence is #4450; this module exposes
no gate and refuses nothing about a ticket.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AgentVersion, CapabilityRecord, Deployment

CAPABILITY_SCHEMA_VERSION = 1
PUBLICATION_RESTRICTION_GITHUB = ".github/"
_EGRESS_CLASSES = frozenset({"sandbox", "docker", "unknown"})

# What a read answers when the binding cannot yield evidence. ``missing`` is
# a deployment recorded before capability recording existed (or with no
# record for its exact image and bundle); ``malformed``, ``mismatched`` and
# ``stale`` are the same refusal for a record whose bytes cannot be trusted.
# None is the ready case: exact recorded bytes with a matching digest.
ENV_UNKNOWN_MISSING = "environment_unknown_missing"
ENV_UNKNOWN_MALFORMED = "environment_unknown_malformed"
ENV_UNKNOWN_MISMATCHED = "environment_unknown_mismatched"
ENV_UNKNOWN_STALE = "environment_unknown_stale"

MAX_MANIFEST_BYTES = 64 * 1024


def _is_sha256(value: str) -> bool:
    """A `sha256:` followed by exactly 64 lowercase hex characters."""

    return (
        value.startswith("sha256:")
        and len(value) == 71
        and all(c in "0123456789abcdef" for c in value[7:])
    )


def canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    """The deterministic bytes of a manifest document.

    Sorted keys, compact separators, one trailing newline: the same manifest
    always hashes to the same digest, so the recorded digest is comparable
    across reads.
    """

    return (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()


def manifest_digest(manifest: dict[str, Any]) -> str:
    """The ``sha256:`` digest of a manifest's canonical bytes."""

    return f"sha256:{hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()}"


def validate_manifest(manifest: dict[str, Any]) -> str:
    """Validate a manifest document, returning its canonical digest.

    Raises ``ValueError`` for a manifest that is not the closed-world shape:
    wrong schema version, a missing or malformed digest binding, an unknown
    egress class, or a missing publication restriction. The refusal names the
    offending field.
    """

    if not isinstance(manifest, dict):
        raise ValueError("capability manifest must be a JSON object")
    if manifest.get("schema_version") != CAPABILITY_SCHEMA_VERSION:
        raise ValueError(f"capability manifest schema_version must be {CAPABILITY_SCHEMA_VERSION}")
    if not manifest.get("publication_restriction"):
        raise ValueError("capability manifest must record its publication restriction")
    if manifest.get("publication_restriction") != PUBLICATION_RESTRICTION_GITHUB:
        raise ValueError(
            "capability manifest publication restriction must be the platform's exact "
            f"{PUBLICATION_RESTRICTION_GITHUB} refusal"
        )
    egress = manifest.get("egress_class")
    if egress not in _EGRESS_CLASSES:
        raise ValueError("capability manifest egress_class must be sandbox, docker or unknown")
    image_digest = manifest.get("image_digest")
    if not isinstance(image_digest, str) or not _is_sha256(image_digest):
        raise ValueError("capability manifest image_digest must be a sha256 digest")
    bundle_digest = manifest.get("bundle", {}).get("bundle_digest")
    if not isinstance(bundle_digest, str) or not _is_sha256(bundle_digest):
        raise ValueError("capability manifest bundle bundle_digest must be a sha256 digest")
    return manifest_digest(manifest)


@dataclass(frozen=True)
class RecordedManifest:
    """A verified deployment-bound manifest: the exact recorded bytes."""

    manifest: dict[str, Any]
    digest: str
    image_digest: str
    bundle_digest: str


async def record_manifest(
    session: AsyncSession,
    *,
    agent_version: AgentVersion,
    manifest: dict[str, Any],
) -> CapabilityRecord:
    """Record one deployment-bound manifest, write-once per binding pair.

    The row binds the manifest bytes and their digest to the version's bundle
    digest and the manifest's recorded runner image digest, with the agent and
    deployment identity. A binding that already has a record is returned
    unchanged (the record is immutable evidence); a different manifest for the
    same pair is refused, because deployment evidence never mutates.
    """

    digest = validate_manifest(manifest)
    image_digest = manifest["image_digest"]
    bundle_digest = manifest["bundle"]["bundle_digest"]
    if agent_version.bundle_sha256 is not None and agent_version.bundle_sha256 != bundle_digest:
        raise ValueError(
            "capability manifest bundle digest does not match the version's stored bundle"
        )
    existing = await find_record(
        session,
        agent_id=agent_version.agent_id,
        image_digest=image_digest,
        bundle_digest=bundle_digest,
    )
    if existing is not None:
        if existing.digest != digest:
            raise ValueError(
                "a capability record already exists for this image and bundle; deployment "
                "evidence is immutable"
            )
        return existing
    record = CapabilityRecord(
        agent_id=agent_version.agent_id,
        version_id=agent_version.id,
        schema_version=CAPABILITY_SCHEMA_VERSION,
        image_digest=image_digest,
        bundle_digest=bundle_digest,
        digest=digest,
        manifest_bytes=canonical_manifest_bytes(manifest).decode(),
    )
    session.add(record)
    await session.commit()
    return record


async def find_record(
    session: AsyncSession,
    *,
    agent_id: Any,
    image_digest: str,
    bundle_digest: str,
) -> CapabilityRecord | None:
    """The one record bound to this exact image and bundle pair, or None."""

    record = await session.scalar(
        select(CapabilityRecord).where(
            CapabilityRecord.agent_id == agent_id,
            CapabilityRecord.image_digest == image_digest,
            CapabilityRecord.bundle_digest == bundle_digest,
        )
    )
    return record if isinstance(record, CapabilityRecord) else None


@dataclass(frozen=True)
class ManifestRead:
    """The authenticated read's answer.

    ``manifest`` is the exact recorded document and ``digest`` its digest when
    the binding is verified; ``reason`` names the environment-unknown
    disposition otherwise. A read never invents a capability: the answer is
    the recorded bytes or a refusal, nothing else.
    """

    manifest: dict[str, Any] | None
    digest: str | None
    reason: str | None

    @property
    def ready(self) -> bool:
        return self.manifest is not None


async def read_manifest(
    session: AsyncSession,
    *,
    deployment: Deployment,
) -> ManifestRead:
    """The authenticated read of one deployment's capability evidence.

    Resolves the deployment's active version and its bundle, then the record
    bound to the manifest's recorded image and bundle. A deployment without a
    stored bundle, without a record, or with a record whose bytes do not hash
    to its recorded digest answers environment unknown, never a ready
    verdict and never an inferred manifest.
    """

    version = await session.get(AgentVersion, deployment.version_id)
    if version is None or version.bundle_sha256 is None:
        return ManifestRead(None, None, ENV_UNKNOWN_MISSING)
    record = await _record_for_bundle(session, deployment.agent_id, version.bundle_sha256)
    if record is None:
        return ManifestRead(None, None, ENV_UNKNOWN_MISSING)
    try:
        manifest = json.loads(record.manifest_bytes)
    except (ValueError, TypeError):
        return ManifestRead(None, None, ENV_UNKNOWN_MALFORMED)
    try:
        digest = validate_manifest(manifest)
    except ValueError:
        return ManifestRead(None, None, ENV_UNKNOWN_MALFORMED)
    if digest != record.digest:
        return ManifestRead(None, None, ENV_UNKNOWN_STALE)
    if (
        manifest.get("image_digest") != record.image_digest
        or manifest.get("bundle", {}).get("bundle_digest") != version.bundle_sha256
    ):
        # The row's binding and the manifest's own binding disagree: the
        # record is not evidence for this deployment's exact pair.
        return ManifestRead(None, None, ENV_UNKNOWN_MISMATCHED)
    return ManifestRead(manifest, digest, None)


async def _record_for_bundle(
    session: AsyncSession,
    agent_id: Any,
    bundle_digest: str,
    image_digest: str | None = None,
) -> CapabilityRecord | None:
    """The record bound to this bundle and image pair, when exactly one exists.

    A bundle with more than one recorded manifest (two runner images built for
    the same bundle) is ambiguous evidence without the image digest: unknown,
    not ready. With the image digest, the record for exactly that pair is the
    binding's evidence.
    """

    clause = CapabilityRecord.bundle_digest == bundle_digest
    if image_digest is not None:
        clause = clause & (CapabilityRecord.image_digest == image_digest)
    rows = (
        await session.scalars(
            select(CapabilityRecord).where(
                CapabilityRecord.agent_id == agent_id,
                clause,
            )
        )
    ).all()
    if len(rows) != 1:
        return None
    return rows[0]


@dataclass(frozen=True)
class AdmissionView:
    """The effective admission view: deployment evidence plus the base commit.

    ``verification_source`` is ``bundle`` when the bundle declares its own
    checks, ``repository`` when the base-commit repository declaration
    resolves, or ``none`` when neither declares any. ``base_commit`` and
    ``repository_declaration`` record exactly what the evidence was resolved
    from, so a later repository edit cannot change this ticket's evidence.
    """

    manifest: dict[str, Any] | None
    manifest_digest: str | None
    reason: str | None
    verification_source: str
    base_commit: str | None
    repository_declaration: dict[str, Any] | None

    @property
    def ready(self) -> bool:
        return self.manifest is not None and self.verification_source != "unknown"


def compose_admission_view(
    read: ManifestRead,
    *,
    base_commit: str | None,
    repository_declaration: dict[str, Any] | None,
    repository_unreadable: bool = False,
) -> AdmissionView:
    """Combine the deployment record with the base-commit declaration.

    Verification precedence (decision 4): bundle checks when the deployed
    bundle declares any, else the repository's ``.curie/verification.json``
    resolved from the ticket's exact immutable base commit, else no declared
    checks. An unreadable repository file is unknown, never a silent
    no-check success. A repository file read from any commit other than
    ``base_commit`` is never evidence for this ticket.
    """

    if not read.ready:
        return AdmissionView(
            read.manifest,
            read.digest,
            read.reason,
            "unknown",
            base_commit,
            None,
        )
    manifest = read.manifest or {}
    bundle_checks = (manifest.get("bundle") or {}).get("bundle_checks") or []
    if bundle_checks:
        # Bundle checks are bound with the deployed bundle; the repository
        # file is not evidence for this ticket.
        return AdmissionView(manifest, read.digest, None, "bundle", base_commit, None)
    if repository_unreadable:
        return AdmissionView(
            manifest,
            read.digest,
            None,
            "unknown",
            base_commit,
            None,
        )
    if repository_declaration is not None:
        return AdmissionView(
            manifest,
            read.digest,
            None,
            "repository",
            base_commit,
            repository_declaration,
        )
    return AdmissionView(manifest, read.digest, None, "none", base_commit, None)


def read_repository_declaration(content: str | None) -> tuple[dict[str, Any] | None, bool]:
    """Parse a base commit's ``.curie/verification.json``.

    Returns ``(declaration, unreadable)``: a parsed object, or ``(None,
    True)`` for unreadable or malformed content, which is unknown rather than
    a silent no-check success. ``None`` content (absent at the commit) is
    ``(None, False)``: no declared checks.
    """

    if content is None:
        return None, False
    try:
        parsed = json.loads(content)
    except (ValueError, TypeError):
        return None, True
    if not isinstance(parsed, dict):
        return None, True
    return parsed, False
