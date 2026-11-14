"""The closed-world deployment capability manifest (#4485).

Decision 2's manifest records the exact capabilities one built runner image
and one deployed bundle had, bound to both digests. Nothing here grants
egress, permission or credential: registry hosts are the probe inputs the
image's own tool layers pull from, connectors and services are descriptive
names, and no credential value appears anywhere in the record.

Decision 4 preserves the verification precedence: bundle checks when the
bundle declares any, else the repository ``.curie/verification.json`` resolved
from the ticket's exact immutable base commit, else no declared checks. The
effective admission view combines the immutable deployment record with that
base-commit repository declaration.

Missing, malformed, mismatched or stale digest bindings yield ``environment
unknown``, never a ready verdict.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Deployment

SCHEMA_VERSION = 1
"""The manifest's schema version (#4485 decision 2)."""

PUBLICATION_RESTRICTION_GITHUB = "GitHub workflow changes cannot be published by this capability"
PUBLICATION_RESTRICTION_GITHUB_METADATA = (
    "GitHub metadata changes cannot be published by this capability"
)
PUBLICATION_RESTRICTIONS = (
    PUBLICATION_RESTRICTION_GITHUB,
    PUBLICATION_RESTRICTION_GITHUB_METADATA,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CHECK_ID = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_DELEGATED_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f`]")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ManifestToolProbe(_Strict):
    """One executable the manifest records: name, observed version, probe argv."""

    name: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=180)
    # A JSON list, not a tuple: the manifest crosses the wire as JSON, and
    # strict mode refuses a list for a tuple field. The field shape follows
    # the wire shape so a recorded manifest always revalidates.
    probe_command: list[str] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def _printable(self) -> ManifestToolProbe:
        if self.name != self.name.strip() or not self.name.strip():
            raise ValueError("name must be printable without surrounding spaces")
        if not self.probe_command[0].strip():
            raise ValueError("probe_command must start with a non-blank executable")
        return self


class DeclaredConnector(_Strict):
    """A connector the deployed bundle declares reachable, by name only."""

    name: str = Field(min_length=1, max_length=64)


class DeclaredService(_Strict):
    """A service the deployed bundle declares reachable, by name only."""

    name: str = Field(min_length=1, max_length=64)


class VerificationCheck(_Strict):
    """One verification check the bundle owns: id, route, optional delegation."""

    id: str = Field(pattern=_CHECK_ID.pattern)
    route: Literal["sandbox", "delegated"]
    delegated_to: str | None = Field(default=None, min_length=1, max_length=64)

    @model_validator(mode="after")
    def _route_consistent(self) -> VerificationCheck:
        if self.route == "delegated" and self.delegated_to is None:
            raise ValueError("a delegated route requires the required PR check it delegates to")
        if self.route == "sandbox" and self.delegated_to is not None:
            raise ValueError("a sandbox route delegates to nothing")
        if self.delegated_to is not None:
            forbidden = _DELEGATED_FORBIDDEN.search(self.delegated_to)
            if self.delegated_to != self.delegated_to.strip() or forbidden:
                raise ValueError(
                    "delegated_to must be printable characters without backticks or spaces"
                )
        return self


class CapabilityManifest(_Strict):
    """The closed-world deployment manifest (#4485 decision 2)."""

    schema_version: int
    image_digest: str = Field(pattern=_SHA256_DIGEST.pattern)
    bundle_digest: str = Field(pattern=_SHA256_DIGEST.pattern)
    # Every container is a JSON list for the same reason as the probe
    # command: the manifest is JSON on the wire and in the column, and a
    # strict model must accept exactly the shapes JSON carries.
    tools: list[ManifestToolProbe] = Field(max_length=64)
    registry_hosts: list[str] = Field(max_length=32)
    connectors: list[DeclaredConnector] = Field(max_length=32)
    services: list[DeclaredService] = Field(max_length=32)
    verification_checks: list[VerificationCheck] = Field(max_length=16)
    egress_class: str = Field(min_length=1, max_length=64)
    publication_restrictions: list[str] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def _closed_world(self) -> CapabilityManifest:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
        if list(self.publication_restrictions) != list(PUBLICATION_RESTRICTIONS):
            raise ValueError(
                "publication_restrictions must be the platform's exact `.github/` refusals"
            )
        host_names = [host for host in self.registry_hosts]
        if len(set(host_names)) != len(host_names):
            raise ValueError("registry_hosts must be unique")
        return self


def canonical_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    """The manifest's canonical bytes: compact JSON, sorted keys, one newline.

    The same in this API as in the CLI's ``repo_runner`` builder, so the
    recorded digest is reproducible from either side.
    """

    return json.dumps(dict(manifest), sort_keys=True, separators=(",", ":")).encode() + b"\n"


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """The SHA-256 hex of the manifest's canonical bytes."""

    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


def validate_manifest(raw: Any) -> CapabilityManifest:
    """Parse and validate a manifest from raw JSON-decoded data.

    Raises ``ValueError`` so a caller can fail closed on malformed stored
    evidence instead of treating it as a ready manifest.
    """

    try:
        return CapabilityManifest.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 - one refusal reason, no echo
        raise ValueError("the stored capability manifest is unreadable") from exc


def manifest_json(manifest: CapabilityManifest) -> dict[str, Any]:
    """The manifest as canonical JSON-decoded data, ready for the column."""

    data = json.loads(canonical_manifest_bytes(manifest.model_dump(mode="json")))
    assert isinstance(data, dict)
    return data


# ---------------------------------------------------------------------------
# Recording and the authenticated read (decision 5)
# ---------------------------------------------------------------------------


async def record_capability_manifest(
    session: AsyncSession,
    deployment: Deployment,
    manifest: Mapping[str, Any],
) -> str:
    """Record the manifest's canonical JSON and digest on the deployment row.

    Refuses a malformed manifest, so a half-validated record can never land.
    Returns the recorded digest. The caller commits.
    """

    validated = validate_manifest(manifest)
    data = manifest_json(validated)
    digest = manifest_digest(data)
    deployment.capability_manifest = data
    deployment.capability_manifest_digest = digest
    return digest


class ManifestEvidence:
    """What an authenticated read answers for one deployment (#4485).

    ``state`` is ``ready`` only when a recorded manifest exists, parses, and
    its stored digest matches its canonical bytes. Missing, malformed,
    mismatched or stale evidence is ``environment_unknown`` -- the verdict is
    named for what the READER cannot establish, never a ready verdict, and the
    reader never claims a capability the record does not name.
    """

    __slots__ = ("state", "manifest", "digest", "reason")

    def __init__(
        self,
        state: Literal["ready", "environment_unknown"],
        *,
        manifest: CapabilityManifest | None = None,
        digest: str | None = None,
        reason: str | None = None,
    ) -> None:
        self.state = state
        self.manifest = manifest
        self.digest = digest
        self.reason = reason

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ManifestEvidence({self.state!r}, reason={self.reason!r})"


def _unknown(reason: str) -> ManifestEvidence:
    return ManifestEvidence("environment_unknown", reason=reason)


def read_recorded_manifest(deployment: Deployment) -> ManifestEvidence:
    """The recorded manifest for a deployment, as evidence (#4485 decision 5).

    An authenticated read returns the exact recorded bytes when the record is
    sound. Anything else is ``environment unknown``:

    - neither column set (a deployment created before capability recording,
      decision 6): missing evidence;
    - one column without the other: a half-set record is stale binding state;
    - a digest that is not 64 lowercase hex: malformed;
    - JSON that does not parse, or parses but does not validate against the
      manifest shape: malformed;
    - a digest that does not match the canonical bytes: mismatched or stale.
    """

    raw = deployment.capability_manifest
    digest = deployment.capability_manifest_digest
    if raw is None and digest is None:
        return _unknown("no capability manifest is recorded for this deployment")
    if raw is None or digest is None:
        return _unknown("the recorded capability manifest binding is incomplete")
    if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        return _unknown("the recorded capability manifest digest is malformed")
    if not isinstance(raw, (dict, list)):
        return _unknown("the recorded capability manifest is malformed")
    try:
        canonical = canonical_manifest_bytes(raw)
    except (TypeError, ValueError):
        return _unknown("the recorded capability manifest is malformed")
    if hashlib.sha256(canonical).hexdigest() != digest:
        return _unknown("the recorded capability manifest digest does not match its bytes")
    try:
        manifest = validate_manifest(raw)
    except ValueError:
        return _unknown("the recorded capability manifest is unreadable")
    return ManifestEvidence("ready", manifest=manifest, digest=digest)


# ---------------------------------------------------------------------------
# The effective admission view (decision 4)
# ---------------------------------------------------------------------------


class ResolvedVerificationDeclaration(BaseModel):
    """The verification declaration an admission resolves (#4485 decision 4).

    ``source`` is ``bundle`` when the recorded manifest's bundle declared
    checks, ``repository`` when the repository's ``.curie/verification.json``
    was read from the ticket's immutable base commit, or ``none`` when neither
    declared any. ``base_commit`` is set exactly when the source is the
    repository file: it is the commit the declaration was read at, never a
    moving branch tip. ``unreadable`` is set when the repository file exists
    but does not parse: unknown, not a silent no-check success.
    """

    model_config = ConfigDict(strict=True)

    source: Literal["bundle", "repository", "none"]
    checks: list[VerificationCheck] = Field(default_factory=list)
    base_commit: str | None = None
    unreadable: str | None = None


def effective_verification(
    evidence: ManifestEvidence, base_declaration: ResolvedVerificationDeclaration
) -> ResolvedVerificationDeclaration:
    """The verification precedence (#4485 decision 4): bundle, then repository, then none.

    Bundle checks are bound with the deployed bundle: the recorded manifest's
    own checks win when it declares any. When it declares none, the
    repository declaration resolved from the ticket's exact immutable base
    commit stands, with its commit recorded on the view. An unreadable
    repository file is unknown, never a silent no-check success.
    """

    if evidence.state == "ready" and evidence.manifest is not None:
        if evidence.manifest.verification_checks:
            return ResolvedVerificationDeclaration(
                source="bundle",
                checks=list(evidence.manifest.verification_checks),
            )
    return base_declaration


def resolve_base_verification(
    repository_declaration: Mapping[str, Any] | None,
    *,
    base_commit: str,
    unreadable: str | None = None,
) -> ResolvedVerificationDeclaration:
    """Resolve the repository's ``.curie/verification.json`` from the base commit.

    ``repository_declaration`` is the file's parsed content as read from the
    ticket's exact immutable base commit -- never a later branch tip or
    checkout. ``None`` means the file is absent at that commit, which resolves
    as no declared checks. ``unreadable`` names a file that exists but does not
    parse: the view is unknown, not a silent success.
    """

    if unreadable is not None:
        return ResolvedVerificationDeclaration(
            source="none", base_commit=base_commit, unreadable=unreadable
        )
    if repository_declaration is None:
        return ResolvedVerificationDeclaration(source="none", base_commit=base_commit)
    raw_checks = repository_declaration.get("checks", ()) if isinstance(
        repository_declaration, Mapping
    ) else None
    if not isinstance(raw_checks, Sequence) or isinstance(raw_checks, (str, bytes)):
        raise ValueError(".curie/verification.json must be an object with exactly checks")
    checks: list[VerificationCheck] = []
    for raw in raw_checks:
        check_id = raw.get("id") if isinstance(raw, Mapping) else None
        command = raw.get("command") if isinstance(raw, Mapping) else None
        # A command is a list of argv words: a bare string is malformed, not
        # a one-word command (str is a Sequence, so it is excluded by name).
        if not isinstance(check_id, str) or not isinstance(command, Sequence) or isinstance(
            command, (str, bytes)
        ):
            raise ValueError("each repository check needs an id and a command list")
        delegated = raw.get("delegated_to") if isinstance(raw, Mapping) else None
        checks.append(
            VerificationCheck(
                id=check_id,
                route="delegated" if delegated is not None else "sandbox",
                delegated_to=delegated if delegated else None,
            )
        )
    return ResolvedVerificationDeclaration(
        source="repository" if checks else "none",
        checks=checks,
        base_commit=base_commit,
    )
