"""Factory capability manifest API regressions (issue #4485).

End-to-end through the API seam: the deployment-bound manifest read, the
environment-unknown refusals for missing, malformed, mismatched and stale
bindings, the base-commit `.curie/verification.json` composition, the
descriptive-only treatment of registry hosts/connectors, the `.github/`
restriction exactness, legacy missing evidence, and the upgrade report.

The CLI-side composition lives in `cli/src/factory_capability.rs`; these
tests exercise the storage, read and composition contracts at the API seam.
"""

import asyncio
import json
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from curie_api.config import get_settings
from curie_api.factory_capability_manifest import (
    CAPABILITY_SCHEMA_VERSION,
    ENV_UNKNOWN_MALFORMED,
    ENV_UNKNOWN_MISMATCHED,
    ENV_UNKNOWN_MISSING,
    ENV_UNKNOWN_STALE,
    ManifestRead,
    compose_admission_view,
    manifest_digest,
    read_repository_declaration,
    validate_manifest,
)
from curie_worker.publication_validation import GITHUB_WORKFLOW_REFUSAL
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


IMAGE_DIGEST = "sha256:" + "1" * 64
BUNDLE_DIGEST = "sha256:" + "2" * 64
OTHER_IMAGE_DIGEST = "sha256:" + "4" * 64


def _manifest(
    *,
    image_digest: str = IMAGE_DIGEST,
    bundle_digest: str = BUNDLE_DIGEST,
    egress_class: str = "sandbox",
) -> dict[str, Any]:
    """A closed-world manifest document as the CLI composes it."""

    return {
        "schema_version": CAPABILITY_SCHEMA_VERSION,
        "image": f"ghcr.io/acme-corp/curie-repo-runner:t-1@{image_digest}",
        "image_digest": image_digest,
        "bundle": {
            "bundle_digest": bundle_digest,
            "bundle_checks": [],
            "connectors": [],
            "registry_hosts": ["index.crates.io", "static.crates.io"],
        },
        "executables": [
            {
                "name": "uv",
                "version": "0.10.7",
                "path": "/usr/local/bin/uv",
                "probe_command": ["uv", "--version"],
                "source": "catalog",
            },
            {
                "name": "cargo fmt",
                "version": "rustfmt 1.7.1",
                "path": "/usr/local/bin/cargo-fmt",
                "probe_command": ["cargo fmt", "--version"],
                "source": "catalog",
            },
            {
                "name": "cargo clippy",
                "version": "clippy 0.1.95",
                "path": "/usr/local/bin/cargo-clippy",
                "probe_command": ["cargo clippy", "--version"],
                "source": "catalog",
            },
        ],
        "egress_class": egress_class,
        # The exact `.github/` refusal the platform enforces.
        "publication_restriction": ".github/",
    }


def _with_session(body: Callable[[AsyncSession], Awaitable[Any]]) -> None:
    async def go() -> None:
        engine = create_async_engine(get_settings().database_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                await body(session)
        finally:
            await engine.dispose()

    asyncio.run(go())


def _agent_version_deployment(client: Any, headers: dict[str, str]) -> tuple[str, str, str]:
    agent = client.post(
        "/agents",
        json={"name": "capability-agent", "channel": {"kind": "slack", "address": "C0CAP0001"}},
        headers=headers,
    ).json()
    version = client.post(
        f"/agents/{agent['id']}/versions",
        json={"version_label": f"v-{uuid.uuid4().hex[:6]}", "created_by": "operator"},
        headers=headers,
    ).json()
    deployment = client.post(
        "/deployments",
        json={"agent_id": agent["id"], "version_id": version["id"], "environment": "dev"},
        headers=headers,
    ).json()
    return agent["id"], version["id"], deployment["id"]


def _record(
    agent_id: str,
    version_id: str,
    manifest: dict[str, Any],
    *,
    digest: str | None = None,
) -> None:
    """Insert a CapabilityRecord bound to the manifest's own digests."""

    async def body(session: AsyncSession) -> None:
        from curie_api.models import CapabilityRecord

        session.add(
            CapabilityRecord(
                agent_id=agent_id,
                version_id=version_id,
                schema_version=CAPABILITY_SCHEMA_VERSION,
                image_digest=manifest["image_digest"],
                bundle_digest=manifest["bundle"]["bundle_digest"],
                digest=digest or manifest_digest(manifest),
                manifest_bytes=json.dumps(manifest, sort_keys=True, separators=(",", ":")),
            )
        )
        await session.commit()

    _with_session(body)


def _update_records(columns: str, params: dict[str, Any]) -> None:
    async def body(session: AsyncSession) -> None:
        await session.execute(text(f"UPDATE curie.capability_records SET {columns}"), params)
        await session.commit()

    _with_session(body)


def _read(
    client: Any, headers: dict[str, str], deployment_id: str, base_commit: str | None = None
) -> Any:
    url = f"/v1/factory/capability/deployments/{deployment_id}"
    if base_commit:
        url += f"?base_commit={base_commit}"
    return client.get(url, headers=headers)


def _bind_bundle(
    client: Any, headers: dict[str, str], bundle_digest: str | None
) -> tuple[str, str, str]:
    agent_id, version_id, deployment_id = _agent_version_deployment(client, headers)
    if bundle_digest is not None:

        async def body(session: AsyncSession) -> None:
            await session.execute(
                text("UPDATE curie.agent_versions SET bundle_sha256 = :d WHERE id = :v"),
                {"d": bundle_digest[7:], "v": version_id},
            )
            await session.commit()

        _with_session(body)
    return agent_id, version_id, deployment_id


# --- AC2: exact bytes recorded and read ----------------------------------


def test_recorded_manifest_reads_back_as_exact_bytes(
    client: Any, auth_headers: dict[str, str], clean_db: None
) -> None:
    manifest = _manifest()
    agent_id, version_id, deployment_id = _bind_bundle(client, auth_headers, BUNDLE_DIGEST)
    _record(agent_id, version_id, manifest)

    resp = _read(client, auth_headers, deployment_id, base_commit="0123456789abcdef")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # The exact recorded bytes: the manifest reads back unchanged, with the
    # recorded digest, and the read reports the base commit the repository
    # declaration was resolved from.
    assert body["manifest"] == manifest
    assert body["manifest_digest"] == manifest_digest(manifest)
    assert body["ready"] is True
    assert body["reason"] is None
    assert body["base_commit"] == "0123456789abcdef"
    assert body["action"] == ""


# --- AC2: missing, malformed, stale, mismatched → environment unknown -----


def test_a_deployment_without_a_record_is_missing_evidence(
    client: Any, auth_headers: dict[str, str], clean_db: None
) -> None:
    _, _, deployment_id = _bind_bundle(client, auth_headers, BUNDLE_DIGEST)
    resp = _read(client, auth_headers, deployment_id)
    body = resp.json()
    assert body["ready"] is False
    assert body["manifest"] is None
    assert body["reason"] == ENV_UNKNOWN_MISSING
    assert body["action"] == "build/render/redeploy"


def test_malformed_bytes_read_as_environment_unknown(
    client: Any, auth_headers: dict[str, str], clean_db: None
) -> None:
    manifest = _manifest()
    agent_id, version_id, deployment_id = _bind_bundle(client, auth_headers, BUNDLE_DIGEST)
    _record(agent_id, version_id, manifest)
    _update_records("manifest_bytes = '{not json'", {})

    resp = _read(client, auth_headers, deployment_id)
    body = resp.json()
    assert body["ready"] is False and body["reason"] == ENV_UNKNOWN_MALFORMED


def test_stale_binding_reads_as_environment_unknown(
    client: Any, auth_headers: dict[str, str], clean_db: None
) -> None:
    manifest = _manifest()
    agent_id, version_id, deployment_id = _bind_bundle(client, auth_headers, BUNDLE_DIGEST)
    # Record the manifest with a digest that is not its own: the bytes do not
    # hash to what the row claims, so the binding is stale.
    _record(agent_id, version_id, manifest, digest="sha256:" + "0" * 64)

    resp = _read(client, auth_headers, deployment_id)
    body = resp.json()
    assert body["ready"] is False and body["reason"] == ENV_UNKNOWN_STALE


def test_mismatched_binding_reads_as_environment_unknown(
    client: Any, auth_headers: dict[str, str], clean_db: None
) -> None:
    manifest = _manifest()
    agent_id, version_id, deployment_id = _bind_bundle(client, auth_headers, BUNDLE_DIGEST)
    # The manifest's own image binding disagrees with the row's: the record
    # is not evidence for the deployment's exact image and bundle pair.
    mismatched = _manifest(image_digest=OTHER_IMAGE_DIGEST)
    _record(agent_id, version_id, manifest)
    _update_records("image_digest = :d", {"d": OTHER_IMAGE_DIGEST})
    _ = mismatched  # the mismatch is created by the row update above

    resp = _read(client, auth_headers, deployment_id)
    body = resp.json()
    assert body["ready"] is False and body["reason"] == ENV_UNKNOWN_MISMATCHED


# --- AC3: declarations are descriptive, never grants --------------------


def test_registry_hosts_and_connectors_are_descriptive_only(
    client: Any, auth_headers: dict[str, str], clean_db: None
) -> None:
    manifest = _manifest()
    agent_id, version_id, deployment_id = _bind_bundle(client, auth_headers, BUNDLE_DIGEST)
    manifest["bundle"]["registry_hosts"] = ["index.crates.io", "static.crates.io"]
    manifest["bundle"]["connectors"] = []
    _record(agent_id, version_id, manifest)

    body = _read(client, auth_headers, deployment_id).json()
    assert body["ready"] is True
    # The host list is recorded unchanged: it does not appear as egress.
    assert body["manifest"]["bundle"]["registry_hosts"] == [
        "index.crates.io",
        "static.crates.io",
    ]
    # A missing connector/service is absent, not defaulted in.
    assert body["manifest"]["bundle"]["connectors"] == []
    # No credential value appears anywhere in the recorded bytes.
    blob = json.dumps(body["manifest"])
    for banned in ("token", "credential", "secret", "api-key", "apikey"):
        assert banned not in blob.lower()
    # The `.github/` restriction is exactly the platform's refusal vocabulary.
    assert body["manifest"]["publication_restriction"] == ".github/"
    assert "GitHub workflow changes" in GITHUB_WORKFLOW_REFUSAL


def test_manifest_refuses_undeclared_egress_classes() -> None:
    bad = _manifest(egress_class="unrestricted")
    with pytest.raises(ValueError):
        validate_manifest(bad)


# --- AC2: base-commit verification precedence ----------------------------


def test_bundle_checks_take_precedence_over_the_repository_declaration() -> None:
    manifest = _manifest()
    manifest["bundle"]["bundle_checks"] = [{"id": "api", "route": "executable"}]
    read = ManifestRead(manifest, manifest_digest(manifest), None)
    view = compose_admission_view(
        read,
        base_commit="abc123",
        repository_declaration={"checks": [{"id": "repo_check"}]},
    )
    assert view.verification_source == "bundle"
    assert view.repository_declaration is None


def test_no_bundle_checks_resolves_the_repository_declaration_from_the_base_commit() -> None:
    manifest = _manifest()
    read = ManifestRead(manifest, manifest_digest(manifest), None)
    repo_declaration = {"checks": [{"id": "api_checks", "route": "delegated"}]}
    view = compose_admission_view(
        read,
        base_commit="0123456789abcdef",
        repository_declaration=repo_declaration,
    )
    assert view.verification_source == "repository"
    assert view.base_commit == "0123456789abcdef"
    assert view.repository_declaration == repo_declaration


def test_an_unreadable_repository_file_is_unknown_not_a_silent_success() -> None:
    manifest = _manifest()
    read = ManifestRead(manifest, manifest_digest(manifest), None)
    view = compose_admission_view(
        read, base_commit="abc123", repository_declaration=None, repository_unreadable=True
    )
    assert view.verification_source == "unknown"
    assert view.ready is False


def test_an_absent_repository_file_is_no_declared_checks() -> None:
    manifest = _manifest()
    read = ManifestRead(manifest, manifest_digest(manifest), None)
    view = compose_admission_view(read, base_commit="abc123", repository_declaration=None)
    assert view.verification_source == "none"


def test_the_repository_declaration_parses_from_the_base_commit_bytes() -> None:
    declaration, unreadable = read_repository_declaration('{"checks": [{"id": "api_checks"}]}')
    assert unreadable is False
    assert declaration == {"checks": [{"id": "api_checks"}]}
    malformed, unreadable = read_repository_declaration("{not json")
    assert malformed is None and unreadable is True
    absent, unreadable = read_repository_declaration(None)
    assert absent is None and unreadable is False


# --- AC4: legacy deployments and new versions -----------------------------


def test_a_legacy_deployment_reads_missing_evidence_with_the_operator_action(
    client: Any, auth_headers: dict[str, str], clean_db: None
) -> None:
    # A deployment created before capability recording: no record exists.
    _, _, deployment_id = _bind_bundle(client, auth_headers, BUNDLE_DIGEST)
    body = _read(client, auth_headers, deployment_id).json()
    assert body["ready"] is False
    assert body["reason"] == ENV_UNKNOWN_MISSING
    assert body["action"] == "build/render/redeploy"


def test_a_new_version_record_does_not_mutate_the_old_deployment(
    client: Any, auth_headers: dict[str, str], clean_db: None
) -> None:
    old_agent, old_version, old_deployment = _bind_bundle(client, auth_headers, BUNDLE_DIGEST)
    new_agent, new_version, new_deployment = _bind_bundle(client, auth_headers, BUNDLE_DIGEST)
    # Record a manifest for the NEW version only.
    _record(new_agent, new_version, _manifest())
    # The old deployment still reads as missing evidence: recording for the
    # new version did not mutate the old deployment or infer a manifest for it.
    body = _read(client, auth_headers, old_deployment).json()
    assert body["ready"] is False
    assert body["reason"] == ENV_UNKNOWN_MISSING
    # The new deployment reads its own recorded bytes.
    body = _read(client, auth_headers, new_deployment).json()
    assert body["ready"] is True
    assert old_version and new_version


def test_the_upgrade_report_names_uncovered_bindings(
    client: Any, auth_headers: dict[str, str], clean_db: None
) -> None:
    agent_id, version_id, deployment_id = _bind_bundle(client, auth_headers, BUNDLE_DIGEST)
    report = client.get("/v1/factory/capability/upgrade-report", headers=auth_headers).json()
    entry = next(b for b in report["bindings"] if b["deployment_id"] == deployment_id)
    assert entry["has_capability_record"] is False
    assert entry["action"] == "build/render/redeploy"

    # After recording a manifest for the exact image+bundle pair, the binding
    # is covered.
    _record(agent_id, version_id, _manifest())
    report = client.get("/v1/factory/capability/upgrade-report", headers=auth_headers).json()
    entry = next(b for b in report["bindings"] if b["deployment_id"] == deployment_id)
    assert entry["has_capability_record"] is True
    assert entry["action"] == ""


def test_a_runner_image_rebind_alone_does_not_cover_a_binding(
    client: Any, auth_headers: dict[str, str], clean_db: None
) -> None:
    # A record for a DIFFERENT runner image with the same bundle does not
    # cover this deployment's exact image+bundle pair.
    agent_id, version_id, deployment_id = _bind_bundle(client, auth_headers, BUNDLE_DIGEST)
    _record(agent_id, version_id, _manifest(image_digest=OTHER_IMAGE_DIGEST))
    body = _read(client, auth_headers, deployment_id).json()
    assert body["ready"] is False
    report = client.get("/v1/factory/capability/upgrade-report", headers=auth_headers).json()
    entry = next(b for b in report["bindings"] if b["deployment_id"] == deployment_id)
    assert entry["has_capability_record"] is False
    assert entry["action"] == "build/render/redeploy"


# --- authentication -------------------------------------------------------


def test_the_capability_read_requires_the_api_key(client: Any, clean_db: None) -> None:
    resp = client.get("/v1/factory/capability/upgrade-report")
    assert resp.status_code in (401, 403)
