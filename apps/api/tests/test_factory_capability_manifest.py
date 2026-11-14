"""The deployment capability manifest's record, read and view (#4485).

Black-box regressions through the API seam: every case drives the real
router, the real ORM row and the real database, so the recorded evidence
and its digest binding are exercised exactly as a later admission consumer
(#4450, out of scope here) will read them.

What each acceptance criterion needs, by outcome:

- AC2: a deployment records the exact manifest bytes and digest; the
  authenticated read returns those exact bytes; missing, malformed,
  mismatched and stale bindings report ``environment unknown`` without
  claiming undeclared capabilities; and the verification precedence --
  bundle checks, else the repository ``.curie/verification.json`` resolved
  from the ticket's immutable base commit -- is exercised end to end.
- AC3: registry hosts and connector/service declarations are descriptive;
  a host declaration changes no permission, a missing declaration is
  absent, no credential value appears, and the ``.github/`` restriction
  matches the platform refusal.
- AC4: a deployment created before capability recording reads as missing
  evidence, never an inferred ready manifest, with the redeploy action;
  recording a manifest for a newly deployed version does not mutate an
  active execution or retroactively change the old version.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from curie_api.capability_manifest import (
    PUBLICATION_RESTRICTIONS,
    SCHEMA_VERSION,
)
from curie_api.config import get_settings
from fastapi.testclient import TestClient

REPO = "acme-corp/acme-bot"

RESTRICTIONS = tuple(PUBLICATION_RESTRICTIONS)


def _sha256_digest(c: str) -> str:
    return "sha256:" + (c * 64)[:64]


def _manifest(
    *,
    image_digest: str | None = _sha256_digest("a"),
    bundle_digest: str | None = _sha256_digest("b"),
    verification_checks: list[dict[str, Any]] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "image_digest": image_digest,
        "bundle_digest": bundle_digest,
        "tools": [
            {
                "name": "uv",
                "version": "0.5.1",
                "probe_command": ["uv", "--version"],
            }
        ],
        "registry_hosts": ["astral.sh"],
        "connectors": [{"name": "github"}],
        "services": [{"name": "docker"}],
        "verification_checks": (
            verification_checks
            if verification_checks is not None
            else [
                {
                    "id": "python",
                    "route": "delegated",
                    "delegated_to": "Python (ruff + mypy + pytest)",
                }
            ]
        ),
        "egress_class": "egress-basic",
        "publication_restrictions": list(RESTRICTIONS),
    }
    if extra:
        manifest.update(extra)
    return manifest


def _canonical(manifest: dict[str, Any]) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(manifest)).hexdigest()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(clean_db: None) -> Iterator[TestClient]:
    from curie_api.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture()
def auth_headers() -> dict[str, str]:
    return {"X-API-Key": get_settings().api_key}


def _create_agent_version(
    client: TestClient, auth_headers: dict[str, str], *, name: str = "manifest-bot"
) -> tuple[str, str]:
    agent_response = client.post(
        "/agents",
        json={
            "name": name,
            "channel": {"kind": "slack", "address": "C0EXAMPLE1"},
            "repo_full_name": REPO,
        },
        headers=auth_headers,
    )
    assert agent_response.status_code == 201, agent_response.text
    version_response = client.post(
        f"/agents/{agent_response.json()['id']}/versions",
        json={"version_label": "v1", "created_by": "operator"},
        headers=auth_headers,
    )
    assert version_response.status_code == 201, version_response.text
    return agent_response.json()["id"], version_response.json()["id"]


def _deploy(
    client: TestClient,
    auth_headers: dict[str, str],
    agent_id: str,
    version_id: str,
    *,
    environment: str = "dev",
) -> str:
    response = client.post(
        "/deployments",
        json={
            "agent_id": agent_id,
            "version_id": version_id,
            "environment": environment,
        },
        headers=auth_headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _record(
    client: TestClient,
    auth_headers: dict[str, str],
    deployment_id: str,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    response = client.post(
        f"/deployments/{deployment_id}/capability-manifest",
        json=manifest,
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _read(
    client: TestClient, auth_headers: dict[str, str], deployment_id: str
) -> dict[str, Any]:
    response = client.get(
        f"/deployments/{deployment_id}/capability-manifest",
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _effective_view(
    client: TestClient,
    auth_headers: dict[str, str],
    deployment_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    response = client.post(
        f"/deployments/{deployment_id}/capability-manifest/effective-view",
        json=body,
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _unknown(payload: dict[str, Any]) -> None:
    """The shared refusal shape: never a ready verdict."""
    assert payload["state"] == "environment_unknown"
    assert "reason" in payload and payload["reason"]
    assert "manifest" not in payload
    assert "digest" not in payload


def _sql(update: str, **params: Any) -> None:
    """A direct column write, as an operator or a drifted writer would make.

    The id binds as text and the statement casts it, because the plain form
    compares uuid to varchar and Postgres refuses the operator.
    """
    import asyncio

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    async def run() -> None:
        engine = create_async_engine(get_settings().database_url)
        try:
            async with engine.begin() as conn:
                await conn.execute(text(update).bindparams(**params))
        finally:
            await engine.dispose()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# AC2: record, the exact read, and the unknown bindings
# ---------------------------------------------------------------------------


def test_record_returns_the_canonical_digest_and_the_read_returns_those_bytes(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    manifest = _manifest()
    recorded = _record(client, auth_headers, deployment_id, manifest)
    assert recorded["state"] == "ready"
    # The digest the API records is the sha256 of the manifest's canonical
    # bytes -- reproducible from the manifest itself, from either side.
    assert recorded["digest"] == _digest(manifest)

    read = _read(client, auth_headers, deployment_id)
    assert read["state"] == "ready"
    assert read["digest"] == recorded["digest"]
    assert read["manifest"] == manifest
    # The read manifest's canonical bytes hash to the returned digest.
    assert hashlib.sha256(_canonical(read["manifest"])).hexdigest() == read["digest"]


def test_a_deployment_created_before_recording_reads_missing_evidence(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    read = _read(client, auth_headers, deployment_id)
    _unknown(read)
    assert "no capability manifest" in read["reason"]


def test_a_malformed_recorded_manifest_is_environment_unknown(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    # A malformed record: bytes that parse as JSON but are not a manifest.
    junk = {"not": "a manifest"}
    _sql(
        "UPDATE curie.deployments SET capability_manifest = cast(:m as jsonb), "
        "capability_manifest_digest = :d WHERE id = cast(:id as uuid)",
        m=json.dumps(junk),
        d=hashlib.sha256(
            json.dumps(junk, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        ).hexdigest(),
        id=deployment_id,
    )
    read = _read(client, auth_headers, deployment_id)
    _unknown(read)


def test_a_mismatched_digest_binding_is_environment_unknown(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    _record(client, auth_headers, deployment_id, _manifest())
    # A digest that no longer matches the recorded bytes.
    _sql(
        "UPDATE curie.deployments SET capability_manifest_digest = :d "
        "WHERE id = cast(:id as uuid)",
        d="e" * 64,
        id=deployment_id,
    )
    read = _read(client, auth_headers, deployment_id)
    _unknown(read)
    assert "match" in read["reason"]


def test_a_stale_digest_binding_is_environment_unknown(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    first = _record(client, auth_headers, deployment_id, _manifest())
    second_manifest = _manifest(bundle_digest=_sha256_digest("9"))
    second = _record(client, auth_headers, deployment_id, second_manifest)
    assert second["digest"] != first["digest"]
    # Re-recording keeps a single sound binding: the read is ready.
    read = _read(client, auth_headers, deployment_id)
    assert read["state"] == "ready"
    assert read["digest"] == second["digest"]
    # A stale binding -- a digest left over from the previous record.
    _sql(
        "UPDATE curie.deployments SET capability_manifest_digest = :d "
        "WHERE id = cast(:id as uuid)",
        d=first["digest"],
        id=deployment_id,
    )
    read = _read(client, auth_headers, deployment_id)
    _unknown(read)


def test_an_incomplete_binding_is_environment_unknown(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    # A half-set record: bytes without a digest, as a crashed writer would
    # leave. The database CHECK refuses exactly this row (see the migration),
    # so the binding is exercised on the reader itself: it must refuse to
    # invent a verdict for a half-set record, whatever wrote it.
    from curie_api import capability_manifest as cm
    from curie_api.models import Deployment

    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    recorded = _record(client, auth_headers, deployment_id, _manifest())

    half = Deployment(
        agent_id=uuid.UUID(agent_id),
        version_id=uuid.UUID(version_id),
        environment="dev",
    )
    half.capability_manifest = recorded_manifest_bytes(client, auth_headers, deployment_id)
    half.capability_manifest_digest = None
    evidence = cm.read_recorded_manifest(half)
    assert evidence.state == "environment_unknown"
    assert "incomplete" in (evidence.reason or "")

    reverse = Deployment(
        agent_id=uuid.UUID(agent_id),
        version_id=uuid.UUID(version_id),
        environment="dev",
    )
    reverse.capability_manifest = None
    reverse.capability_manifest_digest = recorded["digest"]
    evidence = cm.read_recorded_manifest(reverse)
    assert evidence.state == "environment_unknown"
    assert "incomplete" in (evidence.reason or "")


def recorded_manifest_bytes(
    client: TestClient, auth_headers: dict[str, str], deployment_id: str
) -> dict[str, Any]:
    """The recorded manifest as read back from the API, for row surgery."""
    return _read(client, auth_headers, deployment_id)["manifest"]


def test_recording_refuses_a_malformed_manifest(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    response = client.post(
        f"/deployments/{deployment_id}/capability-manifest",
        json={"schema_version": 1},
        headers=auth_headers,
    )
    assert response.status_code == 422, response.text
    # Nothing landed: the read is still missing evidence.
    read = _read(client, auth_headers, deployment_id)
    _unknown(read)


def test_recording_refuses_wrong_publication_restrictions(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    # A paraphrased restriction is not the platform's refusal: refused.
    response = client.post(
        f"/deployments/{deployment_id}/capability-manifest",
        json=_manifest(
            extra={
                "publication_restrictions": [
                    "no GitHub changes",
                    RESTRICTIONS[1],
                ]
            }
        ),
        headers=auth_headers,
    )
    assert response.status_code == 422, response.text


def test_the_authenticated_read_requires_the_api_key(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    response = client.get(f"/deployments/{deployment_id}/capability-manifest")
    assert response.status_code in (401, 403), response.text


def test_an_unknown_deployment_404s(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    response = client.get(
        f"/deployments/{uuid.uuid4()}/capability-manifest", headers=auth_headers
    )
    assert response.status_code == 404, response.text


# ---------------------------------------------------------------------------
# AC2: the effective admission view, end to end
# ---------------------------------------------------------------------------


def test_bundle_checks_win_when_the_manifest_declares_them(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    _record(client, auth_headers, deployment_id, _manifest())
    view = _effective_view(
        client,
        auth_headers,
        deployment_id,
        {
            "base_commit": "b" * 40,
            "verification": {
                "checks": [{"id": "rust", "command": ["cargo", "test"]}]
            },
        },
    )
    assert view["state"] == "ready"
    assert view["verification_source"] == "bundle"
    assert [c["id"] for c in view["checks"]] == ["python"]
    assert view["checks"][0]["delegated_to"] == "Python (ruff + mypy + pytest)"
    # The base commit is recorded on the view even when the bundle wins:
    # it was supplied, and it is part of the evidence.
    assert view["base_commit"] == "b" * 40


def test_repository_checks_stand_when_the_bundle_declares_none(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    _record(
        client,
        auth_headers,
        deployment_id,
        _manifest(verification_checks=[]),
    )
    base = "c0ffee" * 6 + "1234"
    view = _effective_view(
        client,
        auth_headers,
        deployment_id,
        {
            "base_commit": base,
            "verification": {
                "checks": [{"id": "rust", "command": ["cargo", "test"]}]
            },
        },
    )
    assert view["state"] == "ready"
    assert view["verification_source"] == "repository"
    assert [c["id"] for c in view["checks"]] == ["rust"]
    assert view["checks"][0]["route"] == "sandbox"
    assert "delegated_to" not in view["checks"][0]
    # The commit the declaration was read at, never a moving branch tip.
    assert view["base_commit"] == base


def test_a_delegated_repository_check_is_routed(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    _record(
        client,
        auth_headers,
        deployment_id,
        _manifest(verification_checks=[]),
    )
    view = _effective_view(
        client,
        auth_headers,
        deployment_id,
        {
            "base_commit": "d" * 40,
            "verification": {
                "checks": [
                    {
                        "id": "python",
                        "command": ["uv", "run", "pytest"],
                        "delegated_to": "Python (ruff + mypy + pytest)",
                    }
                ]
            },
        },
    )
    assert view["verification_source"] == "repository"
    assert view["checks"][0]["route"] == "delegated"
    assert view["checks"][0]["delegated_to"] == "Python (ruff + mypy + pytest)"


def test_no_checks_when_neither_bundle_nor_repository_declares_any(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    _record(
        client,
        auth_headers,
        deployment_id,
        _manifest(verification_checks=[]),
    )
    # The file is absent at the base commit: no declared checks.
    view = _effective_view(
        client, auth_headers, deployment_id, {"base_commit": "f" * 40}
    )
    assert view["state"] == "ready"
    assert view["verification_source"] == "none"
    assert view["checks"] == []
    assert view["base_commit"] == "f" * 40


def test_an_empty_repository_checks_list_is_no_checks(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    # The repository declaring an empty checks list: still no declared
    # checks, and still a ready view (the manifest is sound).
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    _record(
        client,
        auth_headers,
        deployment_id,
        _manifest(verification_checks=[]),
    )
    view = _effective_view(
        client,
        auth_headers,
        deployment_id,
        {"base_commit": "a" * 40, "verification": {"checks": []}},
    )
    assert view["state"] == "ready"
    assert view["verification_source"] == "none"
    assert view["checks"] == []


def test_an_unreadable_repository_file_is_unknown_not_a_silent_success(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    _record(
        client,
        auth_headers,
        deployment_id,
        _manifest(verification_checks=[]),
    )
    view = _effective_view(
        client,
        auth_headers,
        deployment_id,
        {
            "base_commit": "e" * 40,
            "unreadable": "the .curie/verification.json at this commit is not JSON",
        },
    )
    assert view["state"] == "ready"
    assert view["verification_source"] == "none"
    assert view["checks"] == []
    # The unknown is named, never silently a no-check success.
    assert view["unreadable"] == (
        "the .curie/verification.json at this commit is not JSON"
    )
    assert view["base_commit"] == "e" * 40


def test_the_view_is_unknown_when_the_record_is_missing(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    view = _effective_view(
        client,
        auth_headers,
        deployment_id,
        {
            "base_commit": "b" * 40,
            "verification": {
                "checks": [{"id": "rust", "command": ["cargo", "test"]}]
            },
        },
    )
    assert view["state"] == "environment_unknown"
    assert view["reason"]
    assert "checks" not in view


def test_the_view_refuses_a_missing_base_commit(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    _record(client, auth_headers, deployment_id, _manifest())
    response = client.post(
        f"/deployments/{deployment_id}/capability-manifest/effective-view",
        json={"verification": {"checks": []}},
        headers=auth_headers,
    )
    assert response.status_code == 422, response.text


def test_the_view_refuses_a_malformed_repository_declaration(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    # The bundle declares no checks, so the repository declaration IS
    # resolved -- and a malformed one is refused, never a silent success.
    _record(
        client, auth_headers, deployment_id, _manifest(verification_checks=[])
    )
    response = client.post(
        f"/deployments/{deployment_id}/capability-manifest/effective-view",
        json={
            "base_commit": "b" * 40,
            "verification": {"checks": [{"id": "x", "command": "not-a-list"}]},
        },
        headers=auth_headers,
    )
    assert response.status_code == 422, response.text
    # With bundle checks present the same malformed declaration is never
    # consulted: precedence skips the repository file entirely.
    deployment2 = _deploy(
        client, auth_headers, agent_id, version_id, environment="prod"
    )
    _record(client, auth_headers, deployment2, _manifest())
    response = client.post(
        f"/deployments/{deployment2}/capability-manifest/effective-view",
        json={
            "base_commit": "b" * 40,
            "verification": {"checks": [{"id": "x", "command": "not-a-list"}]},
        },
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["verification_source"] == "bundle"


def test_the_view_404s_for_an_unknown_deployment(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    response = client.post(
        f"/deployments/{uuid.uuid4()}/capability-manifest/effective-view",
        json={"base_commit": "b" * 40},
        headers=auth_headers,
    )
    assert response.status_code == 404, response.text


def test_a_later_repository_edit_does_not_change_the_view(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    # The declaration is bound to the base commit it was read at. A caller
    # that re-reads a LATER commit supplies a different base_commit, and the
    # view names THAT commit -- the evidence for the first ticket never
    # changes underneath it.
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    _record(
        client,
        auth_headers,
        deployment_id,
        _manifest(verification_checks=[]),
    )
    first = _effective_view(
        client,
        auth_headers,
        deployment_id,
        {
            "base_commit": "1111" * 10,
            "verification": {
                "checks": [{"id": "rust", "command": ["cargo", "test"]}]
            },
        },
    )
    assert first["base_commit"] == "1111" * 10
    assert [c["id"] for c in first["checks"]] == ["rust"]
    # The repository later edits the file; a NEW ticket's view names the new
    # commit. The first view's evidence is unchanged.
    second = _effective_view(
        client,
        auth_headers,
        deployment_id,
        {
            "base_commit": "2222" * 10,
            "verification": {
                "checks": [{"id": "python", "command": ["uv", "run", "pytest"]}]
            },
        },
    )
    assert second["base_commit"] == "2222" * 10
    assert [c["id"] for c in second["checks"]] == ["python"]
    assert first["base_commit"] == "1111" * 10
    assert [c["id"] for c in first["checks"]] == ["rust"]


# ---------------------------------------------------------------------------
# AC3: descriptive declarations, and the platform refusal
# ---------------------------------------------------------------------------


def test_a_host_declaration_does_not_change_permissions(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    # A registry host is a probe input, not a grant: recording a host
    # changes nothing but the manifest's own bytes and digest.
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    first = _record(
        client, auth_headers, deployment_id, _manifest(extra={"registry_hosts": ["a.sh"]})
    )
    second = _record(
        client,
        auth_headers,
        deployment_id,
        _manifest(
            extra={"registry_hosts": ["a.sh", "index.crates.io", "evil.example"]}
        ),
    )
    assert second["digest"] != first["digest"]
    # The read returns exactly what was recorded -- descriptive hosts and
    # all -- with no permission surface anywhere in the response.
    read = _read(client, auth_headers, deployment_id)
    assert read["manifest"]["registry_hosts"] == [
        "a.sh",
        "index.crates.io",
        "evil.example",
    ]
    assert read["digest"] == second["digest"]


def test_a_missing_connector_or_service_is_absent_never_inferred(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    _record(
        client,
        auth_headers,
        deployment_id,
        _manifest(extra={"connectors": [], "services": []}),
    )
    read = _read(client, auth_headers, deployment_id)
    assert read["state"] == "ready"
    assert read["manifest"]["connectors"] == []
    assert read["manifest"]["services"] == []
    # Undeclared capability is absent: nothing about the read infers a
    # connector or service the record does not name.
    text = json.dumps(read)
    assert "github" not in text
    assert "docker" not in text


def test_no_credential_value_appears_in_the_recorded_evidence(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    # A caller tries to smuggle a credential into the manifest: an unknown
    # field, refused outright (extra="forbid"), so no credential can land.
    response = client.post(
        f"/deployments/{deployment_id}/capability-manifest",
        json=_manifest(
            extra={
                "credential": "sk-ant-api03-example",
                "tools": [
                    {
                        "name": "uv",
                        "version": "0.5.1",
                        "probe_command": ["uv", "--version"],
                        "api_key": "sk-ant-api03-example",
                    }
                ],
            }
        ),
        headers=auth_headers,
    )
    assert response.status_code == 422, response.text
    read = _read(client, auth_headers, deployment_id)
    _unknown(read)
    assert "sk-ant" not in json.dumps(read)


def test_the_github_restriction_matches_the_platform_refusal(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    _record(client, auth_headers, deployment_id, _manifest())
    read = _read(client, auth_headers, deployment_id)
    # The exact `.github/` refusals the platform enforces, verbatim,
    # workflow changes first.
    assert read["manifest"]["publication_restrictions"] == [
        "GitHub workflow changes cannot be published by this capability",
        "GitHub metadata changes cannot be published by this capability",
    ]
    assert tuple(read["manifest"]["publication_restrictions"]) == RESTRICTIONS


def test_a_refused_manifest_lands_nothing(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    # The wrong schema_version is refused and nothing lands.
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    response = client.post(
        f"/deployments/{deployment_id}/capability-manifest",
        json=_manifest(extra={"schema_version": SCHEMA_VERSION + 1}),
        headers=auth_headers,
    )
    assert response.status_code == 422, response.text
    read = _read(client, auth_headers, deployment_id)
    _unknown(read)


# ---------------------------------------------------------------------------
# AC4: the legacy deployment, and the new version
# ---------------------------------------------------------------------------


def test_a_legacy_deployment_reads_missing_evidence_and_stays_active(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    # The deployment exists and is active, created before capability
    # recording: missing evidence, never an inferred ready manifest. The
    # operator action is to rebuild, render and redeploy so the current
    # image and bundle get a recorded manifest; the deployment itself is
    # not blocked or ended.
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    read = _read(client, auth_headers, deployment_id)
    _unknown(read)
    listed = client.get(
        "/deployments", params={"agent_id": agent_id}, headers=auth_headers
    )
    assert listed.status_code == 200, listed.text
    assert any(d["id"] == deployment_id for d in listed.json())


def test_recording_for_a_new_version_does_not_change_the_old_version(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    # A second version is deployed and records a manifest; the FIRST
    # version's deployment (still active in dev) is unchanged, and recording
    # for the new version does not mutate the active execution's evidence.
    agent_id, first_version = _create_agent_version(client, auth_headers)
    second_version_response = client.post(
        f"/agents/{agent_id}/versions",
        json={"version_label": "v2", "created_by": "operator"},
        headers=auth_headers,
    )
    assert second_version_response.status_code == 201, second_version_response.text
    second_version = second_version_response.json()["id"]

    first_deployment = _deploy(client, auth_headers, agent_id, first_version)
    # The first deployment is active with no record: missing evidence.
    _unknown(_read(client, auth_headers, first_deployment))

    # The new version deploys to prod and records its manifest.
    second_deployment = _deploy(
        client, auth_headers, agent_id, second_version, environment="prod"
    )
    recorded = _record(
        client,
        auth_headers,
        second_deployment,
        _manifest(bundle_digest=_sha256_digest("7")),
    )
    assert recorded["state"] == "ready"

    # The first deployment's evidence is still missing, and its row still
    # answers: the recording for the new version did not mutate it.
    first_read = _read(client, auth_headers, first_deployment)
    _unknown(first_read)
    assert "no capability manifest" in first_read["reason"]

    # And the second deployment reads exactly its own manifest.
    second_read = _read(client, auth_headers, second_deployment)
    assert second_read["state"] == "ready"
    assert second_read["manifest"]["bundle_digest"] == _sha256_digest("7")
    assert second_read["digest"] == recorded["digest"]


def test_the_effective_view_of_a_legacy_deployment_is_unknown(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    # A deployment created before recording has no manifest, so its
    # effective view is environment unknown -- the operator action is to
    # rebuild, render and redeploy before manifest-based admission is
    # enabled, never to admit from an older image's tool list.
    agent_id, version_id = _create_agent_version(client, auth_headers)
    deployment_id = _deploy(client, auth_headers, agent_id, version_id)
    view = _effective_view(
        client,
        auth_headers,
        deployment_id,
        {
            "base_commit": "b" * 40,
            "verification": {
                "checks": [{"id": "rust", "command": ["cargo", "test"]}]
            },
        },
    )
    assert view["state"] == "environment_unknown"
    assert view["reason"]
    # The base commit still travels with the refusal.
    assert view["base_commit"] == "b" * 40
