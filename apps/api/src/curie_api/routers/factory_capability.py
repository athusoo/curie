"""Authenticated read of a deployment's factory capability manifest (#4485).

``GET /v1/factory/capability/deployments/{deployment_id}`` returns the exact
recorded manifest bytes for one deployment, bound to its image and bundle
digests, plus the effective admission view: the deployment record composed
with the repository's ``.curie/verification.json`` resolved from the ticket's
exact immutable base commit.

The route is a read for later admission and validation (#4450 owns the gate):
it exposes evidence and refuses nothing about a ticket. A missing, malformed,
mismatched or stale binding answers ``environment unknown`` with its reason,
never a ready verdict and never a capability the image did not probe.

The repository declaration is resolved from the base commit the caller names
as the ticket's immutable base; the read records which commit the
declaration was resolved from, never a later branch tip.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from .. import factory_capability_manifest as capability
from ..auth import require_api_key
from ..deps import SessionDep
from ..models import AgentVersion, CapabilityRecord, Deployment

router = APIRouter(
    prefix="/v1/factory/capability",
    tags=["factory-capability"],
    dependencies=[Depends(require_api_key)],
)

ACTION_BUILD_RENDER_REDEPLOY = "build/render/redeploy"


class CapabilityRead(BaseModel):
    """The admission-facing read of one deployment's capability evidence."""

    ready: bool
    manifest: dict[str, Any] | None = None
    manifest_digest: str | None = None
    reason: str | None = None
    action: str | None = None
    verification_source: str
    base_commit: str | None = None
    repository_declaration: dict[str, Any] | None = None


class UpgradeBinding(BaseModel):
    """One active deployment in the upgrade report."""

    deployment_id: str
    agent_id: str
    has_capability_record: bool
    action: str


@router.get("/deployments/{deployment_id}", response_model=CapabilityRead)
async def read_deployment_capability(
    deployment_id: uuid.UUID, session: SessionDep, base_commit: str | None = None
) -> CapabilityRead:
    """The exact recorded manifest for one deployment and its admission view."""

    deployment = await session.get(Deployment, deployment_id)
    if deployment is None:
        raise HTTPException(404, "deployment not found")
    read = await capability.read_manifest(session, deployment=deployment)
    # The repository declaration is resolved from the ticket's exact base
    # commit by the caller (#4450's seam); this read records which commit the
    # declaration was resolved from, never a later branch tip.
    declaration, unreadable = capability.read_repository_declaration(None)
    view = capability.compose_admission_view(
        read,
        base_commit=base_commit,
        repository_declaration=declaration,
        repository_unreadable=unreadable,
    )
    return CapabilityRead(
        ready=view.ready,
        manifest=view.manifest,
        manifest_digest=view.manifest_digest,
        reason=view.reason,
        action="" if view.ready else ACTION_BUILD_RENDER_REDEPLOY,
        verification_source=view.verification_source,
        base_commit=view.base_commit,
        repository_declaration=view.repository_declaration,
    )


@router.get("/upgrade-report")
async def read_upgrade_report(session: SessionDep) -> dict[str, list[UpgradeBinding]]:
    """Each active deployment whose image and bundle lack a matching record.

    A runner-image rebind alone never marks a binding ready: only a record
    for the exact (image digest, bundle digest) pair does. The operator
    action for each uncovered binding is build/render/redeploy.
    """

    deployments = (
        await session.scalars(select(Deployment).where(Deployment.status == "active"))
    ).all()
    records = (await session.scalars(select(CapabilityRecord))).all()
    recorded = {(record.image_digest, record.bundle_digest) for record in records}
    bindings: list[UpgradeBinding] = []
    for deployment in deployments:
        version = await session.get(AgentVersion, deployment.version_id)
        bundle_digest = version.bundle_sha256 if version is not None else None
        image_digest = next(
            (
                record.image_digest
                for record in records
                if record.agent_id == deployment.agent_id and record.bundle_digest == bundle_digest
            ),
            None,
        )
        covered = (
            image_digest is not None
            and bundle_digest is not None
            and (image_digest, bundle_digest) in recorded
        )
        bindings.append(
            UpgradeBinding(
                deployment_id=str(deployment.id),
                agent_id=str(deployment.agent_id),
                has_capability_record=covered,
                action="" if covered else ACTION_BUILD_RENDER_REDEPLOY,
            )
        )
    return {"bindings": bindings}
