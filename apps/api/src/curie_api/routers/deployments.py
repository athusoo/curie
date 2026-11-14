"""Deployments of a version to an environment."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status

from curie_api.crud import agents as crud_agents
from curie_api.crud import deployments as crud_deployments
from curie_api.crud import versions as crud_versions
from curie_api.schemas.deployments import DeploymentCreate, DeploymentOut

from .. import approver_tickets, capability_manifest, deploy
from ..auth import require_api_key
from ..deps import SessionDep, StoreDep

router = APIRouter(
    prefix="/deployments",
    tags=["deployments"],
    dependencies=[Depends(require_api_key)],
)


@router.post("", response_model=DeploymentOut, status_code=status.HTTP_201_CREATED)
async def create_deployment(
    data: DeploymentCreate, session: SessionDep, store: StoreDep
) -> DeploymentOut:
    agent = await crud_agents.get_agent(session, data.agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    if (
        "workspace_enabled" in data.model_fields_set
        and data.workspace_enabled is None
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "workspace_enabled must be true or false when provided",
        )
    version = await crud_versions.get_version(session, data.version_id)
    if version is None or version.agent_id != data.agent_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "version not found")
    # Revalidate the stored bundle against the CURRENT size/ratio caps before
    # this version becomes deployable -- catches a bundle stored before these
    # caps existed, or under looser ones (ADR-0059 decision 3).
    try:
        await deploy.revalidate_stored_bundle(store, version)
    except deploy.BundleTooLarge as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    # @spec ACTION-EXECUTOR-16: a bundle stored before intake refused a
    # non-SecretRef sealing key declaration is refused here too, before any row.
    # So is a stored tracker result declaration (#5585), with the upload
    # route's envelopes: a malformed one as a validation failure, a valid one
    # as `tracker_result_not_enabled`.
    try:
        await deploy.check_stored_bundle_intake(store, version)
    except (deploy.BundleTooLarge, deploy.SealingKeyCustody) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    except deploy.BundleInvalid as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"detail": "bundle failed validation", "errors": exc.errors},
        ) from exc
    except deploy.TrackerResultNotEnabled as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, {"code": exc.code, "message": str(exc)}
        ) from exc
    # The declared/bound approval-route join (#2436): this is the first moment
    # both halves are known for a specific agent, and the moment the version
    # becomes the thing that boots. AFTER the bounds check above, so an over-cap
    # legacy bundle keeps reporting `bundle.too_large` rather than surfacing as
    # an extraction failure in here (ADR-0059 decision 3's error contract), and
    # in FRONT of the row creation, so a refusal leaves nothing behind.
    #
    # The same read judges ADR 0271 gate ownership: a version whose bundle would
    # move or drop the gate of a registered approver_ticket pair never serves.
    try:
        await deploy.check_approval_route_bindings(store, version, agent.approval_routes)
    except deploy.ApprovalRoutesUnbound as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    except approver_tickets.BundleGateMismatch as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, {"code": exc.code, "message": str(exc)}
        ) from exc
    deployment = await crud_deployments.create_deployment(session, data)
    return DeploymentOut.model_validate(deployment)


@router.get("", response_model=list[DeploymentOut])
async def list_deployments(
    session: SessionDep, agent_id: uuid.UUID | None = None
) -> list[DeploymentOut]:
    deployments = await crud_deployments.list_deployments(session, agent_id)
    return [DeploymentOut.model_validate(d) for d in deployments]


@router.get("/{deployment_id}", response_model=DeploymentOut)
async def get_deployment(
    deployment_id: uuid.UUID, session: SessionDep
) -> DeploymentOut:
    deployment = await crud_deployments.get_deployment(session, deployment_id)
    if deployment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deployment not found")
    return DeploymentOut.model_validate(deployment)


@router.delete("/{deployment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def end_deployment(deployment_id: uuid.UUID, session: SessionDep) -> None:
    deployment = await crud_deployments.get_deployment(session, deployment_id)
    if deployment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deployment not found")
    await crud_deployments.end_deployment(session, deployment)


# --- capability manifest (#4485) --------------------------------------------


@router.get("/{deployment_id}/capability-manifest")
async def get_capability_manifest(deployment_id: uuid.UUID, session: SessionDep) -> object:
    """The exact recorded capability manifest bytes for one deployment.

    An authenticated read (decision 5): it returns the exact recorded manifest
    and its digest, or ``{"state": "environment_unknown", ...}`` when the
    record is missing, malformed, mismatched or stale. It never claims a
    capability the record does not name, and no credential value appears.
    """

    deployment = await crud_deployments.get_deployment(session, deployment_id)
    if deployment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deployment not found")
    evidence = capability_manifest.read_recorded_manifest(deployment)
    if evidence.state != "ready":
        return {
            "state": "environment_unknown",
            "reason": evidence.reason,
        }
    assert evidence.manifest is not None and evidence.digest is not None
    return {
        "state": "ready",
        "digest": evidence.digest,
        "manifest": capability_manifest.manifest_json(evidence.manifest),
    }


@router.post("/{deployment_id}/capability-manifest")
async def put_capability_manifest(
    deployment_id: uuid.UUID, session: SessionDep, body: dict[str, object]
) -> object:
    """Record a manifest for one deployment.

    Refuses a malformed manifest (422) and returns the recorded digest. This
    is the deployment-side writer decision 5 names; recording a manifest for a
    newly deployed version does not mutate an active execution or retroactively
    change an older version (decision 6).
    """

    deployment = await crud_deployments.get_deployment(session, deployment_id)
    if deployment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deployment not found")
    try:
        digest = await capability_manifest.record_capability_manifest(
            session, deployment, body
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    await session.commit()
    return {"state": "ready", "digest": digest}


@router.post("/{deployment_id}/capability-manifest/effective-view")
async def get_effective_view(
    deployment_id: uuid.UUID, session: SessionDep, body: dict[str, object]
) -> object:
    """The effective admission view for one deployment (#4485 decision 4).

    The caller supplies the ticket's exact immutable base commit and the
    repository's ``.curie/verification.json`` content AS READ AT THAT COMMIT
    (the deployment side cannot read a repository file at a commit through the
    CodeHost port, and the admission consumer is #4450, out of scope here).
    The view composes the immutable recorded manifest with that base-commit
    declaration: bundle checks win when the recorded manifest declares any,
    else the repository declaration stands, bound to the base commit it was
    read at -- never a moving branch tip. A missing record or an unreadable
    repository file yields ``environment_unknown``, never a ready verdict.
    """

    deployment = await crud_deployments.get_deployment(session, deployment_id)
    if deployment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deployment not found")
    base_commit = body.get("base_commit")
    if not isinstance(base_commit, str) or not base_commit.strip():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "base_commit is required: the ticket's immutable base commit",
        )
    raw = body.get("verification")
    unreadable = body.get("unreadable")
    if unreadable is not None and not isinstance(unreadable, str):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "unreadable must name why the repository verification file does not parse",
        )
    evidence = capability_manifest.read_recorded_manifest(deployment)
    if evidence.state != "ready":
        return {
            "state": "environment_unknown",
            "reason": evidence.reason,
            "base_commit": base_commit,
        }
    assert evidence.manifest is not None
    if evidence.manifest.verification_checks:
        # Precedence, first branch: the bundle's own checks are bound with
        # the deployed bundle, so the repository file is never consulted.
        effective = capability_manifest.ResolvedVerificationDeclaration(
            source="bundle", checks=list(evidence.manifest.verification_checks)
        )
    elif raw is not None:
        if not isinstance(raw, dict):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "verification must be the parsed .curie/verification.json object",
            )
        try:
            effective = capability_manifest.resolve_base_verification(
                raw, base_commit=base_commit
            )
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    else:
        # The file is absent or unreadable at the base commit: no declared
        # checks, with the reason named when it is unreadable.
        effective = capability_manifest.resolve_base_verification(
            None, base_commit=base_commit, unreadable=unreadable
        )
    response: dict[str, object] = {
        "state": "ready",
        "digest": evidence.digest,
        "verification_source": effective.source,
        "checks": [
            {
                "id": check.id,
                "route": check.route,
                **({"delegated_to": check.delegated_to} if check.delegated_to else {}),
            }
            for check in effective.checks
        ],
        # The ticket's immutable base commit, as supplied: part of the
        # admission evidence whichever branch won the precedence.
        "base_commit": base_commit,
    }
    if effective.unreadable is not None:
        # An unreadable repository file is unknown, never a silent no-check
        # success: the reason travels with the view (#4485 decision 4).
        response["unreadable"] = effective.unreadable
    return response
