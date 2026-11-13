"""Factory capability records: deployment-bound manifest evidence (#4485).

``capability_records`` stores one immutable, deployment-bound factory
capability manifest (ADR 0199 decision 3): the manifest bytes, their SHA-256
digest, the schema version, and the binding identity -- agent, runner image
digest and bundle digest. A record is written once at deployment with the
deployed bundle and runner identity, and the authenticated read returns those
exact bytes. Missing, malformed, mismatched or stale bindings are missing
evidence for admission, never an inferred ready manifest.

A deployment recorded before this revision has no row and reads as missing
evidence; the row is additive and no existing deployment or execution is
mutated by recording one.

Revision ID: 0167
Revises: 0166
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0167"
down_revision: str = "0166"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "curie"
TABLE = "capability_records"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{SCHEMA}.agents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(f"{SCHEMA}.agent_versions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("image_digest", sa.Text(), nullable=False),
        sa.Column("bundle_digest", sa.Text(), nullable=False),
        sa.Column("digest", sa.Text(), nullable=False),
        sa.Column("manifest_bytes", sa.Text(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint("schema_version = 1", name=f"{TABLE}_schema_version_ck"),
        sa.CheckConstraint(
            "image_digest ~ '^sha256:[0-9a-f]{64}$'", name=f"{TABLE}_image_digest_ck"
        ),
        sa.CheckConstraint(
            "bundle_digest ~ '^sha256:[0-9a-f]{64}$'", name=f"{TABLE}_bundle_digest_ck"
        ),
        sa.CheckConstraint("digest ~ '^sha256:[0-9a-f]{64}$'", name=f"{TABLE}_digest_ck"),
        sa.UniqueConstraint(
            "agent_id", "image_digest", "bundle_digest", name=f"{TABLE}_binding_key"
        ),
        schema=SCHEMA,
    )
    op.create_index(f"ix_{TABLE}_agent_id", TABLE, ["agent_id"], schema=SCHEMA)
    op.create_index(f"ix_{TABLE}_version_id", TABLE, ["version_id"], schema=SCHEMA)


def downgrade() -> None:
    op.drop_index(f"ix_{TABLE}_version_id", TABLE, schema=SCHEMA)
    op.drop_index(f"ix_{TABLE}_agent_id", TABLE, schema=SCHEMA)
    op.drop_table(TABLE, schema=SCHEMA)
