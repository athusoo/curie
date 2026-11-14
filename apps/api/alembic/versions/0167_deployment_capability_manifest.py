"""Deployment capability manifest: recorded bytes and digest (#4485).

Decision 5: at deployment, record the image-and-bundle capability manifest and
its digest with the deployed bundle and runner identity. The storage mechanism
is an implementation choice; this ticket does not require a database table, so
the record lives on the ``deployments`` row it describes. Two columns:

- ``capability_manifest``: the manifest's canonical JSON bytes (compact, sorted
  keys, one trailing newline), stored as JSONB so an authenticated read returns
  exactly the recorded bytes.
- ``capability_manifest_digest``: the SHA-256 hex of those bytes.

Both are absent together or present together: a deployment created before
capability recording (decision 6) has neither, which reads as missing evidence,
never an inferred ready manifest. The CHECK states that pair at the database so
a half-set row cannot be written out of band.

The downgrade refuses while any deployment carries a manifest: dropping the
columns would turn a recorded deployment into missing evidence, and a later
read would report ``environment unknown`` for a deployment that had already
been admitted. It takes an exclusive lock on the table first, under a bounded
wait, so a manifest cannot be recorded between the check and the drop.

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
S = "curie"
TABLE = "deployments"
CHECK = "deployments_capability_manifest_ck"


def upgrade() -> None:
    op.add_column(
        TABLE,
        sa.Column("capability_manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        schema=S,
    )
    op.add_column(
        TABLE,
        sa.Column("capability_manifest_digest", sa.String(length=64), nullable=True),
        schema=S,
    )
    op.create_check_constraint(
        CHECK,
        TABLE,
        "(capability_manifest IS NULL AND capability_manifest_digest IS NULL) "
        "OR (capability_manifest IS NOT NULL "
        "AND capability_manifest_digest IS NOT NULL "
        "AND capability_manifest_digest ~ '^[0-9a-f]{64}$')",
        schema=S,
    )


def downgrade() -> None:
    # Refuse while any row carries a manifest, before any DDL, and under a
    # bounded lock so a recording between the check and the drop cannot slip
    # through: dropping the columns would erase recorded evidence for a
    # deployed bundle.
    op.execute(sa.text("SET LOCAL lock_timeout = '15000ms'"))
    op.execute(sa.text(f"LOCK TABLE {S}.{TABLE} IN ACCESS EXCLUSIVE MODE"))
    recorded = sa.text(
        f"SELECT 1 FROM {S}.{TABLE} WHERE capability_manifest IS NOT NULL LIMIT 1"
    )
    conn = op.get_bind()
    if conn.execute(recorded).first() is not None:
        raise RuntimeError(
            f"cannot downgrade: {S}.{TABLE} rows still carry a capability manifest; "
            "end those deployments or keep revision 0167"
        )
    op.drop_constraint(CHECK, TABLE, schema=S, type_="check")
    op.drop_column(TABLE, "capability_manifest_digest", schema=S)
    op.drop_column(TABLE, "capability_manifest", schema=S)
