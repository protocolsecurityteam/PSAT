"""Preserve security scores when dollar exposure is unknown.

Revision ID: e1b72d9a640c
Revises: d8e51f0a2b64
"""

from alembic import op

revision = "e1b72d9a640c"
down_revision = "d8e51f0a2b64"
branch_labels = None
depends_on = None

_CONSTRAINT = "ck_protocol_scores_grade_pairing"
_NEW_PAIRING = """
    (grade_state = 'computed' AND grade_lambda IS NOT NULL AND confidence_pct IS NOT NULL)
    OR (grade_state <> 'computed' AND grade_lambda IS NULL
        AND grade_exposure IS NULL AND confidence_pct IS NULL)
"""
_OLD_PAIRING = """
    (grade_state = 'computed') =
    (grade_lambda IS NOT NULL AND grade_exposure IS NOT NULL AND confidence_pct IS NOT NULL)
"""


def upgrade() -> None:
    op.drop_constraint(_CONSTRAINT, "protocol_scores", type_="check")
    op.create_check_constraint(_CONSTRAINT, "protocol_scores", _NEW_PAIRING)
    # Recompute from actual inputs, never reconstruct a headline from dated
    # JSON provenance. Documents may also live outside Postgres in object storage.
    op.execute("""
        INSERT INTO protocol_score_queue (protocol_id, reason, dirty_at)
        SELECT id, 'independent_security_score', now() FROM protocols
        ON CONFLICT (protocol_id) DO UPDATE
            SET reason = EXCLUDED.reason, dirty_at = EXCLUDED.dirty_at
    """)


def downgrade() -> None:
    # Old readers interpret these documents as an impossible state. Silently
    # clearing the columns would disagree with inline or spilled documents;
    # inventing a zero exposure would change the meaning of the measurement.
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM protocol_scores
                WHERE grade_state = 'computed' AND grade_exposure IS NULL
            ) THEN
                RAISE EXCEPTION 'Cannot downgrade independent security scores: computed rows with unknown exposure exist; archive or recompute them with the prior model before rollback';
            END IF;
        END $$
    """)
    op.drop_constraint(_CONSTRAINT, "protocol_scores", type_="check")
    op.create_check_constraint(_CONSTRAINT, "protocol_scores", _OLD_PAIRING)
