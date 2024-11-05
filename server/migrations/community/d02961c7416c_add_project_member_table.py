"""Add project member table

Revision ID: d02961c7416c
Revises: 1ab5b02ce532
Create Date: 2024-10-31 15:20:52.833051

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "d02961c7416c"
down_revision = "1ab5b02ce532"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "project_member",
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column(
            "role",
            postgresql.ENUM("reader", "editor", "writer", "owner", name="project_role"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["project.id"],
            name=op.f("fk_project_member_project_id_project"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name=op.f("fk_project_member_user_id_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "project_id", "user_id", name=op.f("pk_project_member")
        ),
    )

    op.add_column("project", sa.Column("public", sa.Boolean(), nullable=True))
    op.create_index(op.f("ix_project_public"), "project", ["public"], unique=False)

    data_upgrade()

    op.drop_table("project_access")


def downgrade():
    op.create_table(
        "project_access",
        sa.Column("public", sa.BOOLEAN(), autoincrement=False, nullable=True),
        sa.Column(
            "owners",
            postgresql.ARRAY(sa.INTEGER()),
            server_default=sa.text("'{}'::integer[]"),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column(
            "readers",
            postgresql.ARRAY(sa.INTEGER()),
            server_default=sa.text("'{}'::integer[]"),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column(
            "writers",
            postgresql.ARRAY(sa.INTEGER()),
            server_default=sa.text("'{}'::integer[]"),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column("project_id", postgresql.UUID(), autoincrement=False, nullable=False),
        sa.Column(
            "editors",
            postgresql.ARRAY(sa.INTEGER()),
            server_default=sa.text("'{}'::integer[]"),
            autoincrement=False,
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["project.id"],
            name="fk_project_access_project_id_project",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("project_id", name="pk_project_access"),
    )
    op.create_index(
        "ix_project_access_writers",
        "project_access",
        ["writers"],
        unique=False,
        postgresql_using="gin",
    )
    op.create_index(
        "ix_project_access_readers",
        "project_access",
        ["readers"],
        unique=False,
        postgresql_using="gin",
    )
    op.create_index(
        "ix_project_access_public", "project_access", ["public"], unique=False
    )
    op.create_index(
        "ix_project_access_project_id", "project_access", ["project_id"], unique=False
    )
    op.create_index(
        "ix_project_access_owners",
        "project_access",
        ["owners"],
        unique=False,
        postgresql_using="gin",
    )
    op.create_index(
        "ix_project_access_editors",
        "project_access",
        ["editors"],
        unique=False,
        postgresql_using="gin",
    )

    data_downgrade()

    op.drop_index(op.f("ix_project_public"), table_name="project")
    op.drop_column("project", "public")
    op.drop_table("project_member")
    conn = op.get_bind()
    conn.execute(sa.text("DROP TYPE project_role;"))


def data_upgrade():
    conn = op.get_bind()
    conn.execute(
        sa.text(
            """
            WITH members AS (
                SELECT
                        project_id AS project_id,
                        unnest(owners) AS user_id,
                        'owner' AS role
                FROM project_access
                UNION
                SELECT
                        project_id AS project_id,
                        unnest(writers - owners) AS user_id,
                        'writer' AS role
                FROM project_access
                UNION
                SELECT
                        project_id AS project_id,
                        unnest(editors - writers - owners) AS user_id,
                        'editor' AS role
                FROM project_access
                UNION
                SELECT
                        project_id AS project_id,
                        unnest(readers - editors - writers - owners) AS user_id,
                        'reader' AS role
                FROM project_access
            )
            INSERT INTO project_member (project_id, user_id, role)
            SELECT DISTINCT project_id, user_id, role::project_role FROM members;
        """
        )
    )

    conn.execute(
        sa.text(
            """
            UPDATE project p
            SET
                public = pa.public
            FROM project_access pa
            WHERE pa.project_id = p.id;
        """
        )
    )


def data_downgrade():
    conn = op.get_bind()
    conn.execute(
        sa.text(
            """
            WITH members AS (
                WITH agg AS (
                    SELECT
                        project_id,
                        array_agg(user_id) AS users_ids,
                        role
                    FROM
                        project_member
                    GROUP BY project_id, role
                )
                SELECT
                    o.project_id,
                    o.users_ids AS owners,
                    o.users_ids || w.users_ids AS writers,
                    o.users_ids || w.users_ids || e.users_ids AS editors,
                    o.users_ids || w.users_ids || e.users_ids || r.users_ids AS readers
                FROM (SELECT * FROM agg WHERE role = 'owner') AS o
                LEFT OUTER JOIN (SELECT * FROM agg WHERE role = 'reader') AS r ON o.project_id = r.project_id
                LEFT OUTER JOIN (SELECT * FROM agg WHERE role = 'editor') AS e ON o.project_id = e.project_id
                LEFT OUTER JOIN (SELECT * FROM agg WHERE role = 'writer') AS w ON o.project_id = w.project_id
                )
            INSERT INTO project_access (project_id, owners, writers, editors, readers)
            SELECT DISTINCT project_id, owners, writers, editors, readers FROM members m;
        """
        )
    )

    conn.execute(
        sa.text(
            """
            UPDATE project_access pa
            SET
                public = p.public
            FROM project p
            WHERE pa.project_id = p.id;
        """
        )
    )