"""Migrage project version author name to user.id

Revision ID: 1ab5b02ce532
Revises: 57d0de13ce4a
Create Date: 2024-09-06 14:01:40.668483

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "1ab5b02ce532"
down_revision = "1c23e3be03a3"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "project_version",
        sa.Column("author_id", sa.Integer(), autoincrement=False, nullable=True),
    )
    op.create_index(
        op.f("ix_project_version_author_id"),
        "project_version",
        ["author_id"],
        unique=False,
    )
    op.create_foreign_key(
        op.f("fk_project_version_author_id_user"),
        "project_version",
        "user",
        ["author_id"],
        ["id"],
    )

    # migrate data
    conn = op.get_bind()
    query = """
        UPDATE project_version
        SET author_id = u.id
        FROM "user" u
        WHERE u.username = author;
    """
    conn.execute(sa.text(query))

    op.drop_index("ix_project_version_author", table_name="project_version")
    op.drop_column("project_version", "author")


def downgrade():
    op.add_column(
        "project_version",
        sa.Column("author", sa.VARCHAR(), autoincrement=False, nullable=True),
    )
    op.create_index(
        "ix_project_version_author", "project_version", ["author"], unique=False
    )

    # migrate data
    conn = op.get_bind()
    query = """
            UPDATE project_version
            SET author = u.username
            FROM "user" u
            WHERE u.id = author_id;
        """
    conn.execute(sa.text(query))

    op.drop_constraint(
        op.f("fk_project_version_author_id_user"), "project_version", type_="foreignkey"
    )
    op.drop_index(op.f("ix_project_version_author_id"), table_name="project_version")
    op.drop_column("project_version", "author_id")
