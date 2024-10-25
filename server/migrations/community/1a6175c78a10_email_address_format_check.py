"""Email address format check

Revision ID: 1a6175c78a10
Revises: 1ab5b02ce532
Create Date: 2024-10-17 15:13:11.360991

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "1a6175c78a10"
down_revision = "1ab5b02ce532"
branch_labels = None
depends_on = None


def upgrade():
    op.create_check_constraint(
        constraint_name="email_format",
        table_name="user",
        condition="email ~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+.[A-Za-z]{2,}$'",
    )


def downgrade():
    op.drop_constraint("email_format", "user", type_="check")
