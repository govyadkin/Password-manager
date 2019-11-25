"""empty message

Revision ID: e9db0836857c
Revises: 1b3d3f6731c9
Create Date: 2019-11-25 16:51:14.148512

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e9db0836857c'
down_revision = '1b3d3f6731c9'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('timestamp', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'timestamp')
    # ### end Alembic commands ###
