"""empty message

Revision ID: 4204bc0daf51
Revises: 
Create Date: 2017-09-01 12:53:22.442000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4204bc0daf51'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('names', sa.String(length=100), nullable=True),
    sa.Column('country', sa.String(length=50), nullable=True),
    sa.Column('category', sa.String(length=50), nullable=True),
    sa.Column('email', sa.String(length=100), nullable=True),
    sa.Column('password', sa.String(length=70), nullable=True),
    sa.Column('repeat_password', sa.String(length=70), nullable=True),
    sa.Column('registered_on', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_index(op.f('ix_user_category'), 'user', ['category'], unique=False)
    op.create_index(op.f('ix_user_country'), 'user', ['country'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_user_country'), table_name='user')
    op.drop_index(op.f('ix_user_category'), table_name='user')
    op.drop_table('user')
    # ### end Alembic commands ###
