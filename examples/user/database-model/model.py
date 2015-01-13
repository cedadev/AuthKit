import sqlalchemy as sa
import datetime
from sqlalchemy import orm
from sqlalchemy import schema, types
import sqlalchemy
import meta

def init_model(engine):
    """Call me before using any of the tables or classes in the model."""

    sm = orm.sessionmaker(autoflush=True, transactional=True, bind=engine)

    meta.engine = engine
    meta.Session = orm.scoped_session(sm)


