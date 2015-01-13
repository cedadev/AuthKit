import model
from authkit.users.sqlalchemy_driver import UsersFromDatabase

# Setup SQLAlchemy database engine
from sqlalchemy import engine_from_config
engine = engine_from_config({'sqlalchemy.url':'sqlite:///test.db'}, 'sqlalchemy.')
model.init_model(engine)
model.engine = engine

users = UsersFromDatabase(model)
model.meta.metadata.create_all(model.engine)
users.group_create("pylons")
users.role_create("admin")
users.user_create("james", password="password1", group="pylons")
users.user_create("ben", password="password2")
users.user_add_role("ben", role="admin")

# Commit the changes
model.meta.Session.commit()
model.meta.Session.remove()

