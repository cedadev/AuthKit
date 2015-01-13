"""\
Set up AuthKit to work in a Pylons 0.9.7 environment. This module
automatically imports the correct driver for the version of SQLAlchemy
you are using but only the 0.4.4 driver is actively tested and maintained.
"""

# SQLAlchemy Driver Initialization
# Author: Daniel Pronych
# Description: this file will import SQLAlchemy and based on version set driver.

# Change Log - originally November 2, 2007
# * moved sqlalchemy_driver.py into a new folder and renamed sqlalchemy_03.py
# * added a sqlalchemy_04.py file tuned for performance with SQLAlchemy 0.4.

import sqlalchemy

if sqlalchemy.__version__ >= '0.5':
    from sqlalchemy_05 import *
elif sqlalchemy.__version__ >= '0.4.0':
    # FIXME: specifically which version greater than 0.4.0 requires this?
    from sqlalchemy_044 import *
elif sqlalchemy.__version__ > '0.3':
    from sqlalchemy_04 import *
else:
    # backwards compatability for SQLAlchemy 0.3
    from sqlalchemy_03 import *
