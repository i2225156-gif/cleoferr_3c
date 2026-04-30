from flask_sqlalchemy import SQLAlchemy

import app

db = SQLAlchemy()
db.init_app(app)
