import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy.orm import DeclarativeBase

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)




# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

# Enable CORS for cross-origin requests
CORS(app)

with app.app_context():
    # Make sure to import the models here or their tables won't be created
    db.create_all()
    
    # Initialize with some sample users for demonstration
    from models import User
    try:
        existing_users = User.query.count()
        if existing_users == 0:
            user1 = User()
            user1.username = 'john_doe'
            user1.email = 'john@example.com'
            
            user2 = User()
            user2.username = 'jane_smith'
            user2.email = 'jane@example.com'
            
            db.session.add(user1)
            db.session.add(user2)
            db.session.commit()
    except Exception as e:
        logging.error(f"Error initializing users: {e}")
        db.session.rollback()

# Import routes after app creation to avoid circular imports
from routes import *
