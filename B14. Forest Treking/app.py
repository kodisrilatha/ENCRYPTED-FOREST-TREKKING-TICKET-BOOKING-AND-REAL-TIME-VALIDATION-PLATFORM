import os
import logging

from flask import Flask
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET","secret")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

from database import get_user_by_id

class User:
    def __init__(self, user_data):
        self.id = user_data.get('id')
        self.username = user_data.get('username')
        self.email = user_data.get('email')
        self.role = user_data.get('role')
        self.full_name = user_data.get('full_name')
        self.phone = user_data.get('phone')
        self.is_active = True
        self.is_authenticated = True
    
    def get_id(self):
        return str(self.id)
    
    @property
    def is_anonymous(self):
        return False

@login_manager.user_loader
def load_user(user_id):
    user_data = get_user_by_id(int(user_id))
    if user_data:
        return User(user_data)
    return None

with app.app_context():
    import routes
