from Event import db, login_manager
from Event import bcrypt
from flask_login import UserMixin
from datetime import datetime
import pytz

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True, autoincrement = True)
    username = db.Column(db.String(length=30), nullable=False, unique=True)
    full_name = db.Column(db.String(length=50), nullable=False)
    email_address = db.Column(db.String(length=50), nullable=False, unique=True)
    google_id = db.Column(db.String(length=50), nullable=True, unique=True)
    hash_password = db.Column(db.String(length=60), nullable=True)
    profile_picture_url = db.Column(db.String(length=100), nullable=True)
    created_at = db.Column(db.DateTime(), default=datetime.utcnow().replace(tzinfo=pytz.UTC).astimezone(pytz.timezone('Asia/Kolkata')), nullable=False)
    last_login = db.Column(db.DateTime(), default=datetime.utcnow().replace(tzinfo=pytz.UTC).astimezone(pytz.timezone('Asia/Kolkata')), nullable=True)
    verification_token = db.Column(db.String(length=32), unique=True)
    is_verified = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(length=20), nullable=True)
    '''filename = db.Column(db.String(50))
    Image_data = db.Column(db.LargeBinary)'''

    def update_last_login(self):
        self.last_login = datetime.utcnow().replace(tzinfo=pytz.UTC).astimezone(pytz.timezone('Asia/Kolkata'))
        db.session.commit()

    @property
    def password(self):
        return self.hash_password

    @password.setter
    def password(self, plain_text_password):
        self.hash_password = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')
    def check_password_correction(self, attempted_password):
        return bcrypt.check_password_hash(self.hash_password, attempted_password)

class Event(db.Model):
    id = db.Column(db.Integer(), primary_key=True, autoincrement = True)
    category = db.Column(db.String(length=30), nullable=False)
    title = db.Column(db.String(length=100), nullable=False, unique=True)
    acronym = db.Column(db.String(length=50), nullable=False, unique=True)
    web_page_url = db.Column(db.String(length=100), nullable=False, unique=True)
    venue = db.Column(db.String(length=30))
    city = db.Column(db.String(length=30), nullable=False)
    country = db.Column(db.String(length=30), nullable=False)
    first_day = db.Column(db.DateTime())
    last_day = db.Column(db.DateTime(), nullable=False)
    primary_area = db.Column(db.String(length=100))
    secondary_area = db.Column(db.String(length=100))
    area_notes = db.Column(db.String(length=200))
    organizer_name = db.Column(db.String(length=30), nullable=False)
    organizer_web_page = db.Column(db.String(length=100))
    phone_no = db.Column(db.String(length=15))
    other_info = db.Column(db.String(length=500))
    
