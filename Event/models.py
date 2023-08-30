from Event import db, login_manager
from Event import bcrypt
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True, autoincrement = True)
    username = db.Column(db.String(length=30), nullable=False, unique=True)
    full_name = db.Column(db.String(length=50), nullable=False)
    email_address = db.Column(db.String(length=50), nullable=False, unique=True)
    google_id = db.Column(db.String(length=50), nullable=True, unique=True)
    password_hash = db.Column(db.String(length=60), nullable=False)
    profile_picture_url = db.Column(db.String(length=100), nullable=True)
    Created_at = db.Column(db.DateTime(), default=db.func.current_timestamp(), nullable=False)
    last_login = db.Column(db.DateTime(), nullable=True)

    @property
    def password(self):
        return self.password

    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password_correction(self, attempted_password):
        return bcrypt.check_password_hash(self.password_hash, attempted_password)

    def update_last_login(self):
        self.last_login = datetime().utcnow()
        db.session.commit()