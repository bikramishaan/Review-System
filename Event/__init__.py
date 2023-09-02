from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_dance.contrib.google import make_google_blueprint, google
import smtplib
from google_auth_oauthlib.flow import Flow
from flask_mail import Mail


import os
import pathlib
import requests


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Event.db'
app.config['SQLALCHEMY_POOL_SIZE'] = 10 
app.config['SECRET_KEY'] = 'c9a7c56baa2482c0465082e4'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login_page"
login_manager.login_message_category = "info" 

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Port for sending email
app.config['MAIL_USERNAME'] = 'bharat.aggarwal@iic.ac.in'  # Your email address
app.config['MAIL_PASSWORD'] = 'ihldipgiadbmyvat'    # os.environ.get("Email_Password")  Your email password
app.config['MAIL_USE_TLS'] = True  # Use TLS for secure connection
app.config['MAIL_USE_SSL'] = False  # Use SSL (only if required)


mail = Mail(app)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "184802851527-oadfjba853a0c8l7jdvpmmgmd6u1vg81.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
  client_secrets_file=client_secrets_file,
  scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
  redirect_uri = "http://127.0.0.1:5000/callback"
  )


'''google_bp = make_google_blueprint(client_id='184802851527-oadfjba853a0c8l7jdvpmmgmd6u1vg81.apps.googleusercontent.com',
                                  client_secret='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',
                                  redirect_to='google_login',
                                  )
app.register_blueprint(google_bp, url_prefix='/google_login')
'''

'''GOOGLE_CLEINT_ID = "184802851527-oadfjba853a0c8l7jdvpmmgmd6u1vg81.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow =  Flow.from_client_secrets_file(
  client_secrets_file=client_secrets_file,
  scopes =["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
  redirect_uri="http://127.0.0.1:5000/EventPage"
  )
'''

app.app_context().push()

from Event import routes
