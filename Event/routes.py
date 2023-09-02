from Event import app
from flask import render_template, redirect, url_for, flash, request, session, abort
from Event.models import User
from Event.forms import RegisterForm, LoginForm
from Event import db, flow, GOOGLE_CLIENT_ID, mail
from flask_login import login_user, logout_user, login_required, current_user
from flask_dance.contrib.google import google
from google.oauth2 import id_token
import google.auth.transport.requests
from datetime import datetime
import pytz
import secrets
from flask_mail import Message

@app.route('/')
@app.route('/home')
def home_page():
    return render_template('home.html')

''' Manual User Regsitration Route'''
@app.route("/register", methods=['GET', 'POST'])
def register_page():
    form = RegisterForm()
    token = None

    if form.validate_on_submit():
        user_to_create = User(username=form.username.data,
                              full_name = form.full_name.data,
                              email_address=form.email_address.data,
                              password=form.password1.data
                              )

        token = generate_verification_token(user_to_create.email_address)
        print(token)
        user_to_create.verification_token=token
        db.session.add(user_to_create)
        db.session.commit()
        verification_link = url_for('verify_email', token=token, _external=True)

        msg = Message('Verify Your Email', sender='bharat.aggarwal@iic.ac.in', recipients=[user_to_create.email_address])
        msg.body = f'Click on the following link to verify your email: {verification_link}'
        mail.send(msg)

        return redirect(url_for('redirect_page'))


        '''
        login_user(user_to_create)

        flash(f"Account Created Successfully! You are now logged in as {user_to_create.username}", category='success')

        return redirect(url_for('Event_page'))
        '''

    if form.errors != {}:       #If there are no errors from the validations.
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}', category='danger')

    return render_template('register.html', form=form)

def generate_verification_token(email):
    token = secrets.token_hex(16) #Generate a random token

    '''user = User.query.filter_by(email_address=email).first()
    user.verification_token = token'''

    return token

''' Manual User Login Route'''
@app.route("/login", methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        print(attempted_user.username)
        print(attempted_user.hash_password)
        if attempted_user and attempted_user.is_verified and attempted_user.check_password_correction(attempted_password=form.password.data):
            login_user(attempted_user)
            attempted_user.update_last_login()
            flash(f'Success!! You are logged in as: {attempted_user.username} ', category='success')
            return redirect(url_for('Event_page'))
        else:
            flash('Username and password are not match! or Email Verification is not done. Please try again', category='danger')

    return render_template('login.html', form=form)


'''  The login required function to check if the google user is in session or not.'''

def login_is_required(function):
  def wrapper(*args, **kwargs):
    if "google_id" not in session: 
      return abort(401) # Authorizaion Required
    else:
      return function()

  return wrapper


@app.route('/EventPage')
def Event_page():
    return render_template('EventPage.html')

@app.route('/Google_Wait')
@login_is_required
def Event_page_google():
    return redirect(url_for('Event_page'))

@app.route('/redirect')
def redirect_page():
    return render_template('Redirect.html')

@app.route('/verify')
def verify_email():
    token = request.args.get('token')
    print(token)
    user = User.query.filter_by(verification_token=token).first()

    if user:
        user.is_verified = True
        print(user.is_verified)
        db.session.commit()
        flash('Your email has been verified. You can now log in.', 'success')
        return redirect(url_for('login_page'))

    else:
        flash('Invalid verification token. Please try again.', 'danger')
        return redirect(url_for('register_page'))


@app.route("/logout")
def logout_page():
    logout_user()
    session.clear()
    flash('You have been logged out!', category='info')
    return redirect(url_for('home_page'))

''' Google authentication code was written from here.
    '''

@app.route('/google_login')
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url) 

@app.route("/callback")
def callback():

  flow.fetch_token(authorization_response=request.url)

  if not session["state"] == request.args["state"]:
    abort(500)

  credentials = flow.credentials
  token_request = google.auth.transport.requests.Request()

  id_info = id_token.verify_oauth2_token(
    id_token=credentials._id_token,
    request=token_request,
    audience=GOOGLE_CLIENT_ID,
    clock_skew_in_seconds = 300
  ) 

  existing_user = User.query.filter_by(google_id=id_info.get("sub")).first()

  if not existing_user:
    # Create a new user in the database using Google-authenticated data
    new_user = User(
        username=id_info.get("sub"),  # You can use the Google sub as the username
        full_name=id_info.get("name"),
        email_address=id_info.get("email"),
        google_id=id_info.get("sub"),  # Store Google ID for future reference
        profile_picture_url=id_info.get("picture"),
        Created_at = datetime.utcnow().replace(tzinfo=pytz.UTC).astimezone(pytz.timezone('Asia/Kolkata')),
        last_login = datetime.utcnow().replace(tzinfo=pytz.UTC).astimezone(pytz.timezone('Asia/Kolkata')),
        is_verified = True
        )
    db.session.add(new_user)
    db.session.commit()
    new_user.update_last_login()

  else: 
    existing_user.update_last_login()


  session["google_id"] = id_info.get("sub")
  session["name"] = id_info.get("name")
  session["Email_id"] = id_info.get("email")
  session["Picture_url"] = id_info.get("picture")
  session["First_Name"] = id_info.get("given_name")
  session["Last_Name"] = id_info.get("family_name")

  print(session["Email_id"])
  print(session["Picture_url"])
  print(session["First_Name"])

  return redirect("/Google_Wait")