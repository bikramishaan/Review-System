from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import Length,EqualTo, Email, DataRequired, ValidationError
from Event.models import User
from flask_wtf.recaptcha import RecaptchaField

class RegisterForm(FlaskForm):
    def validate_username(self, username_to_check):
        user = User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a different username')

    def validate_email_address(self, email_address_to_check):
        email_address = User.query.filter_by(email_address=email_address_to_check.data).first()
        if email_address:
            raise ValidationError('Email Address already exists! Please try a different email address.')

    username = StringField(label='User Name:', validators=[Length(min=2, max=30), DataRequired()])
    full_name = StringField(label='Full Name:', validators=[Length(min=2, max=50), DataRequired()])
    email_address = StringField(label='Email Address:', validators=[Email(), DataRequired()])
    password1 = PasswordField(label='Password:', validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label='Confirm Password:', validators=[EqualTo('password1'), DataRequired()])
    recaptcha = RecaptchaField(render_kw = {'data-sitekey': '6LdCjhAoAAAAAEaLtoMUXZe9Z1Ax0UwCF7qP3gD0'}) 
    submit = SubmitField(label='Create Account')

class LoginForm(FlaskForm):
    username = StringField(label="User Name:", validators=[DataRequired()])
    password = PasswordField(label="Password:", validators=[DataRequired()])
    submit = SubmitField(label='Sign In')

class UploadFileForm(FlaskForm):
    file = FileField("File", validators=[DataRequired()])
    submit = SubmitField("Upload File")

    