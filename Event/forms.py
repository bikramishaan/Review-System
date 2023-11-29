from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, IntegerField, SelectField, DateTimeField
from wtforms.validators import Length,EqualTo, Email, DataRequired, ValidationError, NumberRange
from Event.models import User, Event
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
    role = SelectField(label="Role:", choices=[('','Select Role'), ('participant', 'Participant'), ('organizer', 'Organizer')], validators=[DataRequired()])
    submit = SubmitField(label='Sign In')

class AdminForm(FlaskForm):
    username = StringField(label="User Name:", validators=[DataRequired()])
    password = PasswordField(label="Password:", validators=[DataRequired()])
    submit = SubmitField(label='Sign In')

class UploadFileForm(FlaskForm):
    file = FileField("File", validators=[DataRequired()])
    submit = SubmitField("Upload File")

class InviteLinks(FlaskForm):
    number = IntegerField(
        label="Enter here:", 
        validators=[
            DataRequired(message="This field is required."),
            NumberRange(min=1, max=999, message='Value must be between 1 and 999.')
        ]
    )
    submit = SubmitField(label="Generate Links")

class EventForm(FlaskForm):
    category = SelectField(label="Category:", choices=[('conference', 'Conference'), ('journal', 'Journal')], validators=[DataRequired()])
    title = StringField(label="Title:", validators=[DataRequired()])
    acronym = StringField(label="Acronym:", validators=[DataRequired()])
    web_page_url = StringField(label="Web Page:", validators=[DataRequired()])
    venue = StringField(label="Venue:")
    city = StringField(label="City:", validators=[DataRequired()])
    country = SelectField(label="Country:", choices=[('India', 'India'), ('china', 'China')], validators=[DataRequired()])
    first_day = DateTimeField(label="First day:", format='%Y-%M-%D %H:%M:%S', validators=[DataRequired()])
    last_day = DateTimeField(label="Last day:", format='%Y-%M-%D %H:%M:%S', validators=[DataRequired()])
    primary_area = SelectField(label="Primary area:", choices=[('biological sciences', 'Biological Sciences'), ('technology', 'Technology')], validators=[DataRequired()])
    secondary_area = SelectField(label="Secondary area:", choices=[('biological sciences', 'Biological Sciences'), ('technology', 'Technology')], validators=[DataRequired()])
    area_notes = StringField(label="Area notes:", validators=[DataRequired()])
    organizer_name = StringField(label="Organizer:", validators=[DataRequired()])
    organizer_web_page = StringField(label="Organizer Web page:", validators=[DataRequired()])
    phone_no = StringField(label="Contact Phone number:", validators=[DataRequired()])
    other_info = StringField(label="Any other infromation:", validators=[DataRequired()])
    submit = SubmitField(label='Send Request')