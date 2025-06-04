from flask_security.forms import RegisterForm
from wtforms import StringField, PasswordField, validators, ValidationError
from models import User

class ExtendedRegisterForm(RegisterForm):
    username = StringField('Username', [
        validators.DataRequired(),
        validators.Length(min=3, max=20, message='Username must be between 3 and 20 characters'),
        validators.Regexp('^[A-Za-z0-9_]+$', message='Username can only contain letters, numbers, and underscores')
    ])
    
    password_confirm = PasswordField('Confirm Password', [
        validators.DataRequired(),
        validators.EqualTo('password', message='Passwords must match')
    ])
    
    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already exists. Please choose a different one.')