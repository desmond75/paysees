from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_wtf.file import FileField, FileAllowed, FileRequired




class LoginForm(FlaskForm):
	email = StringField('Enter Email',validators=[DataRequired()])
	password = PasswordField('Password',validators=[DataRequired()])



class EditForm(FlaskForm):
	business_name = StringField('Business Name')
	contact_number = StringField('Contact')
	product_description = StringField('Describe Product/Services')
	business_location = StringField('Business Location')

class UploadForm(FlaskForm):
	image = FileField('Image', validators=[FileRequired()])


class Reset_password_email_form(FlaskForm):
	email = StringField('Enter your email',  validators=[DataRequired(),Email()])


class Reset_password_form(FlaskForm):
	password1 = PasswordField('Password',validators=[DataRequired(), EqualTo('password2', message='Passwords must match!')])
	password2 = PasswordField('Repeat Password',validators=[DataRequired()])


