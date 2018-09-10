from flask import Flask, url_for, redirect, render_template, request, flash, g
from forms import LoginForm, EditForm, UploadForm, Reset_password_email_form, Reset_password_form
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
import datetime
from sqlalchemy.exc import IntegrityError
from flask_login import login_user, logout_user, current_user, login_required, LoginManager, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_uploads import UploadSet, IMAGES, configure_uploads
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
import sys
#flask admin configurations 
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.contrib import sqla
#from flask.ext.babel import Babel

from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer







app = Flask(__name__)

app.config['SECRET_KEY'] = 'adokmdoijuttoshusygysgtfsoawewul66djh///dudhgyd/>>sodjduygdyidyuy'
app.config['WTF_CSRF_ENABLED'] = True
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

#######Flask Uploads configurations#############
TOP_LEVEL_DIR = os.path.abspath(os.curdir)
app.config['UPLOADS_DEFAULT_DEST'] = TOP_LEVEL_DIR + '/static/img/'
app.config['UPLOADS_DEFAULT_URL'] = 'http://localhost:5000/static/img/'
app.config['UPLOADED_IMAGES_DEST'] = TOP_LEVEL_DIR + '/static/img/'
app.config['UPLOADED_IMAGES_URL'] = 'http://localhost:5000/static/img/'
#######Flask Uploads configurations ending#############
app.config['WHOOSH_BASE'] = os.path.join(basedir, 'search.db')

### Email configurations ###
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT '] = 465
# app.config['MAIL_USE_TLS'] = False
# app.config['MAIL_USE_SSL'] = True
# app.config['MAIL_USERNAME'] = 'paysees@gmail.com'
# app.config['MAIL_PASSWORD'] = 'iwantyou65'
# app.config['MAIL_DEFAULT_SENDER '] = 'paysees@gmail.com'

app.config.update(dict(
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 465,
    MAIL_USE_TLS = False,
    MAIL_USE_SSL = True,
    MAIL_USERNAME = 'paysees@gmail.com',
    MAIL_PASSWORD = 'iwantyou65',
    MAIL_DEFAULT_SENDER = 'paysees@gmail.com'
))

mail = Mail(app)

db = SQLAlchemy(app)

#Configure the image uploading via flask-uploads
photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)

#Migration scripts
migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)
#End of migration scripts

#Flask-Login scripts
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
#End of Flask-Login scripts

#initializing app with flask admin
admin = Admin(app)


if sys.version_info >= (3,0):
	enable_search = False 
else:
	enable_search = True 
	import flask_whooshalchemy as whooshalchemy



class User(db.Model,UserMixin):
	__searchable__ = ['business_name1','product_description1','business_location1','search_tags','store_number','city_name']
	id = db.Column(db.Integer, primary_key=True)
	names = db.Column(db.String(100))
	country = db.Column(db.String(50), index=True)
	category = db.Column(db.String(50), index=True)
	email = db.Column(db.String(100),unique=True)
	password = db.Column(db.String(70))
	repeat_password = db.Column(db.String(70))
	registered_on = db.Column(db.DateTime)	
	###First Migration Scripts ###
	business_name1 = db.Column(db.String(50), index=True)
	contact_number1 = db.Column(db.String(50), index=True)
	product_description1 = db.Column(db.Text(), index=True)
	business_location1 = db.Column(db.Text(), index=True)
	search_tags = db.Column(db.String(120),index=True)
	###Second Migration Scripts ###
	image_url = db.Column(db.String(50))
	image_filename = db.Column(db.String(50))
	###Third Migration Scripts ###
	store_number = db.Column(db.String(50))
	city_name = db.Column(db.String(50),index=True)

	def __init__(self, names, country, category, email, password, repeat_password):
		self.names = names
		self.country = country
		self.category = category
		self.email = email
		self.password = password
		self.repeat_password = repeat_password
		self.registered_on = datetime.datetime.utcnow()

	def __repr__(self):
		return '<User %r>' % (self.product_description1) # Needs to create the database again
		
# class MicroBlogModelView(ModelView):
#     can_delete = False  # disable model deletion
#     page_size = 50  # the number of entries to display on the list view

admin.add_view(ModelView(User, db.session))


if enable_search:
    whooshalchemy.whoosh_index(app,User)


#Defining Image Upload form using flask-wtforms
class UploadForm(FlaskForm):
	image = FileField('Image', validators=[FileRequired(), FileAllowed(photos, 'Images only!')])


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))




@app.before_request
def before_request():
    g.user = current_user
    if g.user.is_authenticated:
    	db.session.add(g.user)
    	db.session.commit()

@app.route('/')
def home_page():
	
	return render_template('main.html')


@app.errorhandler(404)
def error_page_404(e):
	return render_template('404.html'),404


@app.errorhandler(500)
def error_page_500(e):
	return render_template('500.html'),500


####Function for sending emails ####
def send_email(subject, recipients, text_body, html_body):
	msg = Message(subject, recipients=recipients)
	msg.body = text_body
	msg.html = html_body
	mail.send(msg)
##ends here##


@app.route('/create_account/', methods=['POST','GET'])
def create_account():

	if request.method == 'POST':
		try:
			## checks to make sure form is submitted with data
			if  request.form['names'] == '' or request.form['country'] == '' or request.form['category'] == ''  or request.form['email'] == '' or request.form['password'] == '' or request.form['repeat_password'] == '':
				field_required_error = 'All fields are required'
				return render_template('create_account.html',field_required_error=field_required_error)
	          ## Ensures passwords match       
			elif request.form['password'] != request.form['repeat_password']: 
				password_must_match_error = 'Passwords must match'
				return render_template('create_account.html',password_must_match_error=password_must_match_error)

			elif request.method == 'GET':
				return render_template('create_account.html')

			elif not request.form['email'].lower().endswith(('@yahoo.com','@gmail.com','@hotmail.com','@outlook.com')):
				email_error = '[ Invalid email! ]'
				return render_template('create_account.html',email_error=email_error)

             ##using the werkzeug.security features to hash our passwords
			first_password_hash = generate_password_hash(request.form['password'],method='sha256') 
			second_password_hash = generate_password_hash(request.form['repeat_password'],method='sha256')

			user = User(request.form['names'], request.form['country'], request.form['category'],  request.form['email'].lower(), first_password_hash,second_password_hash)
			db.session.add(user)
			db.session.commit()
            #sends a message to a new user who registers
			
			# send_email('Registration', 
			# 	        [request.form['email']], 
			# 	        'Thanks for creating a Paysees account', 
			# 	        '<h3>Thanks for creating a Paysees account!</h3>')
            #login a new user
			login_user(user)
			flash('Thanks, account successfully for created')
			return redirect(url_for('create_business_profile'))
		except IntegrityError: #Ensures there are no duplicate Email or phone number
			db.session.rollback()
			flash('ERROR! Email ({}) already exists'.format(request.form['email']))

	return render_template('create_account.html')



@app.route('/login/account', methods=['POST','GET'])
def login():
	form = LoginForm()
	if request.method == 'POST' and form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data.lower()).first()
		if user:
			   ### Ensures passward recieve match that in the database with the werkzeug.security features
			if check_password_hash(user.password,form.password.data):
				login_user(user)
				flash('You are now login, you can now edit and  manage your dashboard')
				return redirect(url_for('dashboard'))

			error = 'Wrong Email or Password, Please Try again'
			return render_template('login_page.html',form=form,error=error)

		error = 'Wrong Email or Password, Please Try again'
		return render_template('login_page.html',form=form,error=error)	
	
	return render_template('login_page.html', form=form)



@app.route('/logout/')
@login_required
def logout():
	flash('You have successfully logout, to login provide the required information below!')
	logout_user()
	return redirect(url_for('login'))



@app.route('/profile/<names>')
@login_required
def profile(names):
	##Checks the database for a name pass submited
	user = User.query.filter_by(names=names).first()
	if user == None: #if name does not exist user is send to the homepage
		flash('This Profile does not exist {}'.format(names))
		return redirect(url_for('dashboard'))
	return render_template('profile.html',user=user)



@app.route('/create/business/profile',methods=['POST','GET'])
@login_required
def create_business_profile():
	#flash('Please editing Your business profile requires you resubmit all information again!')	
	if request.method == 'POST':
		##Ensure that form is submitted with data
		if request.form['business_name1'] == '' or request.form['contact_number1'] == '' or request.form['product_description1'] == '' or request.form['describe_location1'] == '' or request.form['search_tags'] == ''  or request.form['city_name'] == '':

			FieldError = 'All feilds are required,except store or shed number'
			#flash("Please editing Your business profile \
				   #requires you resubmit all information again!")
				   
			return render_template('create_business_profile.html',
				                     FieldError=FieldError
				                   )#closing render_template

        ### Inserts data into the database
		g.user.business_name1 = request.form['business_name1']
		g.user.contact_number1 = request.form['contact_number1']
		g.user.product_description1 = request.form['product_description1']
		g.user.business_location1 = request.form['describe_location1']
		g.user.search_tags = request.form['search_tags'] #list of products and services 
		g.user.store_number = request.form['store_number']
		g.user.city_name = request.form['city_name']

		try:
			db.session.add(g.user)
			db.session.commit()
			flash('Profile successfully created,Upload\
			        a picture of Products or Services'
			      )#closing flash
			#Send user to the upload page to upload a photo
			return redirect(url_for('upload'))
		except:
			flash('Error in creating Business profile')
			return render_template('create_business_profile.html')
	else:
		#request.form['business_name1'] = g.user.business_name1
		#request.form['contact_number1'] = g.user.contact_number1
		#request.form['product_description1'] = g.user.product_description1
		#request.form['describe_location1'] = g.user.business_location1
		#request.form['search_tags'] = g.user.search_tags 
		return render_template('create_business_profile.html')



@app.route('/upload/',methods=['POST','GET'])
@login_required
def upload():
	form = UploadForm() #Image wtf-forms
	if request.method == "POST":
		if form.validate_on_submit():
			filename = photos.save(request.files['image'])
			url = photos.url(filename)
			g.user.image_url = url
			g.user.image_filename = filename
			db.session.add(g.user)
			db.session.commit()
			flash('Photo Uploaded Safely!,Click below to see how your profile looks like')
			return redirect(url_for('dashboard'))
		else:
			url = g.user.image_url
			filename = g.user.image_filename
	return render_template('upload.html',form=form)



@app.route('/user/PAYSEES#ADE@MPTO#989%3#&#PTOCARO2876l123<int:user_id>')
def user(user_id):
	#displays user by user id 
	user = User.query.filter(User.id == user_id).first()
	return render_template('user.html', user=user)


          ##Searching route###

@app.route('/search/', methods=['POST'])
def search():
	if request.form['query'] == '':
		#flash('Cannot search empty form')
		return redirect(url_for('home_page'))
	return redirect(url_for('search_results', 
		                     query= request.form['query']
		                    )#closing url_for
	                )#closing redirect


@app.route('/search_results/<query>')
def search_results(query):
	results = User.query.whoosh_search(query).all()
	return render_template('search_results.html', 
		                    results=results, 
		                    query=query
		                   )#closing redirect

#search form on the search result page
@app.route('/search2/', methods=['POST'])
def search2():
	#Checks to see if form is submitted without any data
	if request.form['query2'] == '':
		#Sflash('Cannot search empty form')
		return render_template('search_results.html')
	return redirect(url_for('search_results', 
		                   query=request.form['query2']
		                   )#closing url_for
	                )#closing redirect


#search form on the user page
@app.route('/search3',methods = ['POST'])
def search3():
	if request.form['query3'] == '':
		return render_template('search_results.html')
	return redirect(url_for('search_results',
		                     query=request.form['query3']
		                    )
		            )
##End of search functions ##

#dashboard route takes user to the dashboard
@app.route('/dashboard/')
@login_required
def dashboard():
	return render_template('dashboard.html')


#Edit product /services route
@app.route('/edit/products/services/',methods=['POST','GET'])
@login_required
def edit_product_services():
	if request.method == 'POST':
		if request.form['edit_product_services'] != '':
			g.user.search_tags = request.form['edit_product_services']
			db.session.add(g.user)
			db.session.commit()
			flash('Your changes have been added')
			return redirect(url_for('dashboard'))
		else:
			return render_template('edit_product_services.html')
			#request.form['edit_product_services'] = g.user.search_tags
	flash('Please editing this requires you to resubmit all information again')
	return render_template('edit_product_services.html',user=user)




@app.route('/about/')
def about():
	return render_template('about.html')

@app.route('/advertise/')
def advertise():
	return render_template('advertise.html')

@app.route('/terms/')
def terms():
	return render_template('terms.html')
@app.route('/privacy/')
def privacy():
	return render_template('privacy.html')

#All contacts will be redirected to our facebook page for now
@app.route('/contact/')
def contact():
	return render_template('contact.html')

@app.route('/how_to_create')
def how_to_create():
	
	return render_template('how_to_create.html')

@app.route('/how_to_search')
def how_to_search():
	return render_template('how_to_search.html')


@app.route('/adminm/')
def admin():
	return render_template('admin.html')

##password reset functions 

def send_password_reset_email(user_email):
	password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

	password_reset_url = url_for(
		'reset_with_token',
		token = password_reset_serializer.dumps(user_email,salt='password-reset-salt'),
		_external=True)

	html = render_template(
		'email_password_reset.html',
		password_reset_url=password_reset_url)

    #sends password reset link to user email 
	send_email('Password Reset Requested', [user_email], 'Thanks', html)



@app.route('/reset_password',methods=['GET','POST'])
def reset_password():
	#users form email 
	form = Reset_password_email_form()
	if form.validate_on_submit():
		try:
			# queries the database for submitted email
			user = User.query.filter_by(email=form.email.data).first_or_404()
		except:
			flash('Invalid email address!', 'error')
			return render_template('reset_password_form_email.html',form=form)

         #checks if email or user exist and if it exist it send the password reset link
		if user:
			send_password_reset_email(user.email)
			flash('Please check your email for a password reset link.', 'success')
		else:
			flash('Invalid email address!', 'error')
			return render_template('reset_password_form_email.html',form=form)

		return redirect(url_for('login'))

	return render_template('reset_password_form_email.html',form=form)


@app.route('/reset_password/<token>',methods=['GET','POST'])
def reset_with_token(token):
	try:
		password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
		email = password_reset_serializer.loads(token, salt='password-reset-salt', max_age=3600)
	except:
		flash('The password reset link is invalid or has expired.', 'error')
		return redirect(url_for('login'))
    
    #new password form 
	form = Reset_password_form()
	if form.validate_on_submit():
		try:
			user = User.query.filter_by(email=email).first_or_404()
		except:
			flash('Invalid email address!', 'error')
			return redirect(url_for('login'))
         
         #encrypting password 
		user.password = generate_password_hash(form.password1.data, method='sha256')
		user.repeat_password = generate_password_hash(form.password2.data, method='sha256')
		db.session.add(user)
		db.session.commit()
		flash('Your password has been updated!', 'success')
		return redirect(url_for('login'))
		
	return render_template('reset_password_with_token.html',form=form,token=token)



@app.route('/all_products')
def all_products():
	products = User.query.all()
	return render_template('all_products.html',products=products)

if __name__ == "__main__":
	app.run(debug=True) 
	