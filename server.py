from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector 
import re
# import os
from flask_bcrypt import Bcrypt
app = Flask(__name__)
app.secret_key = 'secret'
#this to encrypt the secret key randomly within the same period the the server is running
# app.secret_key = os.urandom(24)
mysql = MySQLConnector(app, 'wall_login_reg')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
number_check = re.compile(r'^[a-zA-Z]+$')
bcrypt = Bcrypt(app)

@app.route('/')
def index():
	return render_template('/index.html')

@app.route('/login')
def login():
	print "inside login"
	query = 'SELECT message.id, message.messages, message.created_at, users.first_name, users.last_name, users.id as user_id FROM message JOIN users ON message.users_id = users.id'
	get_messages=mysql.query_db(query)

	query = 'SELECT comment.id, comment.comments, comment.created_at, users.first_name, users.last_name, users.id as user_id FROM comment JOIN users ON comment.users_id = users.id'

	get_comments=mysql.query_db(query)


	return render_template('/wall.html', messages=get_messages, comments=get_comments)



@app.route('/register', methods=['POST'])
def register():
	# print "inside register"

	query_email = 'SELECT * FROM users WHERE emails =:emails'

	data_email = {
		'emails' : request.form['emails'],

	}

	user_exist = mysql.query_db(query_email, data_email)
	if user_exist != []:
		flash('Users Exist')
		errrors =True
		return redirect('/')
		
		# return redirect('/login')
		#not sure how to pass this information to the login page
		# return redirect('/login', user_exist=user_exist)

	errors = False
	if len(request.form['first_name']) < 1:
		flash('First name cannot be blank')
		errors = True
	if len(request.form['last_name']) < 1: 
		flash('Last name cannot be blank')
		errors = True

	if len(request.form['emails']) < 1: 
		flash('Email cannot be blank')
		errors = True

	if len(request.form['password']) < 1: 
		flash('Password cannot be blank')
		errors = True

	if len(request.form['con_password']) < 1: 
		flash('Confirmed password cannot be blank')
		errors = True

	if not number_check.match(request.form['first_name']):
		flash('First name can only contain lettters')
		errors = True

	if not number_check.match(request.form['last_name']):
		flash('Last name can only contain lettters')
		errors = True

	if not EMAIL_REGEX.match(request.form['emails']):
		flash('Invalid email')
		errors = True

	if not request.form['password'] > 3: 
		flash('Password must be longer than 8 characters')
		errors = True
	
	if not request.form['password'] == request.form['con_password']:
		flash('Password and Confirmed password dont match')
		errors = True

	if errors:
		return redirect('/')

	if not errors:
		password = request.form['password']
		pw_hash = bcrypt.generate_password_hash(password)
		query = 'INSERT INTO users (first_name, last_name, emails, password, created_at, updated_at) VALUES (:first_name, :last_name, :emails, :password, NOW(), NOW())'

		data = {
			'first_name' : request.form['first_name'],
			'last_name' : request.form['last_name'],
			'emails' : request.form['emails'],
			'password' : pw_hash
		}

		mysql.query_db(query, data)

		query_set = 'SELECT * FROM users WHERE emails =:emails'

		data_email = {
		'emails' : request.form['emails'],
		
		}

		user_exist = mysql.query_db(query_set, data_email)
		session['id'] = user_exist[0]['id']
		print session['id']
		return redirect('/login')


@app.route('/logout')
def logout():
	session.clear()
	return render_template('/index.html')


@app.route('/login_reg', methods=['POST'])
def login_reg():
	errors = False
	if not EMAIL_REGEX.match(request.form['emails']):
		flash("Invalid Email Address!")
		errors = True

	if len(request.form['password']) < 1: 
		flash('Password cannot be blank!')
		errors = True

	if len(request.form['emails']) < 1: 
		flash('Email cannot be blank!')
		errors = True

	if errors:
		return redirect("/")
	else: 
		password = request.form['password']
		login_query = 'SELECT password from users WHERE emails = :emails LIMIT 1'
		user_query = 'SELECT * from users WHERE emails = :emails LIMIT 1'

		data = {
			'emails': request.form['emails']
		}

		login_data = mysql.query_db(login_query, data)
		user_data = mysql.query_db(user_query, data)
		
		if len(login_data) == 1: 
			if 	bcrypt.check_password_hash(login_data[0]['password'], password):
				flash("Successfully Logged In")
				session['id'] = user_data[0]['id']
				
				# print user_data[0]['id']
				return redirect('/login')

		
		flash('Failed to Login!')
		return redirect('/')

@app.route('/messages', methods=['POST'])
def message(): 

	# print request.form
	# print "inside messages"

	"""
	query = "INSERT INTO message (messages, users_id, created_at, updated_at) VALUES ('{}','{}', NOW(), NOW())".format(request.form['messages'],session['id']) 

	"""
	query = "INSERT INTO message (messages, users_id, created_at, updated_at) VALUES (:messages, :users_id, NOW(), NOW())"
	data = {
		"messages" : request.form['messages'],
		"users_id": session['id']
		}
	mysql.query_db(query,data)
	

	# print (query)
	return redirect('/get_messages')

@app.route('/comments', methods=['POST'])
def comment(): 
	# print request.form
	"""
	query = "INSERT INTO comment (comments, users_id, message_id, created_at, updated_at) VALUES ('{}','{}', '{}', NOW(), NOW())".format(request.form['comments'],session['id']) 

	"""
	query = "INSERT INTO comment(comments, message_id, users_id, created_at, updated_at) VALUES (:comments, :message_id, :users_id, NOW(), NOW())"
	data = {
		"comments" : request.form['comments'],
		"message_id":request.form['message_id'],
		"users_id": session['id']

		}
	# print "inside comments"
	mysql.query_db(query,data)
	return redirect('/get_messages')

@app.route('/get_messages')
def get_messages():
	query = 'SELECT message.id, message.messages,message.users_id, message.created_at, users.first_name, users.last_name, users.id as u_id FROM message LEFT JOIN users ON message.users_id = users.id';

	# print 'get_messages'
	get_messages=mysql.query_db(query)
	# print get_messages
	query2 = 'SELECT comment.id, comment.comments,comment.users_id, comment.message_id, comment.created_at, users.first_name, users.last_name, users.id as u_id FROM comment LEFT JOIN users ON comment.users_id = users.id';

	get_comments=mysql.query_db(query2)

	return render_template('/wall.html', messages=get_messages, comments=get_comments)


@app.route('/get_comments')
def get_comments():
	# print 'hello'

	query = 'SELECT comment.id, comment.comments,comment.users_id, comment.created_at, users.first_name, users.last_name, users.id as u_id FROM comment LEFT JOIN users ON comment.users_id = users.id';

	get_comments=mysql.query_db(query)

	return render_template('/wall.html', comments=get_comments)

#this in a working query 
	# print data
	# another_query = "INSERT INTO users (first_name, last_name, emails, password) VALUES (:first_name, :last_name, :emails, :password)"
	# some_data = {
	# 	'first_name' : request.form['first_name'],
	# 	'last_name' : request.form['last_name'],
	# 	'emails' : request.form['emails'],
	# 	'password' : request.form['password'],
	# }
	# user = mysql.query_db(another_query, some_data)
	# print '////'
	# print user
	# mysql.query_db(query, data)
app.run(debug=True)