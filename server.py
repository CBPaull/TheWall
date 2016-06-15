from flask import Flask, render_template, request, redirect, flash, session
from flask.ext.bcrypt import Bcrypt
from mysqlconnection import MySQLConnector
import re
import os
app = Flask(__name__)
bcrypt = Bcrypt(app)


EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
PASS_REGEX = re.compile(r'\d.*[A-Z]|[A-Z].*\d')
mysql = MySQLConnector(app, 'regcheck')

app.secret_key = os.urandom(24)
session['username'] = None


@app.route('/')
# If user is logged in, go to wall index, if user is not logged in, go to login/register page
# wall index displays the most recent 25 messages, comments can be expanded to view comments
def index():
    if 'username' in session:
        user_query = "SELECT * FROM users WHERE username = %s" % session['username']
        info = user_query
        return render_template('index.html', info=info)
    else:
        return render_template('login.html')


@app.route('/message')
# post a new message
def msgpost():
    msginsert_query = "INSERT INTO messages (message, users_id, created_at, updated_at) VALUES (:message, :users.id, NOW(), NOW())"


@app.route('/msgedit')
# commit changes to a message
def msgedit():
    query = "UPDATE messages SET message = :message, updated_at = NOW() WHERE id = :id"


@app.route('/msgdelete')
# only shown if message has not been commented on
# delete message
def msgdelete():
    query = "DELETE FROM messages WHERE id = :id"


@app.route('/comment')
# add comment to a message
# if parent = message
def cmtpost():
    cmtinsert_query = "INSERT INTO comments (comment, users_id, messages_id, created_at, updated_at) VALUES (:message, :users.id, messages.id, NOW(), NOW())"
# if parent = comment
    cmtinsert_query = "INSERT INTO comments (comment, users_id, comments_id, created_at, updated_at) VALUES (:message, :users.id, comments.id, NOW(), NOW())"


@app.route('/cmtedit')
# commit changes to a comment
def cmtedit():
    query = "UPDATE comments SET comment = :comment, updated_at = NOW() WHERE id = :id"


@app.route('/cmtdelete')
# only shown if comment has not been commented on
# delete comment
def cmtdelete():
    query = "DELETE FROM comments WHERE id = :id"


@app.route('/logout')
# ends current session
def logout():
    session.pop('username', None)
    return redirect('/')

@app.route('/login')
# logs user in and returns to index
def login():
    email = request.form['email']
    password = request.form['password']
    user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    query_data = {'id': id, 'email': email}
    user = mysql.query_db(user_query, query_data)   # user will be returned in a list
    if bcrypt.check_password_hash(user[0]['pw_hash'], password):
        session['username'] = user[0]['username']
        return redirect('/')
    else:
        flash("Email or Password is incorrect")
        return redirect('/')


@app.route('/register')
# registers user and returns to index
def users():
    print request.form
    if len(request.form['email']) < 2:
        flash("email cannot be empty!")
        return redirect('/')
    email = request.form['email']
    username = request.form['username']
    email_query = "SELECT email FROM users WHERE email = '%s'" % email
    echeck = mysql.query_db(email_query)
    print echeck
    if echeck:
        flash("Email %s already in use" % email)
        return redirect('/')
    if not EMAIL_REGEX.match(request.form['email']):
        flash("must be a valid email!")
        return redirect('/')
    if len(request.form['username']) < 2:
        flash("username cannot be empty!")
        return redirect('/')
    username_query = "SELECT username FROM users WHERE username = '%s'" % username
    ucheck = mysql.query_db(username_query)
    print ucheck
    if ucheck:
        flash("Username %s already in use" % username)
        return redirect('/')
    if len(request.form['password']) < 8:
        flash("password must be 8 characters or longer!")
        return redirect('/')
    if not PASS_REGEX.match(request.form['password']):
        flash("Password must contain an uppercase letter and a number")
        return redirect('/')
    if not (request.form['password'] == request.form['confirm']):
        flash("password and confirmation password must match")
        return redirect('/')

    password = request.form['password']
    pw_hash = bcrypt.generate_password_hash(password)
    # now we insert the new user into the database
    insert_query = "INSERT INTO users (email, username, pw_hash, created_at, updated_at) VALUES (:email, :username, :pw_hash, NOW(), NOW())"
    query_data = {'email': email, 'username': username, 'pw_hash': pw_hash}
    mysql.query_db(insert_query, query_data)
    session['username'] = username
    return redirect('/')


@app.route('/<username>/edit')
def userdisplay():
    return render_template('user.html', username=session['username'])

@app.route('/<usersname>/')
def useredit():
    print request.form
    if len(request.form['email']) < 2:
        flash("email cannot be empty!")
        return redirect('/')
    email = request.form['email']
    username = request.form['username']
    email_query = "SELECT email FROM users WHERE email = :email"
    data = {'email': email}
    echeck = mysql.query_db(email_query, data)
    print echeck
    if echeck:
        flash("Email %s already in use" % email)
        return redirect('/')
    if not EMAIL_REGEX.match(request.form['email']):
        flash("must be a valid email!")
        return redirect('/')
    if len(request.form['username']) < 2:
        flash("username cannot be empty!")
        return redirect('/')
    username_query = "SELECT email FROM users WHERE username = :username"
    data = {'username': username}
    ucheck = mysql.query_db(username_query, data)
    print ucheck
    if ucheck:
        flash("Username %s already in use" % username)
        return redirect('/')
    query = "UPDATE users SET first_name = :first_name, last_name = :last_name, email = :email, username = :username, updated_at = NOW() WHERE id = :id"
