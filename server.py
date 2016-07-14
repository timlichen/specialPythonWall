from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import MySQLConnector
import re
from flask_bcrypt import Bcrypt
app = Flask(__name__)
app.secret_key = "s3cr37k3y"
bcrypt = Bcrypt(app)
mySql = MySQLConnector(app, 'the_wall')

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
number_check = re.compile(r'^[a-zA-Z]+$')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=["POST"])
def registerInfo():
    errFlag = False
    if not number_check.match(request.form['first_name']):
        flash("Only letters allowed")
        errFlag = True
    if len(request.form['first_name']) < 1:
        flash("First Name must be at least 2 characters long")
        errFlag = True
    if not number_check.match(request.form['last_name']):
        flash("Only letters allowed")
        errFlag = True
    if len(request.form['last_name']) < 1:
        flash("First Name must be at least 2 characters long")
        errFlag = True
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Use a valid email address")
        errFlag = True
    if len(request.form['password']) < 1:
        flash("You must enter a password")
        errFlag = True
    if request.form['password'] != request.form['cPassword']:
        flash("Your passwords must match")
        errFlag = True

    if errFlag:
        print "Error Found"
        print errs
        return redirect('/')
    else:
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, NOW(), NOW())"
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'email': request.form['email'],
            'password': pw_hash
        }
        mySql.query_db(query, data)
        flash("Registered Sucessfully")
        return redirect('/')

    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    print "at login"
    query = "SELECT users.id, users.email, users.password FROM users WHERE users.email =  :email LIMIT 1"
    data = {
        'email': request.form['email']
    }
    user = mySql.query_db(query, data)
    password = request.form['password']
    if len(user) > 0:
        if bcrypt.check_password_hash(user[0]['password'], password):
            session['id'] = user[0]['id']
            return redirect('/theWall')
        else:
            flash('Invalid Login')
            return redirect('/')
    else:
        flash('Invalid Login')
        return redirect('/')

    return redirect('/')

# BEGIN WALL LOGIC

@app.route('/theWall')
def theWall():
    print session['id']
    query = "SELECT first_name, last_name FROM users WHERE id = :id"
    data = {
        'id' : session['id']
    }
    user = mySql.query_db(query, data)

    messagesQuery = "SELECT messages.id AS message_id, messages.message, messages.created_at, users.id AS user_id, users.first_name, users.last_name FROM messages LEFT JOIN users on messages.user_id = users.id ORDER BY messages.created_at DESC"
    messages = mySql.query_db(messagesQuery)

    commentsQuery = "SELECT comments.message_id, comments.user_id, comments.comment, comments.created_at, users.first_name, users.last_name FROM comments LEFT JOIN users ON users.id = comments.user_id ORDER BY comments.created_at ASC"
    comments = mySql.query_db(commentsQuery)

    dict = {
        'messages': messages,
        'comments': comments,
        'user': user
    }

    return render_template('wall.html', data = dict)

@app.route('/postMessage', methods=['POST'])
def postMessages():
    print session['id']
    print request.form['message']
    query = "INSERT INTO messages (user_id, message, created_at, updated_at) VALUES (:id, :message, NOW(), NOW())"
    data = {
        'id': session['id'],
        'message': request.form['message']
    }
    mySql.query_db(query, data)
    return redirect('/theWall')

@app.route('/postComment/<messageId>', methods=['POST'])
def postComment(messageId):

    print messageId
    print request.form['comment']
    print session['id']

    query = "INSERT INTO comments (message_id, user_id, comment, created_at, updated_at) VALUES (:mID, :uID, :comment, NOW(), NOW())"

    data = {
        'mID': messageId,
        'uID': session['id'],
        'comment': request.form['comment']
    }

    mySql.query_db(query, data)

    return redirect('/theWall')

# LOGOUT

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

app.run(debug=True)
