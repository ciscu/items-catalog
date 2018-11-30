#!/usr/bin/env python2.7
from databasesetup import Base, User, Category, Item
from flask import Flask, jsonify, request, url_for, abort, g, render_template, redirect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from flask_httpauth import HTTPBasicAuth
import json
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response, session as login_session
import requests, random, string

auth = HTTPBasicAuth()
h = httplib2.Http()

# assigning flask object to var
app = Flask(__name__)
# Connect database engine
engine = create_engine('sqlite:///itemscatalog.db?check_same_thread=False')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']


# -----------------------------------------------------------------------#
#                   Routes for the webpages                              #
#------------------------------------------------------------------------#

#                              #
## Routes for Authentication  ##
#                              #


## Sign in window ##

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    # State token to prevent forgery attacks
    if request.method == 'POST':
        if request.form['stateToken'] != login_session['state']:
            return render_template('error.html', errormessage="Invalid state token {} expecting {}".format(request.form['stateToken'],login_session['state']))

        # If username or password are not filled in return error page
        uname = session.query(User).filter_by(username = request.form['username']).first()
        pword = request.form['password']
        if uname is None:
            return render_template('error.html', errormessage="Username not found")
        if uname.verify_password(pword) == False:
            return render_template('error.html', errormessage="Bad password")
        login_session['username'] = uname.username
        login_session['email'] = uname.email
        login_session['picture'] = uname.picture
        login_session['id'] = uname.id
        login_session['providor'] = 'local'
        return redirect(url_for('showCatalog'))
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('signin.html', state=state)


## Register window ##

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['username']
        email = request.form['email']
        password = request.form['password'] # Add hash functionality with CRUD implementation
        newUser = User(username=name, email=email)
        newUser.hash_password(password)

        session.add(newUser)
        session.commit()

        return redirect(url_for('signin'),307)
    return render_template('signup.html')


## Route to log out ##

@app.route('/logout/')
def logout():
    if 'id' in login_session:
        del login_session['username']
        del login_session['email']
        del login_session['id']
        del login_session['picture']
        return redirect(url_for('showCatalog'), 301)
    return render_template('error.html', errormessage="No user logged in")


## Edit user info ##

@app.route('/users/<int:user_id>/edit/', methods=['GET', 'POST'])
def editUserInfo(user_id):
    updatedUser = session.query(User).get(user_id)
    if request.method == 'POST':
        updatedUser.username = request.form['newUserName']
        updatedUser.email = request.form['newUserEmail']
        updatedUser.hash_password(request.form['newUserPassword'])

        session.add(updatedUser)
        session.commit()

        return redirect(url_for('showCatalog'))

    # Only allow user who are signed in, else refer to login
    if 'username' in login_session and user_id == login_session['id']:
        return render_template('editUserInfo.html', user=updatedUser)
    return render_template('signin.html')


## Google sign in ##

@app.route('/gconnect', methods=['GET', 'POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Tokens client ID does not match apps."), 401)
        print "Tokens client ID does not match apps."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if user exists, if not create a new one
    user_id = getUserId(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output
#                                        #
## CRUD opperations on the Catalog page ##
#                                        #

## Main Page ##

@app.route('/')
def redirectCatalog():
    return redirect(url_for('showCatalog'), 301)


@app.route('/catalog/')
def showCatalog():
    categories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template('catalog.html', categories=categories, user=None)
    return render_template('catalog.html', categories=categories, user=login_session)


## Add new category ##

@app.route('/catalog/new/', methods=['GET','POST'])
def createNewCategory():
    if request.method == 'POST':
        name = request.form['newCategoryName']
        dbUpdate = Category(name=name, user_id=login_session['id'])
        session.add(dbUpdate)
        session.commit()
        categories = session.query(Category).all()
        return redirect(url_for('showCatalog'), 301)

    # Only allow user who are signed in, else refer to login
    if 'username' in login_session:
        return render_template('createNewCategory.html')
    return render_template('signin.html')


## Edit existing catergory item ##

@app.route('/catalog/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    category = session.query(Category).get(category_id)
    if request.method == 'POST':
        category.name = request.form['newCategoryValue']
        session.add(category)
        session.commit()
        return redirect(url_for('showCatalog'), 301)

    # Only allow user who owns the category, else refer to login
    if 'username' in login_session and category.user_id == login_session['id']:
        return render_template('editCategory.html', category=category)
    return render_template('signin.html')


## Delete existing catergory item ##

@app.route('/catalog/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    category = session.query(Category).get(category_id)
    if request.method == 'POST':
        session.delete(category)
        session.commit()
        return redirect(url_for('showCatalog'), 301)

    # Only allow user who owns the category, else refer to login
    if 'username' in login_session and category.user_id == login_session['id']:
        return render_template('deleteCategory.html', category=category)
    return render_template('signin.html')


#                                            #
## CRUD opperations on the Individual items ##
#                                            #


## List all items per catergory ##

@app.route('/catalog/<int:category_id>/items/')
def listCategoryItems(category_id):
    category = session.query(Category).get(category_id)
    items = session.query(Item).filter_by(category_id=category_id).all()

    hasEditAccess = False
    if 'username' in login_session and login_session['id'] == category.user_id:
        hasEditAccess = True

    return render_template('listCategoryItems.html', items=items, category=category, hasEditAccess=hasEditAccess)


## Add new item to category ##

@app.route('/catalog/<int:category_id>/items/new/', methods=['GET', 'POST'])
def createNewItem(category_id):
    category = session.query(Category).get(category_id)
    if request.method == 'POST':
        newItem = Item(name = request.form['newCategoryItem'],
        category_id=category_id, user_id=login_session['id'])
        session.add(newItem)
        session.commit()
        return redirect(url_for('listCategoryItems', category_id=category.id),301)

    # Only allow user who owns the category, else refer to login
    if 'username' in login_session and category.user_id == login_session['id']:
        return render_template('createNewItem.html', category = category)
    return render_template('signin.html')


## Edit existing item in catergory ##

@app.route('/catalog/<int:category_id>/items/<int:item_id>/edit/', methods=['GET', 'POST'])
def editItem(category_id, item_id):
    item = session.query(Item).get(item_id)
    if request.method == 'POST':
        item.name = request.form['newItemValue']
        session.add(item)
        session.commit()
        return redirect(url_for('listCategoryItems', category_id=category_id),301)

    # Only allow user who owns the category, else refer to login
    if 'username' in login_session and item.user_id == login_session['id']:
        return render_template('editItem.html', category_id=category_id, item=item)
    return render_template('signin.html')


## Delete existing item in catergory ##

@app.route('/catalog/<int:category_id>/items/<int:item_id>/delete/', methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    item = session.query(Item).get(item_id)
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        return redirect(url_for('listCategoryItems', category_id=category_id), 301)

    # Only allow user who owns the category, else refer to login
    if 'username' in login_session and item.user_id == login_session['id']:
        return render_template('deleteItem.html', category_id=category_id, item=item)
    return render_template('signin.html')

#                                            #
##              API endpoints               ##
#                                            #


# API endpoint for catalog items

@app.route('/catalog/api')
def showCatalogApi():
    catalogItems = session.query(Category).all()
    return jsonify(CatalogItems=[i.serialize for i in catalogItems])

# API endpoit for specific category

@app.route('/catalog/<int:category_id>/items/api/')
def showItemsApi(category_id):
    items = session.query(Item).filter_by(category_id = category_id)
    category = session.query(Category).get(category_id)
    js = [i.serialize for i in items]
    return jsonify([js])

@app.route('/users/api')
def showUsersApi():
    users = session.query(User).all()
    return jsonify(Users=[u.serialize for u in users])


#                                #
##       Helper functions       ##
#                                #

def createUser(login_session):
    newUser = User (name = login_session['username'], email = login_session['email'],
    picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user

def getUserId(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None


if __name__ == '__main__':
    app.secret_key = 'supa_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
