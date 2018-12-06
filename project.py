#!/usr/bin/env python2.7
from databasesetup import Base, User, Category, Item
from flask import Flask, jsonify, request, url_for, abort, g, render_template
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, desc
from flask_httpauth import HTTPBasicAuth
import json
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response, redirect, flash, session as login_session
import requests
import random
import string
from redis import Redis
import time
from functools import update_wrapper

#------------------------------------------------------------------------#
#                     Configuration code                                 #
#------------------------------------------------------------------------#

## Shortcuts

# Redis server application to limit the access amounts per IP
redis = Redis()


# HTTP Authentication
auth = HTTPBasicAuth()


#  Extensive lib to do requests
h = httplib2.Http()


# Connecting to the database
engine = create_engine('sqlite:///itemscatalog.db?check_same_thread=False')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Googles client secret file
CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']


# assigning flask object to var
app = Flask(__name__)

# Rate limit Configuration
class RateLimit(object):
    expiration_window = 10

    def __init__(self, key_prefix, limit, per, send_x_headers):
        self.reset = (int(time.time()) // per) * per + per
        self.key = key_prefix + str(self.reset)
        self.limit = limit
        self.per = per
        self.send_x_headers = send_x_headers
        p = redis.pipeline()
        p.incr(self.key)
        p.expireat(self.key, self.reset + self.expiration_window)
        self.current = min(p.execute()[0], limit)

    remaining = property(lambda x: x.limit - x.current)
    over_limit = property(lambda x: x.current >= x.limit)

def get_view_rate_limit():
    return getattr(g, '_view_rate_limit', None)

def on_over_limit(limit):
    return (jsonify({'data': 'You hit the rate limit', 'error': '429'}), 429)

def ratelimit(limit, per=300, send_x_headers=True,
              over_limit=on_over_limit,
              scope_func=lambda: request.remote_addr,
              key_func=lambda: request.endpoint):
    def decorator(f):
        def rate_limited(*args, **kwargs):
            key = 'rate-limit/%s/%s/' % (key_func(), scope_func())
            rlimit = RateLimit(key, limit, per, send_x_headers)
            g._view_rate_limit = rlimit
            if over_limit is not None and rlimit.over_limit:
                return over_limit(rlimit)
            return f(*args, **kwargs)
        return update_wrapper(rate_limited, f)
    return decorator

@app.after_request
def inject_x_rate_headers(response):
    limit = get_view_rate_limit()
    if limit and limit.send_x_headers:
        h = response.headers
        h.add('X-RateLimit-Remaining', str(limit.remaining))
        h.add('X-RateLimit-Limit', str(limit.limit))
        h.add('X-RateLimit-Reset', str(limit.reset))
    return response

## Add rate limiter

@app.route('/ratelimit')
@ratelimit(limit=300, per=30*1)
def stopTheHogs():
    return jsonify({'response': 'this is a rate limited response'})


## Setup HTTP auth decorator

@auth.verify_password
def verify_password(email_or_token, password):
    # Check if it is token
    validToken = User.verify_auth_token(email_or_token)
    if validToken:
        user = session.query(User).filter_by(id = validToken).one()
    else:
        user = session.query(User).filter_by(email = email_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


#------------------------------------------------------------------------#
#                     Routes for the webpages                            #
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
            return render_template('error.html', errormessage="Invalid state token {} expecting {}".format(request.form['stateToken'], login_session['state']))

        # Check if user exists and the password is correct
        user = session.query(User).filter_by(email = request.form['email']).first()
        pword = request.form['password']

        # User does not exist
        if user is None:
            return render_template('error.html', errormessage="Username not found")
        # Password is wrong
        if user.verify_password(pword) == False:
            return render_template('error.html', errormessage="Bad password")

        # Add the Users object paramaters to the session cookie
        login_session['name'] = user.name
        login_session['email'] = user.email
        login_session['picture'] = user.picture
        login_session['id'] = user.id
        login_session['provider'] = 'local'

        # Redirect the user to the mainpage and send message to indicate succes
        flash("Welcome back {}".format(login_session['name']))
        return redirect(url_for('showCatalog'))

    # Render a token and send it with the page to prevent MiM attacks
    state = renderToken(32)
    login_session['state'] = state
    return render_template('signin.html', state=state)


## Register window ##

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Gather the info from the form
        name = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Make sure this account doesnt already exist
        users = session.query(User).filter_by(email=email).first()
        if users is not None:
            return render_template('error.html', errormessage="Users already exists")

        # Create the new user object and add to database
        newUser = User(name=name, email=email, provider='local')
        newUser.hash_password(password)
        flash("New user '{}' Successfully created".format(newUser.name))
        session.add(newUser)
        session.commit()

        return redirect(url_for('showCatalog'))
    return render_template('signup.html')


## Edit user info ##

@app.route('/users/<int:user_id>/edit/', methods=['GET', 'POST'])
def editUserInfo(user_id):
    user = session.query(User).get(user_id)
    if request.method == 'POST':
        # Store the form data into memory
        newEmail = request.form['newUserEmail']
        newName = request.form['newUserName']

        # Hash the password
        user.hash_password(request.form['newUserPassword'])

        # Check if email is altered, if so, check if it already exists
        if user.email != newEmail:
            findEmail = session.query(User).filter_by(email=newEmail).first()
            if findEmail is not None:
                return render_template('error.html', errormessage="Email address: {} already in use".format(findEmail.email))

        user.name = newName
        user.email = newEmail

        session.add(user)
        session.commit()

        login_session['name'] = user.name
        login_session['email'] = user.email

        flash("User '{}' successfully updated".format(newName))
        return redirect(url_for('showCatalog'))

    # Only allow user who are signed in, else refer to login
    if 'name' in login_session and user_id == login_session['id']:
        return render_template('editUserInfo.html', user=login_session)
    state = renderToken(32)
    login_session['state'] = state
    return render_template('signin.html', state=state)


## Google sign in ##

@app.route('/gconnect', methods=['GET', 'POST'])
def gconnect():
    print(request.data)
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

    login_session['name'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    flash("Logged is as {}".format(login_session['name']))
    # See if user exists, if not create a new one
    user_id = getUserId(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['id'] = user_id
    return "Successfully logged in with Google"


## Facebook sign in ##

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('invalid state parameter'), 401)
        response.headers['content-type'] = 'application/json'
        return response
    access_token = request.data

    # Exchange the short lived token for a long lived token
    # Read the app id and secret from the json file
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']

    # Exchange short term for long term token
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    access_token = (json.loads(result))['access_token']

    # Query Facebook API to get user credentials
    url = 'https://graph.facebook.com/v3.2/me?access_token=%s&fields=name,id,email,picture.width(200).height(200)' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['provider'] = 'facebook'
    login_session['name'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']
    login_session['picture'] = data['picture']['data']['url']

    # See if user exists, if not create a new one
    user_id = getUserId(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['id'] = user_id
    flash("Welcome back {}".format(login_session['name']))
    return "Susccesfully logged user in with facebook"


## Route to log out ##

@app.route('/logout/')
def logout():
    if 'id' in login_session:

        ## Facebook disconnect
        if login_session['provider'] == 'facebook':
            facebook_id = login_session['facebook_id']
            url = 'https://graph.facebook.com/{}/permissions'.format(facebook_id)
            h = httplib2.Http()
            result = h.request(url, 'DELETE')[1]
            del login_session['name']
            del login_session['email']
            del login_session['picture']
            del login_session['id']
            del login_session['facebook_id']
            flash("Logged out successfully")
            return redirect(url_for('showCatalog'))


        ## Google disconnect
        if login_session['provider'] == 'google':
            access_token = login_session.get('access_token')
            if access_token is None:
                print 'Access Token is None'
                response = make_response(json.dumps('Current user not connected.'), 401)
                response.headers['Content-Type'] = 'application/json'
                return response
            url = 'https://accounts.google.com/o/oauth2/revoke?token={}'.format(access_token)
            h = httplib2.Http()
            result = h.request(url, 'POST')[0]
            if result['status'] == '200':
                del login_session['access_token']
                del login_session['gplus_id']
                del login_session['name']
                del login_session['email']
                del login_session['picture']
                del login_session['id']
                response = make_response(json.dumps('Successfully disconnected.'), 200)
                response.headers['Content-Type'] = 'application/json'
                flash("Logged out successfully")
                return redirect(url_for('showCatalog'))
            else:
                response = make_response(json.dumps('Failed to revoke token for given user.', 400))
                response.headers['Content-Type'] = 'application/json'
                return response


        ## Local user disconnect
        elif login_session['provider'] == 'local':
            del login_session['name']
            del login_session['email']
            del login_session['id']
            del login_session['picture']
            flash("Logged out successfully")
            return redirect(url_for('showCatalog'))


    return render_template('error.html', errormessage="No user logged in")


#                                        #
## CRUD opperations on the Catalog page ##
#                                        #

## Main Page ##

# redirect users to /catalog
@app.route('/')
def redirectCatalog():
    return redirect(url_for('showCatalog'), 301)


@app.route('/catalog/')
def showCatalog():
    # Query the categories and the 6 last create items
    categories = session.query(Category).all()
    items = session.query(Item).order_by(desc(Item.id)).limit(6)

    # Present different pages based on if user is logged in or not
    # User is not logged in
    if 'name' not in login_session:
        return render_template('catalog.html', items=items, categories=categories, user=None)

    # User is logged in
    return render_template('catalog.html', title="Catalog", items=items, categories=categories, user=login_session)


## Add new category ##

@app.route('/catalog/new/', methods=['GET', 'POST'])
def createNewCategory():
    if request.method == 'POST':
        name = request.form['newCategoryName']

        # Check if name already exist
        if session.query(Category).filter_by(name = name).first() is not None:
            return render_template('error.html', errormessage="Catergory with the name {} already exists".format(name))

        dbUpdate = Category(name=name, user_id=login_session['id'])
        session.add(dbUpdate)
        session.commit()
        flash("New category '{}' created".format(name))
        return redirect(url_for('showCatalog'), 301)

    # Only allow user who are signed in, else refer to login
    if 'name' in login_session:
        return render_template('createNewCategory.html', user=login_session)
    state = renderToken(32)
    login_session['state'] = state
    return render_template('signin.html', state=state)


## Edit existing catergory item ##

@app.route('/catalog/<string:category_name>/edit/', methods=['GET', 'POST'])
def editCategory(category_name):
    category = session.query(Category).filter_by(name = category_name).first()
    if request.method == 'POST':
        # Check if name already exist
        if session.query(Category).filter_by(name = request.form['newCategoryValue']).first() is not None:
            return render_template('error.html', errormessage="Catergory with the name {} already exists".format(request.form['newCategoryValue']))
        flash("Category updated from '{}' to '{}'".format(category.name, request.form['newCategoryValue']))
        category.name = request.form['newCategoryValue']

        session.add(category)
        session.commit()

        return redirect(url_for('showCatalog'), 301)

    # Only allow user who owns the category, else refer to login
    if 'name' in login_session and category.user_id == login_session['id']:
            return render_template('editCategory.html', category=category, user=login_session)

    state = renderToken(32)
    login_session['state'] = state
    return render_template('signin.html', state=state)


## Delete existing catergory item ##

@app.route('/catalog/<string:category_name>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_name):
    category = session.query(Category).filter_by(name = category_name).first()
    items = session.query(Item).filter_by(category_id = category.id).all()
    if request.method == 'POST':
        session.delete(category)
        session.commit()
        flash("Category '{}' removed".format(category.name))
        for item in items:
            session.delete(item)
            session.commit()
        return redirect(url_for('showCatalog'), 301)

    permissions = {}
    if 'name' in login_session and login_session['id'] == category.user_id:
        permissions['editAccess'] = True

    if 'name' in login_session:
        permissions['userPresent'] = True
    else:
        permissions['userPresent'] = False
    # Only allow user who owns the category, else refer to login
    if 'id' in login_session and category.user.id == login_session['id']:
        return render_template('deleteCategory.html', category=category, user=login_session, permissions=permissions)
    state = renderToken(32)
    login_session['state'] = state
    return render_template('signin.html', state=state)


#                                            #
## CRUD opperations on the Individual items ##
#                                            #


## List all items per catergory ##

@app.route('/catalog/<string:category_name>/items/')
def listCategoryItems(category_name):
    category = session.query(Category).filter_by(name = category_name).one()
    items = session.query(Item).filter_by(category_id = category.id).all()

    # This dict decides if the user can see the edit button bases on if he is logged in or not
    permissions = {}
    if 'name' in login_session and login_session['id'] == category.user_id:
        permissions['editAccess'] = True

    if 'name' in login_session:
        permissions['userPresent'] = True
    else:
        permissions['userPresent'] = False
    return render_template('listCategoryItems.html', items=items, category=category, user=login_session, permissions=permissions)


## List details of item ##

@app.route('/catalog/<string:category_name>/items/<string:item_name>/')
def listItem(item_name, category_name):
    item = session.query(Item).filter_by(name = item_name).first()
    # category = session.query(Category).filter_by('')
    # This bool decides if the user can see the edit button bases on if he is logged in or not
    permissions = {'hasEditAccess': False}
    if 'name' in login_session and login_session['id'] == item.user.id:
        permissions['hasEditAccess'] = True

    if 'name' in login_session:
        permissions['userPresent'] = True
    else:
        permissions['userPresent'] = False

    return render_template('listItem.html', item=item, category_name=category_name, user=login_session, permissions=permissions)


## Add new item to category ##

@app.route('/catalog/<string:category_name>/items/new/', methods=['GET', 'POST'])
def createNewItem(category_name):
    category = session.query(Category).filter_by(name = category_name).first()
    if request.method == 'POST':
        newItem = Item(name = request.form['newCategoryItem'],
        category_id=category.id, user_id=login_session['id'],
        description=request.form['newDescription'])
        session.add(newItem)
        session.commit()
        flash("Item '{}' created".format(newItem.name))
        return redirect(url_for('listCategoryItems', category_name=category.name), 301)


    permissions = {}
    if 'name' in login_session:
        permissions['userPresent'] = True
    else:
        permissions['userPresent'] = False
    # Only allow user who owns the category, else refer to login
    if 'name' in login_session and category.user_id == login_session['id']:
        return render_template('createNewItem.html', category=category, user=login_session, permissions=permissions)

    state = renderToken(32)
    login_session['state'] = state
    return render_template('signin.html', state=state)


## Edit existing item in catergory ##

@app.route('/catalog/<string:category_name>/items/<string:item_name>/edit/', methods=['GET', 'POST'])
def editItem(item_name, category_name):
    item = session.query(Item).filter_by(name = item_name).first()
    if request.method == 'POST':
        item.name = request.form['newItemValue']
        item.description = request.form['newDescription']
        session.add(item)
        session.commit()
        flash("Item '{}' updated".format(item.name))
        return redirect(url_for('listCategoryItems', category_name=category_name), 301)

    # Check is user is present or not
    # To check login button status
    permissions = {}
    if 'name' in login_session:
        permissions['userPresent'] = True
    else:
        permissions['userPresent'] = False

    # Only allow user who owns the category, else refer to login
    if 'name' in login_session and item.user_id == login_session['id']:
        return render_template('editItem.html', item=item, user=login_session, permissions=permissions)
    state = renderToken(32)
    login_session['state'] = state
    return render_template('signin.html', state=state)


## Delete existing item in catergory ##

@app.route('/catalog/<string:category_name>/items/<string:item_name>/delete/', methods=['GET', 'POST'])
def deleteItem(category_name, item_name):
    item = session.query(Item).filter_by(name = item_name).first()
    if request.method == 'POST':
        flash("Item '{}' removed".format(item.name))
        session.delete(item)
        session.commit()
        return redirect(url_for('listCategoryItems', category_name=category_name), 301)

    permissions = {}
    if 'name' in login_session:
        permissions['userPresent'] = True
    else:
        permissions['userPresent'] = False
    # Only allow user who owns the category, else refer to login
    if 'name' in login_session and item.user_id == login_session['id']:
        return render_template('deleteItem.html', category_name=category_name, item=item, permissions=permissions)
    state = renderToken(32)
    login_session['state'] = state
    return render_template('signin.html')


#                                            #
##              API endpoints               ##
#                                            #


## Endpoint to request token for Authentication

@app.route('/token')
@auth.login_required
def getAuthToken():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


## API endpoint for catalog items

@app.route('/catalog/json')
@auth.login_required
@ratelimit(limit=300, per=30*1)
def showCatalogApi():
    catalogItems = session.query(Category).all()

    return jsonify(CatalogItems=[i.serialize for i in catalogItems])


## Creating catalog items

@app.route('/catalog/jsonnew', methods=['POST'])
@auth.login_required
@ratelimit(limit=300, per=30*1)
def createJsonCategory():
    newCatName = request.json.get('name')
    user = session.query(User).filter_by(email=request.json.get('email')).first()
    newCat = Category(name=newCatName, user_id=user.id)
    session.add(newCat)
    session.commit()
    response = make_response(json.dumps('User {} removed successfully'.format(newCatName)), 200)
    response.headers['content-type'] = 'application/json'
    return response

## API endpoint for specific category

@app.route('/catalog/<string:category_name>/items/json')
@auth.login_required
@ratelimit(limit=300, per=30*1)
def showItemsApi(category_name):
    category = session.query(Category).filter_by(name = category_name).one()
    items = session.query(Item).filter_by(category_id = category.id).all()
    return jsonify([i.apiMachine for i in items])


## API endpoint for specific item

@app.route('/catalog/<string:category_name>/items/<string:item_name>/json')
@auth.login_required
@ratelimit(limit=300, per=30*1)
def showItemApi(category_name, item_name):
    category = session.query(Category).filter_by(name = category_name).one()
    items = session.query(Item).filter_by(name = item_name, category_id=category.id).all()
    return jsonify([i.serialize for i in items])

## Listing users

@app.route('/users/json')
@auth.login_required
@ratelimit(limit=300, per=30*1)
def showUsersApi():
    users = session.query(User).all()
    return jsonify(Users=[u.serialize for u in users])


## Register user trough json post ##

@app.route('/jsonsignup', methods=['POST'])
@auth.login_required
def jsonsignup():
    # Store json parameters in memory
    user = request.json.get('name')
    password = request.json.get('password')
    email = request.json.get('email')

    # Check if json paramaters are Valid
    if user is None or password is None or email is None:
        abort(400)

    # Check if user already exists
    if session.query(User).filter_by(email=email).first() is not None:
        abort(400)

    # Store user credentials in database
    newUser = User(name=user, email=email, provider="json")
    newUser.hash_password(password)
    session.add(newUser)
    session.commit()
    return jsonify({'username': newUser.name})


## Deleting users via json

@app.route('/jsondelete', methods=['POST'])
@auth.login_required
def jsonDelete():
    id = request.json.get('id')
    user = session.query(User).get(id)
    username = user.name

    session.delete(user)
    session.commit()

    response = make_response(json.dumps('User {} removed successfully'), 200)
    response.headers['content-type'] = 'application/json'
    return response


## Check Password ##

@app.route('/jsoncheck', methods=['GET'])
def checker():
    print(request.json.get('email'))
    user = session.query(User).filter_by(email=request.json.get('email')).first()
    if not user.verify_password(request.json.get('password')):
        response = make_response(json.dumps('Credentials not good, bad!'), 401)
        response.headers['content-type'] = 'application/json'
        return response

    response = make_response(json.dumps('User verified'), 200)
    response.headers['content-type'] = 'application/json'
    return response

#                                #
##       Helper functions       ##
#                                #


# Create a user from an Oauth login

def createUser(login_session):
    newUser = User(name=login_session['name'], email=login_session['email'],
    picture = login_session['picture'], provider=login_session['provider'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Returns User class object

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Returns user id with email as given arguments

def getUserId(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Renders random size token

def renderToken(size):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(size))


if __name__ == '__main__':
    app.secret_key = renderToken(32)
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
