#!/usr/bin/env python2.7
from databasesetup import Base, User, Category, Item
from flask import Flask, jsonify, request, url_for, abort, g, render_template, redirect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, desc
from flask_httpauth import HTTPBasicAuth
import json
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response, session as login_session
import requests, random, string
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
    return (jsonify({'data':'You hit the rate limit','error':'429'}),429)

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
    return jsonify({'response':'this is a rate limited response'})


## Setup HTTP auth decorator

@auth.verify_password
def verify_password(name_or_token, password):
    # Check if it is token
    validToken = User.verify_auth_token(name_or_token)
    if validToken:
        user = session.query(User).filter_by(id = validToken).one()
    else:
        user = session.query(User).filter_by(name = name_or_token).first()
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
            return render_template('error.html', errormessage="Invalid state token {} expecting {}".format(request.form['stateToken'],login_session['state']))

        # If username or password are not filled in return error page
        uname = session.query(User).filter_by(name = request.form['username']).first()
        pword = request.form['password']
        if uname is None:
            return render_template('error.html', errormessage="Username not found")
        if uname.verify_password(pword) == False:
            return render_template('error.html', errormessage="Bad password")
        login_session['name'] = uname.name
        login_session['email'] = uname.email
        login_session['picture'] = uname.picture
        login_session['id'] = uname.id
        login_session['provider'] = 'local'
        return redirect(url_for('showCatalog'))
    state = renderToken(32)
    login_session['state'] = state
    return render_template('signin.html', state=state)


## Register window ##

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['username']
        email = request.form['email']
        password = request.form['password'] # Add hash functionality with CRUD implementation
        users = session.query(User).filter_by(email=email).first()
        if users is not None:
            return render_template('error.html', errormessage="Users already exists")
        newUser = User(name=name, email=email, provider='local')
        newUser.hash_password(password)

        session.add(newUser)
        session.commit()

        return redirect(url_for('showCatalog'))
    return render_template('signup.html')


## Register user trough json post ##

@app.route('/jsonsignup', methods=['POST'])
def jsonsignup():
    # Store json parameters in memory
    user = request.json.get('name')
    password = request.json.get('password')
    email = request.json.get('password')

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
    return jsonify({ 'username': newUser.name })


## Endpoint to request token for Authentication
@app.route('/token')
@auth.login_required
def getAuthToken():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


## Edit user info ##

@app.route('/users/<int:user_id>/edit/', methods=['GET', 'POST'])
def editUserInfo(user_id):
    user = session.query(User).get(user_id)
    if request.method == 'POST':
        newEmail = request.form['newUserEmail']
        newName = request.form['newUserName']
        user.hash_password(request.form['newUserPassword'])

        # Check if email is altered, if so, check if it already exists
        if user.email != newEmail:
            findEmail = session.query(User).filter_by(email=newEmail).first()
            if findEmail is not None:
                return render_template('error.html', errormessage="Email address: {} already in use".format(findEmail.email))
        user.name = newName
        user.email = newEmail

        # Check if updated email does not already exist

        user.hash_password(request.form['newUserPassword'])

        session.add(user)
        session.commit()

        login_session['name'] = user.name
        login_session['email'] = user.email
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
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id,app_secret,access_token)
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
            return redirect(url_for('showCatalog'))


    return render_template('error.html', errormessage="No user logged in")


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
    items = session.query(Item).order_by(desc(Item.id)).limit(7)
    if 'name' not in login_session:
        return render_template('catalog.html', items=items, categories=categories, user=None)
    return render_template('catalog.html', items=items, categories=categories, user=login_session)


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
    if 'name' in login_session:
        return render_template('createNewCategory.html')
    state = renderToken(32)
    login_session['state'] = state
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
    if 'name' in login_session and category.user_id == login_session['id']:
            return render_template('editCategory.html', category=category)
    state = renderToken(32)
    login_session['state'] = state
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
    if 'name' in login_session and category.user_id == login_session['id']:
        return render_template('deleteCategory.html', category=category)
    state = renderToken(32)
    login_session['state'] = state
    return render_template('signin.html')


#                                            #
## CRUD opperations on the Individual items ##
#                                            #


## List all items per catergory ##

@app.route('/catalog/<int:category_id>/items/')
def listCategoryItems(category_id):
    category = session.query(Category).get(category_id)
    items = session.query(Item).filter_by(category_id=category_id).all()

    # This bool decides if the user can see the edit button bases on if he is logged in or not
    hasEditAccess = False
    if 'name' in login_session and login_session['id'] == category.user_id:
        hasEditAccess = True

    return render_template('listCategoryItems.html', items=items, category=category, hasEditAccess=hasEditAccess)

## List details of item ##

@app.route('/catalog/<int:category_id>/items/<int:item_id>/')
def listItem(item_id, category_id):
    item = session.query(Item).get(item_id)

    # This bool decides if the user can see the edit button bases on if he is logged in or not
    hasEditAccess = False
    if 'name' in login_session and login_session['id'] == item.user_id:
        hasEditAccess = True

    return render_template('listItem.html', item=item, category_id=item.category_id, hasEditAccess=hasEditAccess)

## Add new item to category ##

@app.route('/catalog/<int:category_id>/items/new/', methods=['GET', 'POST'])
def createNewItem(category_id):
    category = session.query(Category).get(category_id)
    if request.method == 'POST':
        newItem = Item(name = request.form['newCategoryItem'],
        category_id=category_id, user_id=login_session['id'],
        description=request.form['newDescription'])
        session.add(newItem)
        session.commit()
        return redirect(url_for('listCategoryItems', category_id=category_id),301)

    # Only allow user who owns the category, else refer to login
    if 'name' in login_session and category.user_id == login_session['id']:
        return render_template('createNewItem.html', category = category)
    state = renderToken(32)
    login_session['state'] = state
    return render_template('signin.html')


## Edit existing item in catergory ##

@app.route('/catalog/<int:category_id>/items/<int:item_id>/edit/', methods=['GET', 'POST'])
def editItem(item_id, category_id):
    item = session.query(Item).get(item_id)
    if request.method == 'POST':
        item.name = request.form['newItemValue']
        item.description = request.form['Description']
        session.add(item)
        session.commit()
        return redirect(url_for('listCategoryItems', category_id=item.category_id),301)

    # Only allow user who owns the category, else refer to login
    if 'name' in login_session and item.user_id == login_session['id']:
        return render_template('editItem.html', item=item)
    state = renderToken(32)
    login_session['state'] = state
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
    if 'name' in login_session and item.user_id == login_session['id']:
        return render_template('deleteItem.html', category_id=category_id, item=item)
    state = renderToken(32)
    login_session['state'] = state
    return render_template('signin.html')


#                                            #
##              API endpoints               ##
#                                            #


## API endpoint for catalog items

@app.route('/catalog/json/')
@auth.login_required
@ratelimit(limit=300, per=30*1)
def showCatalogApi():
    catalogItems = session.query(Category).all()
    return jsonify(CatalogItems=[i.serialize for i in catalogItems])


## API endpoint for specific category

@app.route('/catalog/<int:category_id>/items/json/')
@auth.login_required
@ratelimit(limit=300, per=30*1)
def showItemsApi(category_id):
    items = session.query(Item).filter_by(category_id = category_id)
    name = session.query(Category).get(category_id)
    js = [i.apiMachine for i in items]
    js = [name.name]+js
    return jsonify([js])


## API endpoint for specific item

@app.route('/catalog/<int:category_id>/items/<int:item_id>/json')
@auth.login_required
@ratelimit(limit=300, per=30*1)
def showItemApi(category_id, item_id):
    item = session.query(Item).get(item_id)
    return jsonify([item.serialize])


@app.route('/users/json')
@auth.login_required
@ratelimit(limit=300, per=30*1)
def showUsersApi():
    users = session.query(User).all()
    return jsonify(Users=[u.serialize for u in users])



#                                #
##       Helper functions       ##
#                                #


## Create a user from an Oauth login

def createUser(login_session):
    newUser = User(name = login_session['name'], email = login_session['email'],
    picture = login_session['picture'], provider= login_session['provider'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id


## Returns User class object

def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user


## Returns user id with email as given arguments

def getUserId(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None


## Renders random size token

def renderToken(size):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(size))



if __name__ == '__main__':
    app.secret_key = renderToken(32)
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
