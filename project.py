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
import requests

auth = HTTPBasicAuth()


# assigning flask object to var
app = Flask(__name__)
# Connect database engine
engine = create_engine('sqlite:///itemscatalog.db?check_same_thread=False')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# -----------------------------------------------------------------------#
#                   Routes for the webpages                              #
#------------------------------------------------------------------------#

#                              #
## Routes for Authentication  ##
#                              #


## Sign in window ##

@app.route('/signin/', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
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
        return redirect(url_for('showCatalog'))
    return render_template('signin.html')


## Register window ##

@app.route('/signup/', methods=['GET', 'POST'])
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
    if 'username' in login_session and category.user_id == login_session['id']:
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
    return jsonify([{category.name:js}])

@app.route('/users/api')
def showUsersApi():
    users = session.query(User).all()
    return jsonify(Users=[u.serialize for u in users])

if __name__ == '__main__':
    app.secret_key = 'supa_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
