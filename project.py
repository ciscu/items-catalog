#!/usr/bin/env python2.7k
from databasesetup import Base, User
from flask import Flask, jsonify, request, url_for, abort, g, render_template
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from flask_httpauth import HTTPBasicAuth

import json

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests

# assigning flask object to var
app = Flask(__name__)
# Connect database engine
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()



# -----------------------------------------------------------------------#
#                   Routes for the webpages                              #
#------------------------------------------------------------------------#

#
## Routes for Authentication  ##
#

# Route to login
@app.route('/login')
def login():
    return "This is the page to login"


# Route to log out
@app.route('/logout')
def logout():
    return "This is the page to logout"


#
## CRUD opperations on the main page ##
#

## Main Page ##

@app.route('/')
@app.route('/catalog')
def showCatalog():
    return render_template('catalog.html')

## Add new category ##
@app.route('/catalog/new', methods=['GET','POST'])
def createNewCategory():
    if request.method == 'POST':
        name = request.form['newCategoryName']
        return "Post request received susccesfully message was {}".format(name)
    return render_template('createNewCategory.html')


## Edit existing catergory item ##
@app.route('/catalog/<int:category_id>/edit', methods=['GET', 'POST'])
def editCategory(category_id):
    if request.method == 'POST':
        name = request.form['newCategoryValue']
        return "Post request received susccesfully message was {}and id is {}".format(name, category_id)
    return render_template('editCategory.html', category_id=category_id)


## Delete existing catergory item ##
@app.route('/catalog/<int:category_id>/delete', methods=['GET', 'POST'])
def deleteCategory(category_id):
    if request.method == 'POST':
        return "Post request received susccesfully catalog item {} was deleted".format(category_id)
    return render_template('deleteCategory.html', category_id=category_id)
#
## CRUD opperations on the Individual items ##
#

## See all items per catergory ##

@app.route('/catalog/<int:category_id>/items')
def listCategoryItems(category_id):
    return render_template('listCategoryItems.html', category_id = category_id)

## Add new item to category ##
@app.route('/catalog/<int:category_id>/items/new', methods=['GET', 'POST'])
def createNewItem(category_id):
    if request.method == 'POST':
        item = request.form['newCategoryItem']
        return 'Succesfully created a new item with {}'.format(item)
    return render_template('createNewItem.html', category_id = category_id)


## Edit existing item in catergory ##
@app.route('/catalog/<int:category_id>/items/<int:item_id>/edit', methods=['GET', 'POST'])
def editItem(category_id, item_id):
    if request.method == 'POST':
        item = request.form['newItemValue']
        return 'Succesfully Edited item {} with item id {} and cat id {}'.format(item, item_id, category_id)
    return render_template('editItem.html', category_id=category_id, item_id=item_id)


## Delete existing item in catergory ##
@app.route('/catalog/<int:category_id>/items/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    if request.method == 'POST':
        return "Succesfully deteted item {}".format(item_id)
    return render_template('deleteItem.html', category_id=category_id, item_id=item_id)

#
## User Authentication
#

## Sign in window ##
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        name = request.form['username']
        return "Succesfully signed in with username {}".format(name)
    return render_template('signin.html')

## Register window ##


if __name__ == '__main__':
    app.secret_key = 'supa_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
