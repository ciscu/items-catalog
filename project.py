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
@app.route('/catalog/new')
def createNewCategory():
    return "This is a route to create new Catalog items"


## Edit existing catergory item ##
@app.route('/catalog/<int:category_id>/edit')
def editCategory(category_id):
    return "This is a route to edit item with id {}".format(category_id)


## Delete existing catergory item ##
@app.route('/catalog/<int:category_id>/delete')
def deleteCategory(category_id):
    return "This is a route to delete item with id {}".format(category_id)

#
## CRUD opperations on the Individual items ##
#

## See all items per catergory ##

@app.route('/catalog/<int:category_id>/items')
def listCategoryItems(category_id):
    return "This page will list out all the items for this category number {}".format(category_id)


## Add new item to category ##
@app.route('/catalog/<int:category_id>/items/new')
def createNewItem(category_id):
    return "This is a route to create new item for catalog {}".format(category_id)


## Edit existing item in catergory ##
@app.route('/catalog/<int:category_id>/items/<int:item_id>/edit')
def editItem(category_id, item_id):
    return "This is a route to edit item with id {}, from category {}".format(item_id,category_id)


## Delete existing item in catergory ##
@app.route('/catalog/<int:category_id>/items/<int:item_id>/delete')
def deleteItem(category_id, item_id):
    return "This is a route to delete item with id {}, from category {}".format(item_id,category_id)








if __name__ == '__main__':
    app.secret_key = 'supa_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
