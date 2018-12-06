# Items Catalog web app

## Introduction

This project intent is to create a Python based web server that will ser you
a landing page on which, depending if you are logged in or not,
view, create, edit and delete categories and subsequently category items.

Permission system is setup in a way that only lets you edit or remove categories and
items that you created yourself.

## Site structure


The site structure goes as follows:
```
.localhost:8000/catalog/
|____Log In
| |____Sign Up
|
|____Category 1
| |
| |____Item A
| | |____Description
| |
| |____Item B
| | |____Description
|
|____Category 2
| |
| |____Item A
| | |____Description
| |
| |____Item B
| | |____Description
```

Site visitors can only view items.

Once a user signs in with either the credentials stored in the database
or using Google's or Facebook sign-ins, they can add a category and category items
to their hearts Content.

Creating a new account can be done in 2 ways:
1. Filling in a form on the site by going to `login > Register for new account`
or visiting `/signup`
2. Sending a JSON post request. More info on this in the API section

## Prerequisites

You can satisfy the prerequisites in two ways:

### 1. Using Vagrant and VirtualBox

1. Download and install [Vagrant](https://www.vagrantup.com/downloads.html)
2. Download and install [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
3. Download the Vagrant [Virtual Machine](https://github.com/udacity/fullstack-nanodegree-vm/tree/master/vagrant)
4. In your shell, navigate to the /vagrant directory and enter the command `vagrant up`.
   This will download and install all the necessary dependencies. Be patient, this can take a couple of minutes.
5. In the same folder enter `vagrant ssh`. This will log you in the virtual machine.
6. Everything that exists in the /vagrant folder on your local machine will also
be available in the the virtual machine if you go navigate to `cd /vagrant`
7. Now you can go to the **Starting the server** section below to spin up server.

### 2. Installing prerequisites manually

**Following packages need to be installed:**
- Python 2.7
- flask
- packaging
- oauth2client
- redis
- passlib
- flask-httpauth

You can get these packages by entering the following commands:
```
apt-get -qqy install python python-pip
pip2 install --upgrade pip
pip2 install flask packaging oauth2client redis passlib flask-httpauth
pip2 install sqlalchemy flask-sqlalchemy psycopg2-binary bleach requests
```


## Starting the server
1. Start up the redis server for rate limiting the incoming API requests.
```
regis-server &
# the `&` is to run the service in the background
```

1. Clone the repo on your the machine you want to host on
```
git clone https://github.com/ciscu/items-catalog.git
```
2. Navigate into the items-catalog folder
```
cd items-catalog
```
3. To spin up the server run
```
./project.py
```


## API

The server can provide JSON formatted content on several points on the site
To get the JSON representation of these endpoints, add `json` to the end of the URI

example:
```
http://localhost:8000/catalog/json
```
```
.localhost:8000/catalog/ -> Level 1 API Call
|____Log In
| |____Sign Up
|
|____Category 1 ----------> Level 2 API Call
| |
| |____Item A ------------> Level 3 API Call
| | |____Description
| |
| |____Item B
| | |____Description
|
|____Category 2
| |
| |____Item A
| | |____Description
| |
| |____Item B
| | |____Description
```

### Level 1

This provides a list of all the Categories in the catalog
example:
```
http://localhost:8000/catalog/json
```
```
{
  "CatalogItems": [
    {
      "name": "Category 1"
    }
    {
      "name": "Category 2"
    }
  ]
}
```

### Level 2

This provides a list of the items in specified Categories in the catalog
example:
```
http://localhost:8000/catalog/category%201/json
```

```
[
  {
    "name": "Item A"
  },
  {
    "name": "Item B"
  }
]
```
### Level 3

If provided, this provides detailed description of the item
example:
```
http://localhost:8000/catalog/Category%201/items/Item%20A/json
```

```
[
  {
    "category": "Category 1",
    "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec massa nisl, fringilla ut elementum et, varius placerat dui. Pellentesque tristique elit in mauris viverra malesuada. Vivamus tristique mi auctor enim iaculis posuere. Etiam fermentum, lacus ac consectetur blandit, libero lacus cursus ligula, quis sollicitudin lorem nisl ac nisi. Nullam dictum, ante vitae fringilla vulputate, velit libero mattis felis, in egestas felis magna quis elit. Sed ut tempor elit. Proin aliquam porta euismod. Quisque tempus convallis fermentum. Nam eu enim turpis. Ut aliquam dictum neque, vel tempus risus molestie nec. Curabitur finibus dictum metus, ac accumsan diam ullamcorper et. Sed nisi erat, vehicula vitae augue sed, fermentum iaculis magna. Etiam sit amet nunc sit amet magna pulvinar viverra vel vitae lorem. Curabitur eleifend arcu sit amet faucibus fermentum. Donec et neque ullamcorper, varius odio sit amet, euismod augue",
    "name": "Item A"
  }
]
```

## Accessing API

In order to protect the data it is required to authenticate first by registering
for an account in the local database. Once authenticated you can request a token
for that provides 10 minute access.

### Create a user

#### 1. In the browser
Filling in a form on the site by going to `login > Register for new account` or visiting /signup

#### 2. JSON POST request
Send a request including following parameter:
- name
- password
- email

Example using curl:
```
curl -i -X POST -H 'content-type: application/json' -d '{"name":"foo","password":"bar","email":"foobar@gmail.com"}' http://localhost:8000/jsonsignup
```
If the request is successful you get a JSON response containing your username

```
{
  "username": "foo"
}
```
## Authentication

Once you are registered as a user you can do a GET request any of the 3 JSON endpoints.
If you need to multiple requests you can request a token, this will provide you access for 10 mins.

#### Using username password combination

You can authenticate using username/password combination.
```
curl -u username:password -i -X GET http://localhost:8000/catalog/json
```

#### Using token

##### Requesting a token

An authentication token can be obtained by sending following get request:
```
curl -u foo:bar -i -X GET http://localhost:8000/token
```

If the request is successful you get a JSON response containing your token
```
{
  "token": "eyJhbGciOiJIUzI1NiIsImV4cCI6MTU0MzcwNjIwMSwiaWF0IjoxNTQzNzA1NjAxfQ.eyJpZCI6MX0.nr8_lB0k4IyT4INdA_6RvgHGk2L5hONsxoDRU7eP0s4"
}
```
Now that you have obtained the token you can use it in following fashion
```
curl -u token:blank -i -X GET http://localhost:8000/catalog/json
```
Notice that you leave the password field blank.
