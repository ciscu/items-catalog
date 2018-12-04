# Creating Users

# Authentication
Getting a token
```curl -u foo:bar -i -X GET http://localhost:8000/token```

If all goes well you should receive a response in the form of:


```
{
  "token": "eyJhbGciOiJIUzI1NiIsImV4cCI6MTU0MzcwNjIwMSwiaWF0IjoxNTQzNzA1NjAxfQ.eyJpZCI6MX0.nr8_lB0k4IyT4INdA_6RvgHGk2L5hONsxoDRU7eP0s4"
}
```

This will grant you a token that is valid for 10 minutes

# using the token for Authentication
You can substitute the word token for the actual token you will receive from the server

```
curl -u token:blank -i -X GET http://localhost:8000/catalog/json
```



## Using json post request


You can send a POST request to the server to create a new user
Following fiels need to be satisfied:
- Name
- Password
- Email

Below you will see an example of a curl post request

`curl -i -X POST -H 'content-type: application/json' -d '{"name":"foo","password":"bar","email":"foobar@gmail.com"}' http://localhost:8000/jsonsignup`

# API

There are 3 types of API calls you can do
- List of all the catalogs `http://localhost:8000/catalog/json`
- Items per Category `http://localhost:8000/catalog/1/items/json`
- Single item with description

You can make an api request of a all the catalogs like so:  
`curl -u username:password -i -X GET http://localhost:8000/catalog/json`

Or make a list of specific


# Rate limiting

In order to protect our server from overload i implemented a limiter based on IP address

To activate redis first run `redis-server` on your machine
