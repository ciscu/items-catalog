# Creating Users

# Authentication
Getting a token
```curl -u Cis:cis -i -X GET http://localhost:8000/token```

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

`curl -i -X POST -H 'content-type: application/json' -d '{"name":"Laure","password":"laure","email":"laure@gmail.com"}' http://localhost:8000/jsonsignup`

# API

You can make an api request of a all the catalogs like so:  
`curl -u username:password -i -X GET http://localhost:8000/catalog/json`

Or make a list of specific
