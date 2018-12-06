import os
import requests, json, urllib, string
from time import sleep
from requests.auth import HTTPDigestAuth

### FUNCTIONS ###

def loginMenu():
    display_title_bar()
    print("1. Create user")
    print("2. Log in")

    option = input("Enter option: ")
    if option < 1 or option > 2:
        return loginMenu()

    elif option == 1:
        createUser()

    elif option == 2:
        mainMenu()

def mainMenu(credentials):
    display_title_bar()
    print("1. Create users")
    print("2. List users")
    print("3. Remove users")
    print("4. List Categories")
    print("5. Create Category")

    option = input("Enter option: ")
    if option < 1 or option > 5:
        return mainMenu(credentials)

    elif option == 1:
        createUser(credentials)

    elif option == 2:
        listUsers(credentials)

    elif option == 3:
        removeUser(credentials)

    elif option == 4:
        getCategories(credentials)

    elif option == 5:
        createNewCategory(credentials)



# Get username and password
def createUser(credentials):
    display_title_bar()
    name = raw_input("Enter username: ")
    password = raw_input("Enter Password: ")
    email = raw_input("Enter Email: ")

    params = {"name":name,"password":password,"email":email}
    url = "http://localhost:8000/jsonsignup"
    response = requests.post(url, auth=credentials,json=params)
    createdUser = response.json()
    if response.status_code == 200:
        print("Successfully created user with username {}". format(name))
        sleep(3)
        return mainMenu(credentials)
    else:
        print("Something went wrong")

def removeUser(credentials):
    display_title_bar()
    listUsers(credentials)

    toDelete = raw_input("Remove ID: ")
    # print("press q to go back")
    # if toDelete == 'q':
    #     return mainMenu(credentials)

    params = {'id': int(toDelete)}
    url = "http://localhost:8000/jsondelete"

    response = requests.post(url, auth=credentials,json=params)

    if response.status_code == 200:
        print("Successfully deleted user with id {}". format(toDelete))
        sleep(1)
        return removeUser(credentials)
    else:
        print("Something went wrong")

def listUsers(credentials):
    display_title_bar()
    users = requests.get("http://localhost:8000/users/json", auth=credentials)
    userList = users.json()
    # print(userList['Users'])
    for user in userList['Users']:
        print("ID: \t{} \nname: \t{} \nID: \t{} \n".format(user['user name'], user['email'], user['user id']))
        # print("user name: {}\n email: {}".format(user[0]['user name'], user[0]['email']))
    while raw_input("q to go back to main menu: ") == 'q':
        return mainMenu(credentials)

def getCredentials():
    display_title_bar()
    name = raw_input("Enter username: ")
    password = raw_input("Enter Password: ")
    credentials = (name, password)
    return credentials

# Get Categories
def getCategories(credentials):
    display_title_bar()
    categories = requests.get("http://localhost:8000/catalog/json", auth=credentials)
    results = categories.json()
    print("Press q to go back")
    for result in enumerate(results['CatalogItems']):
        print("{}: {}".format((result[0]+1), result[1]['name']))
    option = raw_input("Category: ")

    if option == 'q':
        return mainMenu(credentials)

    category = results['CatalogItems'][int(option)-1]['name']
    return listItems(category, credentials)

# Create Category
def createNewCategory(credentials):

    catName = raw_input("New category name: ")

    # find current users email
    # Query for all the users and store in a list
    users = requests.get("http://localhost:8000/users/json", auth=credentials)
    userList = users.json()
    # Search list for matching username and grab the email address
    gold = ""
    for user in userList['Users']:
        if user['user name'] == credentials[0]:
            gold = user['email']

    params = {"name":catName,"email":gold}
    url = "http://localhost:8000/catalog/jsonnew"
    response = requests.post(url, auth=credentials,json=params)
    if response.status_code == 200:
        print("Successfully created catergory {}". format(catName))
        sleep(3)
        return mainMenu(credentials)
    else:
        print("Something went wrong")




# Get items/categories
def listItems(category, credentials):
    display_title_bar()
    choice = str(category.replace(" ","%20"))
    url = "http://localhost:8000/catalog/{}/items/json".format(choice)
    items = (requests.get(url, auth=(credentials))).json()

    for item in enumerate(items):
        print("{}: {}".format( (item[0]+1), item[1]['name']))

    itemToDisplay = raw_input("Selecet item ")
    if itemToDisplay == 'q':
        return getCategories(credentials)
    item = items[int(itemToDisplay)-1]['name']
    return displayItem(category, item, credentials)


# Get description
def displayItem(category, item, credentials):
    display_title_bar()
    categoryChoice = str(category.replace(" ","%20"))
    itemChoice = str(item.replace(" ","%20"))
    url= "http://localhost:8000/catalog/{}/items/{}/json".format(categoryChoice, itemChoice)

    itemDetails = (requests.get(url, auth=credentials)).json()

    print("Item: {} \n\nDescription: {}".format(itemDetails[0]['name'], itemDetails[0]['description']))
    if raw_input("\nPress q to go back to {}: ".format(category)) == 'q':
        listItems(category, credentials)


# Print titlebar
def display_title_bar():
    # Clears the terminal screen, and displays a title bar.
    os.system('clear')

    print("\t**********************************************")
    print("\t***        Items Catalog admin tool        ***")
    print("\t**********************************************")


### MAIN PROGRAM ###
credentials = getCredentials()
mainMenu(credentials)

# credentials = getCredentials()
# category = getCategories(credentials)

#
# categories = requests.get("http://localhost:8000/catalog/json", auth=("Cis","Cipert88"))
# results = categories.json()
#
# for result in enumerate(results['CatalogItems']):
#     print("{}: {}".format((result[0]+1), result[1]['name']))
#
# option = input("Category: ")
# choice = str((results['CatalogItems'][option-1]['name']).replace(" ","%20"))
# url = "http://localhost:8000/catalog/{}/items/json".format(choice)
# items = (requests.get(url, auth=("Cis","Cipert88"))).json()
#
# for item in enumerate(items):
#     print("{}: {}".format( (item[0]+1), item[1]['name']))
#
# option = input("Item: ")
# itemChoice = str(items[option-1]['name']).replace(" ","%20")
# # choice = str((results['CatalogItems'][option-1]['name']).replace(" ","%20"))
#
# url = "http://localhost:8000/catalog/{}/items/{}/json".format(choice,itemChoice)
# itemDetails = (requests.get(url, auth=("Cis","Cipert88"))).json()
# detail = itemDetails[0]['description']
# print detail

# -------------------------------------------------------------------
# import os

# Greeter is a terminal application that greets old friends warmly,
#   and remembers new friends.


### FUNCTIONS ###
#
# def display_title_bar():
#     # Clears the terminal screen, and displays a title bar.
#     os.system('clear')
#
#     print("\t**********************************************")
#     print("\t***  Greeter - Hello old and new friends!  ***")
#     print("\t**********************************************")
#
# def get_user_choice():
#     # Let users know what they can do.
#     print("\n[1] See a list of friends.")
#     print("[2] Tell me about someone new.")
#     print("[q] Quit.")
#
#     return input("What would you like to do? ")
#
# def show_names():
#     # Shows the names of everyone who is already in the list.
#     print("\nHere are the people I know.\n")
#     for name in names:
#         print(name.title())
#
# def get_new_name():
#     # Asks the user for a new name, and stores the name if we don't already
#     #  know about this person.
#     new_name = input("\nPlease tell me this person's name: ")
#     if new_name in names:
#         print("\n%s is an old friend! Thank you, though." % new_name.title())
#     else:
#         names.append(new_name)
#         print("\nI'm so happy to know %s!\n" % new_name.title())
#
# ### MAIN PROGRAM ###
#
# # Set up a loop where users can choose what they'd like to do.
# names = []
#
# choice = ''
# display_title_bar()
# while choice != 'q':
#
#     choice = get_user_choice()
#
#     # Respond to the user's choice.
#     display_title_bar()
#     if choice == '1':
#         show_names()
#     elif choice == '2':
#         get_new_name()
#     elif choice == 'q':
#         print("\nThanks for playing. Bye.")
#     else:
#         print("\nI didn't understand that choice.\n")
