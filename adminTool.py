import os
import requests, json, urllib, string, getpass
from time import sleep
from requests.auth import HTTPDigestAuth

### FUNCTIONS ###

def getUrl():
    display_title_bar()
    return raw_input("enter url: ")

def mainMenu(hostUrl, credentials):
    display_title_bar()
    print("1. Create users")
    print("2. List users")
    print("3. Remove users")
    print("4. List Categories")
    print("5. Create Category")

    option = input("Enter option: ")
    if option < 1 or option > 5:
        return mainMenu(hostUrl, credentials)

    elif option == 1:
        createUser(hostUrl, credentials)

    elif option == 2:
        listUsers(hostUrl, credentials)

    elif option == 3:
        removeUser(hostUrl, credentials)

    elif option == 4:
        getCategories(hostUrl, credentials)

    elif option == 5:
        createNewCategory(hostUrl, credentials)



# Get username and password
def createUser(hostUrl, credentials):
    display_title_bar()
    name = raw_input("Enter username: ")
    password = getpass.getpass("Enter Password: ")
    email = raw_input("Enter Email: ")

    params = {"name":name,"password":password,"email":email}
    url = hostUrl + "/jsonsignup"
    response = requests.post(url, auth=credentials,json=params)
    createdUser = response.json()
    if response.status_code == 200:
        print("Successfully created user with username {}". format(name))
        sleep(3)
        return mainMenu(hostUrl, credentials)
    else:
        print("Something went wrong")

def removeUser(hostUrl, credentials):
    display_title_bar()
    listUsers(hostUrl, credentials)

    toDelete = raw_input("Remove ID: ")
    # print("press q to go back")
    # if toDelete == 'q':
    #     return mainMenu(credentials)

    params = {'id': int(toDelete)}
    url = hostUrl +"/jsondelete"

    response = requests.post(url, auth=credentials,json=params)

    if response.status_code == 200:
        print("Successfully deleted user with id {}". format(toDelete))
        sleep(1)
        return removeUser(hostUrl, credentials)
    else:
        print("Something went wrong")

def listUsers(hostUrl, credentials):
    display_title_bar()
    users = requests.get((hostUrl+"/users/json"), auth=credentials)
    userList = users.json()
    # print(userList['Users'])
    for user in userList['Users']:
        print("name: \t{} \nemail: \t{} \nID: \t{} \n".format(user['user name'], user['email'], user['user id']))
        # print("user name: {}\n email: {}".format(user[0]['user name'], user[0]['email']))
    while raw_input("q to go back to main menu: ") == 'q':
        return mainMenu(hostUrl, credentials)

def getCredentials(hostUrl):
    display_title_bar()
    email = raw_input("Enter email: ")
    password = getpass.getpass("Enter Password: ")

    params = {"email":email, "password":password}
    url = hostUrl+"/jsoncheck"
    response = requests.get(url, json=params)

    if response.status_code != 200:
        return getCredentials(hostUrl)

    return (email, password)

# Get Categories
def getCategories(hostUrl, credentials):
    display_title_bar()
    categories = requests.get(hostUrl+"/catalog/json", auth=credentials)
    results = categories.json()
    print("Press q to go back")
    for result in enumerate(results['CatalogItems']):
        print("{}: {}".format((result[0]+1), result[1]['name']))
    option = raw_input("Category: ")

    if option == 'q':
        return mainMenu(hostUrl, credentials)

    category = results['CatalogItems'][int(option)-1]['name']
    return listItems(hostUrl, category, credentials)

# Create Category
def createNewCategory(hostUrl, credentials):

    catName = raw_input("New category name: ")
    params = {"name":catName, "email":credentials[1]}
    url = hostUrl+"/catalog/jsonnew"
    response = requests.post(url, auth=credentials,json=params)
    if response.status_code == 200:
        print("Successfully created catergory {}". format(catName))
        sleep(3)
        return mainMenu(hostUrl, credentials)
    else:
        print("Something went wrong")

# Get items/categories
def listItems(hostUrl,category, credentials):
    display_title_bar()
    choice = str(category.replace(" ","%20"))
    url = hostUrl+"/catalog/{}/items/json".format(choice)
    items = (requests.get(url, auth=(credentials))).json()

    for item in enumerate(items):
        print("{}: {}".format( (item[0]+1), item[1]['name']))

    itemToDisplay = raw_input("Selecet item ")
    if itemToDisplay == 'q':
        return getCategories(credentials)
    item = items[int(itemToDisplay)-1]['name']
    return displayItem(category, item, credentials)


# Get description
def displayItem(hostUrl, category, item, credentials):
    display_title_bar()
    categoryChoice = str(category.replace(" ","%20"))
    itemChoice = str(item.replace(" ","%20"))
    url= hostUrl+"/catalog/{}/items/{}/json".format(categoryChoice, itemChoice)

    itemDetails = (requests.get(url, auth=credentials)).json()

    print("Item: {} \n\nDescription: {}".format(itemDetails[0]['name'], itemDetails[0]['description']))
    if raw_input("\nPress q to go back to {}: ".format(category)) == 'q':
        listItems(hostUrl, category, credentials)


# Print titlebar
def display_title_bar():
    # Clears the terminal screen, and displays a title bar.
    os.system('clear')

    print("\t**********************************************")
    print("\t***        Items Catalog admin tool        ***")
    print("\t**********************************************")


### MAIN PROGRAM ###
url = getUrl()
credentials = getCredentials(url)
mainMenu(url, credentials)
