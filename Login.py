import getpass
import random
import string
from Crypto.Hash import SHA256
import json
from os import system

clear = lambda: system('clear')

def userLogin(username, passcode):
    
    random.seed(passcode)
    saltLength = random.randint(12,20)
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(saltLength))

    passcode = username + passcode + password
   
    h = SHA256.new()
    passtoByte = str.encode(passcode)
    h.update(passtoByte)

    with open("users.json") as jsonFile:
        users = json.load(jsonFile)
        jsonFile.close()
    clear()
    if (users[username] == h.hexdigest()):
        print("Successfully logged in as:", username)
        return True
    else:
        print("Username or password is incorrect")
        return False
        
