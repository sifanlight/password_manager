import json
from os import system
import getpass
import random
import string
from Crypto.Hash import SHA256
from Login import userLogin
from userUI import returnPassword
from userUI import addPassword
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import base64

clear = lambda: system('clear')

def userRegister():
    flag = 1
    #   Checking if the username is unique or not
    while (flag):
        print("Please enter a unique username:", end = " ")
        newUser = input()
        with open("users.json") as jsonFile:
            users = json.load(jsonFile)
            jsonFile.close()
        if (newUser in users):
            clear()
            print("Sorry, this username already exists. Please enter another username")
            continue
        else:
            flag = 0
    

    #   Getting password from user
    flag = 1
    while (flag):
        passcode = getpass.getpass(prompt="Please enter a password:")
        passcodeCheck = getpass.getpass(prompt="Please enter your password again:")
        if (passcode == passcodeCheck):
            flag = 0
        else:
            print("Error: passwords does not match")


    #   Generating Salt
    random.seed(passcode)
    saltLength = random.randint(12,20)
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(saltLength))

    #   Final passcode that goes for encryption
    passcode = newUser + passcode + password
   
   #    Hashing the digested passcode
    h = SHA256.new()
    passtoByte = str.encode(passcode)
    h.update(passtoByte)
    users[newUser] = h.hexdigest()

    #   Updating JSON file
    with open("users.json","w") as jsonFile:
        json.dump(users, jsonFile)
        jsonFile.close()
    with open("database.json") as jsonFile:
        domains = json.load(jsonFile)
        jsonFile.close()
    domains[newUser] = {}
    with open("database.json","w") as jsonFile:
        json.dump(domains, jsonFile)
        jsonFile.close()


def userPassReset():
    print("Username: ", end="")
    username = input()
    passcode = getpass.getpass(prompt="Enter your old password: ")    
    Authentic = userLogin(username, passcode)
    if (Authentic):
        newPasscode = getpass.getpass(prompt="Enter your new password: ")
        verifyPasscode = getpass.getpass(prompt="Enter your new password again: ")
        if (newPasscode == verifyPasscode):
            with open("users.json") as jsonFile:
                users = json.load(jsonFile)
                jsonFile.close()
            random.seed(newPasscode)
            saltLength = random.randint(12,20)
            characters = string.ascii_letters + string.digits + string.punctuation
            passwordSalt = ''.join(random.choice(characters) for i in range(saltLength))
            newPasscode = username + newPasscode + passwordSalt
            h = SHA256.new()
            passToByte = str.encode(newPasscode)
            h.update(passToByte)
            users[username] = h.hexdigest()
            with open("users.json","w") as jsonFile:
                json.dump(users, jsonFile)
                jsonFile.close()
            with open("database.json") as jsonFile:
                domains = json.load(jsonFile)
                jsonFile.close()
            for domain in domains[username]:
                #   Finding the password 
                random.seed(passcode)
                saltLength = random.randint(12,20)
                characters = string.ascii_letters + string.digits + string.punctuation 
                salt = ''.join(random.choice(characters) for i in range(saltLength))
                saltBinary = str.encode(salt)
                key = PBKDF2(passcode, saltBinary, dkLen=32)
                cipher = AES.new(key, AES.MODE_ECB)
                encryptedPass =  base64.b64decode(domains[username][domain])
                original_data = (unpad(cipher.decrypt(encryptedPass), AES.block_size)).decode("utf-8")
                domainPass = original_data.replace(salt, '')
                #   Encrypting the password
                random.seed(verifyPasscode)
                saltLength = random.randint(12,20)
                characters = string.ascii_letters + string.digits + string.punctuation 
                salt = ''.join(random.choice(characters) for i in range(saltLength))
                saltBinary = str.encode(salt)
                domainPassSalted = domainPass + salt
                key = PBKDF2(verifyPasscode, saltBinary, dkLen=32)
                cipher = AES.new(key, AES.MODE_ECB)
                domainPassSaltedByte = str.encode(domainPassSalted)
                cipherText = cipher.encrypt(pad(domainPassSaltedByte, AES.block_size))
                encoded = base64.b64encode(cipherText)
                domains[username][domain] = encoded.decode('ascii')
            
            #   saving the changes
            with open("database.json","w") as jsonFile:
                json.dump(domains, jsonFile)
                jsonFile.close()
            

