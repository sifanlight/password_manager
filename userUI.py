import json
import getpass
import random
import string
from os import system
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
import base64

clear = lambda: system('clear')






def addPassword(newDomain, domainPass,username, passcode):
        # print("Enter domain: ", end="")
        # newDomain = input()
        # domainPass = getpass.getpass(prompt="Enter password: ")
        with open("database.json") as jsonFile:
            domains = json.load(jsonFile)
            jsonFile.close() 
        random.seed(username)
        saltLength = random.randint(12,20)
        characters = string.ascii_letters + string.digits + string.punctuation 
        salt = ''.join(random.choice(characters) for i in range(saltLength))
        # domains[username][newDomain]= domainPass + salt
        saltedDomain = newDomain + salt
        saltedDomainByte = str.encode(saltedDomain)
        h = SHA256.new()
        h.update(saltedDomainByte)

        random.seed(passcode)
        saltLength = random.randint(12,20)
        characters = string.ascii_letters + string.digits + string.punctuation 
        salt = ''.join(random.choice(characters) for i in range(saltLength))
        domainPassSalted = domainPass + salt
        saltBinary = str.encode(salt)
        key = PBKDF2(passcode, saltBinary, dkLen=32)
        cipher = AES.new(key, AES.MODE_ECB)
        domainPassSaltedByte = str.encode(domainPassSalted)
        cipherText = cipher.encrypt(pad(domainPassSaltedByte, AES.block_size))

        encoded = base64.b64encode(cipherText)
        domains[username][h.hexdigest()] = encoded.decode('ascii')

        with open("database.json","w") as jsonFile:
            json.dump(domains, jsonFile)
            jsonFile.close()


def returnPassword(domain, username, passcode):
    # print("Enter domain name: ", end="")
    # domain = input()
    random.seed(username)
    saltLength = random.randint(12,20)
    characters = string.ascii_letters + string.digits + string.punctuation 
    salt = ''.join(random.choice(characters) for i in range(saltLength))
    saltedDomain = domain + salt
    saltedDomainByte = str.encode(saltedDomain)
    h = SHA256.new()
    h.update(saltedDomainByte)
    domainHash = (h.hexdigest())
    random.seed(passcode)
    saltLength = random.randint(12,20)
    characters = string.ascii_letters + string.digits + string.punctuation 
    salt = ''.join(random.choice(characters) for i in range(saltLength))
    saltBinary = str.encode(salt)
    key = PBKDF2(passcode, saltBinary, dkLen=32)
    cipher = AES.new(key, AES.MODE_ECB)
    with open("database.json") as jsonFile:
        domains = json.load(jsonFile)
        jsonFile.close() 
    if (domainHash in domains[username]):
        encryptedPass =  base64.b64decode(domains[username][domainHash])
        original_data = (unpad(cipher.decrypt(encryptedPass), AES.block_size)).decode("utf-8")
        return original_data.replace(salt, '')
    else:
        return "Error! Domain not found"



def userUI(username, passcode):
    print("Please choose one of the options below:")
    print("1- Add domain and passowrd")
    print("2- Request a passowrd for a domain\n")

    action = input()
    clear()
    if (action == "Add"):
        print("Enter domain: ", end="")
        newDomain = input()
        domainPass = getpass.getpass(prompt="Enter password: ")
        addPassword(newDomain, domainPass, username, passcode)


    if (action == "Request"):
        print("Enter domain name: ", end="")
        domain = input()
        print(returnPassword(domain, username, passcode))
