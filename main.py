import random
import cryptography 
import json
from os import system
import getpass
from register import userRegister
from Login import userLogin
from userUI import userUI
from register import userPassReset

clear = lambda: system('clear')

#   Welcome Screen
clear()
print("Welcome! Please select one of the actions below:")
print("1-Register")
print("2-Login")
print("3-Reset Password \n")
firstAction = input()

clear()
#   Handling Registering new user

if (firstAction == "Register"):
    userRegister()
elif (firstAction == "Login"):
    print("Username: ", end="")
    username = input()
    passcode = getpass.getpass(prompt="Password: ")    
    Authentic = userLogin(username, passcode)
    if (Authentic):
        userUI(username, passcode)

elif (firstAction == "Reset"):
    userPassReset()