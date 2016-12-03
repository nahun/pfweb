#!/usr/local/bin/python2.7

try:
	from pfweb.config import Config
except ImportError:
	# Try from local directory
	from config import Config

from getpass import getpass

config = Config()

username = ""
while True:
	prompt = 'Enter username: '
	if username != "":
		prompt = 'Enter username [{}]: '.format(username)

	username_input = raw_input(prompt)
	if username_input != "":
		username = username_input

	if username == "":
		print "Username cannot be blank"
		continue

	password1 = getpass('Enter Password: ')
	password2 = getpass('Confirm Password: ')

	if password1 == password2:
		break
	else:
		print "Passwords do not match"

config.create_user(username, password1)

print "User " + username + " created successfully"