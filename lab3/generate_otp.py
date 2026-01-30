import pyotp

# Global constants
_client_secrets = {'student':'GTKWFRVSKAUDK3ER7I7QUB3OCSEV2LSH'}

totp = pyotp.TOTP(_client_secrets['student'])
print(totp.now())
