import getpass
import hashlib
import json
import pyotp
import socket
import time

def hash_password(pw):
    """
    Hashes the password using SHA-256 and returns a hex digest of the password.
    
    Args:
        string: The plaintext password

    Returns:
        string: The hashed password hex digest.
    """
    m = hashlib.sha256()
    m.update(pw.encode("utf-8"))
    return m.hexdigest()

def generate_otp(username):
    """
    Generate the one time password for the given username
    
    :param username: The username of the user that requires the OTP
    """
    client_info = json.load(open('users.json'))
    totp = pyotp.TOTP(client_info[username]["otp_secret"])
    print(totp.now())

def generate_otp_client(username):
    """
    Helper function to generate the OTP secret for the given user. Also writes the value into 'users.json'. 
    
    :param username: The username of the user that the secret should be generated for
    """
    with open('users.json') as data:
        client_info = json.load(data)
    client_secret = pyotp.random_base32()
    client_info[username]["otp_secret"] = client_secret
    with open('users.json', "w") as data:
        json.dump(client_info, data, indent=4)

def auth_client():
    """
    Main program for the authorization client
    """
    hostname = socket.gethostname() 
    port = 12345

    # create the socket and connect to the host via port 12345
    client_socket = socket.socket()
    client_socket.connect((hostname, port))

    # prompt the user to provide a message 
    username = input("Provide a username: ")
    password = getpass.getpass()
    
    # number of incorrect password tries before the program exits
    num_tries = 5
    valid_pwd = False
    data_map = {'username' : username, 'password' : hash_password(password)}
    
    while not valid_pwd:
        data_string = json.dumps(data_map)
        client_socket.send(data_string.encode())

        resp = client_socket.recv(1024).decode()
        if not resp:
            print("Server did not respond. Exiting program.")
            client_socket.close()

        if 'SUCCESS' == resp:
            print ("Username and password validated")
            valid_pwd = True
        elif 'INVALID_USER' == resp:
            print("User does not exist. Please try again. Exiting program.")
            client_socket.accept
            exit()
        elif 'FAILED' == resp:
            if 1 == num_tries:
                print("Incorrect password. Attempts to login have been exhausted. Exiting program.")
                client_socket.close()
                exit()
            else:
                num_tries -= 1
                print("Incorrect password. %d attempts left" % num_tries)
                password = hash_password(getpass.getpass())
        else:
            print("Unexpected response from server")
            
    
    otp = input('Please provide the OTP: ')
    client_socket.send(otp.encode())

    resp = client_socket.recv(1024).decode()
    if 'SUCCESS' == resp:
        print("Successful OTP verification.")
    elif 'FAILED':
        print("OTP is incorrect. Exiting program.")
    else:
        print("Unexpected response from server. Connection may be closed.")
    
    client_socket.close()

if __name__ == '__main__':
    auth_client()