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

def auth_client():
    hostname = socket.gethostname() 
    port = 12345

    # create the socket and connect to the host via port 12345
    client_socket = socket.socket()
    client_socket.connect((hostname, port))

    # prompt the user to provide a message 
    username = input("Provide a username: ")
    password = getpass.getpass()
    
    num_tries = 5
    valid_pwd = False
    data_map = {'username' : username, 'password' : hash_password(password)}
    
    while not valid_pwd:
        data_string = json.dumps(data_map)
        client_socket.send(data_string.encode())

        resp = client_socket.recv(1024).decode()
        print(resp)
        if not resp:
            print("Server did not respond. Exiting program.")
            client_socket.close()

        if 'SUCCESS' == resp:
            print ("Username and password validated")
            valid_pwd = True
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