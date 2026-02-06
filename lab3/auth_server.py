import json
import pyotp
import socket

def validate_password(username, hashed_pwd):
    """
    Validate the password for the given user
    
    :param username: The user providing the password 
    :param hashed_pwd: The hashed password provided by the client
    """
    with (open('users.json')) as data:
        client_info = json.load(data)
    return client_info[username]["password"] == hashed_pwd

def validate_otp(username, otp_string):
    """
    Validate the OTP provided using the secret for the given username.
    
    :param username: The user providing the OTP
    :param otp_string: The OTP provided by the user
    """
    with (open('users.json')) as data:
        client_info = json.load(data)
    totp = pyotp.TOTP(client_info[username]["otp_secret"])
    return totp.verify(otp_string)

def auth_server():
    """
    Main program for the authorization server
    """
    # retrieve the hostname of the machine
    hostname = socket.gethostname()
    # static assigned port for the socket server based on requirements
    port = 12345

    server_socket = socket.socket()
    server_socket.bind((hostname, port))
    
    server_socket.listen(1)

    while True:
        conn, addr = server_socket.accept()

        with conn:
            validated_user = False
            username = None

            while True: 
                try:
                    data = conn.recv(1024).decode()
                    if data:
                        if not validated_user:
                            user_info = json.loads(data)
                            username = user_info['username']
                            if username not in user_info:
                                print("User %s does not exist in system." % username)
                                return_msg = "INVALID_USER"
                                conn.send(return_msg.encode())
                                break
                            if validate_password(username, user_info['password']):
                                print("User %s authenticated using password. Waiting for OTP." % username)
                                return_msg = "SUCCESS"
                                validated_user = True
                            else: 
                                print("User %s has entered an incorrect password." % username)
                                return_msg = "FAILED"
                            
                            conn.send(return_msg.encode())
                        else:
                            if validate_otp(username, data):
                                print ("OTP verification successful for user %s" % username)
                                return_msg = "SUCCESS"
                            else:
                                print ("OTP incorrect for user %s" % username)
                                return_msg = "FAILED"
                            conn.send(return_msg.encode())
                            break
                    else:
                        break
                except ConnectionResetError:
                    print("Client closed the connection")
                    break

if __name__ == '__main__':
    auth_server()

                
