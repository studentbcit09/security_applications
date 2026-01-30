import json
import pyotp
import socket

# Global Constants
_client_passwords = {'student': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'}
_client_secrets = {'student':'GTKWFRVSKAUDK3ER7I7QUB3OCSEV2LSH'}

def validate_password(username, hashed_pwd):
    return _client_passwords[username] == hashed_pwd

def validate_otp(username, otp_string):
    totp = pyotp.TOTP(_client_secrets[username])
    return totp.verify(otp_string)

def auth_server():
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

                
