import hashlib
import json
from PIL import Image
import pyotp
import stepic

from cryptography.fernet import Fernet
import nmap
import socket 
import logging

logger = logging.getLogger(__name__)

class AuthClient:
    HOST_IP = "127.0.0.1"
    SCAN_PORT_START = "400"
    SCAN_PORT_END = "10000"
    TARGET_PORT = 1234

    username = "test_user"
    password = "test_password"


    def get_client_info(self):
        """
        Gets the client info from the stored users.json file.

        Using an encrypted database would be better for access and security.
        If the file or database is corrupted or inaccessible due to adversary actions, 
        the program will gracefully handle the error.

        Raises:
            AuthenticationError: Raises an error if any access or parsing errors occur.

        Returns:
            dict: The object containing user data
        """
        try:
            with (open('users.json')) as data:
                client_info = json.load(data)
                return client_info
        except Exception as e:
            logger.error(e)
            raise AuthenticationError(f"Configuration or database access error: {str(e)}")

    def get_user_info(self, client_info, username, key):
        """
        Attempts to retrieve the key for the user from the client info object.

        If there are configuration issues or corrupted data due to adversary actions, 
        the program will gracefully handle the error.

        Args:
            client_info (dict): All the client info
            username (string): The user to obtain the information for
            key (string): The info key that is needed

        Raises:
            AuthenticationError: Raises an error if the key or value does not exist

        Returns:
            string: The value associated with the key provided for the provided user
        """
        try:
            return client_info[username][key]
        except Exception as e:
            raise AuthenticationError(f"Client Info configuration error: {str(e)}")
        
    def generate_otp(self, username):
        """
        Generate the one time password for the given username
        :param username: The username of the user that requires the OTP
        """
        client_info = self.get_client_info()
        totp = pyotp.TOTP(self.get_user_info(client_info, username, "otp_secret"))
        return totp.now()

    def run_client(self):
        """
        The main function for running the client logic.
        """
        try:
            if not self.port_scanning():
                print(f"Target port {self.TARGET_PORT} on {self.HOST_IP} is closed. Unable to proceed.")
                return

            self.decrypt_image()
            encrypted_file = self.encrypt_file("architect_manifesto.txt", self.username)

            current_socket = socket.socket()
            current_socket.connect((self.HOST_IP, self.TARGET_PORT))

            server_pwd_resp = self.socket_send(self.create_message("authentication", self.create_auth_request_object(is_pwd=True)), current_socket)

            otp_code = self.handle_otp(server_pwd_resp, self.username)

            server_otp_resp = self.socket_send(self.create_message("authentication", self.create_auth_request_object(otp_code=otp_code)), current_socket)

            if "authentication" in server_otp_resp:
                print('OTP was not accepted correctly. Please try again. Exiting.')
                current_socket.close()
                return

            server_data_resp = self.socket_send(self.create_message('data', {'file': encrypted_file},), current_socket)
            print(f'Server response: {server_data_resp['status']}')
            current_socket.close()

        except AuthenticationError as e:
            print(f'Unable to authenticate: {e} Exiting.')
            current_socket.close()


    def handle_otp(self, resp, username):
        if "authentication" not in resp:
            raise AuthenticationError("Incorrect password or error occured while validating password. Please try again.")
        if resp["authentication"]["require_otp"]:
            otp_code = self.generate_otp(username)
            return otp_code
        else:
            raise AuthenticationError("Out of sequence, no OTP required by server.")
    
    def create_message(self, msg_key, msg_obj):
        msg = {'username': self.username}
        msg[msg_key] = msg_obj

        return msg
    
    def decrypt_image(self):
        carrier = Image.open('final/evidence.png')

        # Encode and save
        stego_msg = stepic.decode(carrier)

        with open("architect_manifesto.txt", "w") as file:
            file.write(stego_msg)
    
    def create_auth_request_object(self, is_pwd=False, otp_code=None):
        """
        Creates the protocol message for initial authentication based on the
        provided username and password.

        Hashing the password allows for more secure communication of credentials
        between the client and server, reducing sniffing attacks that result in 
        leaked credentials.

        Args:
            username (string): username for the login user
            is_pwd (boolean): If True, fetch the password for the user and hash it with a salt before sending.
            otp_code (int): The OTP code, if available, for this connection.

        Returns:
            dict: The protocol message containing the authentication object.
        """
        if is_pwd:
            m = hashlib.sha256()
            salt = b"fsct8561!"
            m.update(self.password.encode("utf-8") + salt)
            hashed_pwd = m.hexdigest()

            return {"password": hashed_pwd}
        elif otp_code:
            return {'otp' : otp_code}

    def socket_send(self, msg, client_socket):
        msg_str = json.dumps(msg)
        try:
            client_socket.send(msg_str.encode())
            resp = client_socket.recv(4096).decode()
            return json.loads(resp)
        except ConnectionResetError as err:
            logging.error(err)
            print("Server disconnected or reset by server")

    def encrypt_file(self, file_name, username):
        client_info = self.get_client_info()
        fernet_key = self.get_user_info(client_info, username, "fernet_key")

        cipher = Fernet(fernet_key)

        with open(file_name, "r", encoding="utf-8") as file:
            content = file.read()
        
        message = content.encode()
        encrypted = cipher.encrypt(message).decode('utf-8')
        return encrypted

    def port_scanning(self):
        """
        Main port scanning logic. 

        Returns:
            bool : True if the target port is open, else False.
        """
        port_scanner = nmap.PortScanner()
        
        host = self.HOST_IP
        port_start = self.SCAN_PORT_START
        port_end = self.SCAN_PORT_END

        port_range = port_start + '-' + port_end
        results = port_scanner.scan(host, port_range, '-sV')
        
        # Includes failure to resolve hostname/invalid IP
        if 'error' in port_scanner.scaninfo():
            print("Error occured while scanning: %s" % port_scanner.scaninfo()['error'][0])
            return False

        # Host is unreachable or scannable
        if not port_scanner.all_hosts():
            print("Error: Unable to reach host")
            return False
        
        target_port_open = False
        
        host_info = port_scanner[port_scanner.all_hosts()[0]]
        with open("recon_log.txt", "a") as file:
            file.write('command: %s \n' % port_scanner.command_line())
            file.write('host: %s (%s)\n' % (host, host_info.hostname()))
            file.write('state: %s\n' % host_info.state())
            if not host_info.all_protocols():
                file.write("No open ports for %s\n" % host)
            else:
                for protocol in host_info.all_protocols():
                    file.write('Protocol: %s\n' % protocol)

                    port_status = host_info[protocol].keys()
                    for port in port_status:
                        port_info = host_info[protocol][port]
                        if not port_info['name']:
                            file.write('port: %s\t state: %s\t' % (port, port_info['state']))
                        else:
                            file.write('port: %s\t state: %s\t service: %s' % (port, port_info['state'], port_info['name']))

                        if port == self.TARGET_PORT:
                            target_port_open = True
                    file.write('\n')

        return target_port_open
    
class AuthenticationError(Exception):
    """
    An error that occurs while inside the MFA module.
    The caller of the functions are expected to handle the exceptions.
    """
    pass

if __name__ == '__main__':
    client = AuthClient()
    client.run_client()