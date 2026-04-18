import hashlib
import json

from cryptography.fernet import Fernet
import nmap
import socket 
import logging

logging.basicConfig(
    level=logging.DEBUG, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class AuthClient:
    HOST_IP = "192.168."
    SCAN_PORT_START = ""
    SCAN_PORT_END = ""
    TARGET_PORT = ""

    def run_client(self):
        if not self.port_scanning():
            print(f"Target port {self.TARGET_PORT} on {self.HOST_IP} is closed. Unable to proceed.")
            return

        encrypted_file = self.encrypt_file("architect_manifesto.txt")

        self.current_socket = socket.socket()
        self.current_socket.connect((self.HOST_IP, self.TARGET_PORT))

        server_pwd_resp = self.socket_send(self.create_message(self.create_auth_request_object(is_pwd=True)))

        otp_code = self.handle_otp(server_pwd_resp)

        server_otp_resp = self.socket_send(self.create_message(self.create_auth_request_object(otp_code=otp_code)))

        # TODO: validate server response

        self.socket_send(self.create_message('data', {'file': encrypted_file}))


    def handle_otp(self, resp):
        auth_obj = resp['authentication']
        if 'require_otp' in auth_obj:
            otp_code = self.generate_otp()
            return otp_code
    
    def create_message(self, msg_key, msg_obj):
        msg = {'username': self.username}
        msg[msg_key] = msg_obj

        return msg

    def create_auth_request_object(self, is_pwd=False, otp_code=None):
        """
        Creates the protocol message for initial authentication based on the
        provided username and password.

        Hashing the password allows for more secure communication of credentials
        between the client and server, reducing sniffing attacks that result in 
        leaked credentials.

        Args:
            username (string): username for the login user
            password (string): plaintext password for the user

        Returns:
            dict: The protocol message containing the authentication object.
        """
        auth_msg = {}
    
        if is_pwd:
            m = hashlib.sha256()
            m.update(self.password.encode("utf-8"))
            hashed_pwd = m.hexdigest()

            auth_msg['authentication'] = {"password": hashed_pwd}
        elif otp_code:
            auth_msg['authentication'] = {'otp' : otp_code}
        return auth_msg

    def socket_send(self, msg):

        hostname = socket.gethostname() 
        port = 12345

        # create the socket and connect to the host via port 12345
        client_socket = socket.socket()
        client_socket.connect((hostname, port))

        msg_str = json.dumps(msg)
        try:
            client_socket.send(msg_str.encode())
            # TODO: what if the message is longer than 4096
            resp = client_socket.recv(4096).decode()
            return resp
        except ConnectionResetError as err:
            logging.error(err)
            print("Server disconnected or reset by server")

    def encrypt_file(file_name):
        key = Fernet.generate_key()
        cipher = Fernet(key)

        with open(file_name, "r", encoding="utf-8") as file:
            content = file.read()
        
        message = content.encode()
        encrypted = cipher.encrypt(message)

    def port_scanning(self):
        port_scanner = nmap.PortScanner()
        
        host = self.HOST_IP
        port_start = self.SCAN_PORT_START
        port_end = self.SCAN_PORT_END

        port_range = port_start + '-' + port_end
        results = port_scanner.scan(host, port_range, '-sV')
        
        # TODO: change to logging 
        # print(port_scanner.command_line())
        
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
        print('host: %s (%s)' % (host, host_info.hostname()))
        print('state: %s' % host_info.state())
        if not host_info.all_protocols():
            print("No open ports for %s" % host)
        else:
            for protocol in host_info.all_protocols():
                print('Protocol: %s' % protocol)

                port_status = host_info[protocol].keys()
                for port in port_status:
                    port_info = host_info[protocol][port]
                    if not port_info['name']:
                        print('port: %s\t state: %s\t' % (port, port_info['state']))
                    else:
                        print('port: %s\t state: %s\t service: %s' % (port, port_info['state'], port_info['name']))

                    if port == self.TARGET_PORT:
                        target_port_open = True

        return target_port_open
    
class AuthenticationError(Exception):
    """
    An error that occurs while inside the MFA module.
    The caller of the functions are expected to handle the exceptions.
    """
    pass

if __name__ == '__main__':
    print("need to pick something to run")