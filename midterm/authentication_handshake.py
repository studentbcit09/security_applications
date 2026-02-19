import json
import logging
import pyotp

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)

class AuthenticationServer:
    """
    Docstring for AuthenticationServer
    """

    # {username: {counter: num, require_otp: bool, num_attemps_left}, session_state}

    active_connections = {}

    def __init__(self):
        pass

    # remember to mention: input validation? failed authentication? logging?
    def validate_password(self, username, hashed_pwd):
        with (open('users.json')) as data:
            client_info = json.load(data)

        if username not in client_info:
            raise AuthenticationError(f"User {username} not found")
        
        elif client_info[username]["password"] != hashed_pwd:
            if self.active_connections[username]["pwd_attempts"] > 1:
                self.active_connections[username]["pwd_attempts"] -= 1
                logger.debug(f"{self.active_connections[username]["pwd_attempts"]} password attempts left for {username}")
                return False
            else:
                raise AuthenticationError(f"Incorrect password for user {username}")
        
        else:
            logger.info(f"User {username} has successfully logged in")
            return True
    
    # assumption: user already known to be in the database because they have authenticated with username/pw
    # assumption: otp_secret is populated, there is a failure mechanism during config that will not allow this to be empty
    def validate_otp(self, username, otp_val):
        with (open('users.json')) as data:
            client_info = json.load(data)

        totp = pyotp.TOTP(client_info[username]["otp_secret"])
        if totp.verify(otp_val):
            logger.info(f"OTP validated for user {username}, user sucessfully logged in")
            # TODO: if extra lines, change to enum
            self.active_connections[username]["session_state"] = "CONNECTED"
            self.active_connections[username]["nonce_secret"] = client_info[username]["otp_secret"]
            return True

        elif self.active_connections[username]["otp_attempts"] > 1:
            self.active_connections[username]["otp_attempts"] -= 1
            logger.debug(f"{self.active_connections[username]["otp_attempts"]} OTP attempts left for {username}")
            return False

        else:
            # assume that the function calling the authserver module will check this and close necessary connections
            self.active_connections[username]["session_state"]["state"] = "CLOSED"
            raise AuthenticationError(f"Exhausted number of OTP attempts for {username}")


    
    # assumption, JSON validation already performed by detection module; detection module does input validation (length and checks for malicious/suspiciously formed inputs)
    # only minor checks performed here 
    def authentication_handshake(self, message):
        return_msg = {}
        if "authentication" not in message:
            raise AuthenticationError("Malformed message: Missing authentication object")
        
        auth_obj = message['authentication']
        if "username" not in message:
            raise AuthenticationError("Malformed message: Missing username")
        username = message["username"]
        return_msg["username"] = username

        if username in self.active_connections:
            if self.active_connections[username]["pwd_auth"]:
                if "otp" not in auth_obj:
                    raise AuthenticationError("Malformed message: Missing OTP value")
                
                # will throw error if OTP exhausted
                if self.validate_otp(username, auth_obj["otp"]):
                    hotp = pyotp.HOTP(self.active_connections[username]["nonce_secret"])
                    return_msg["otp"] = hotp.at(0)
                    self.active_connections[username]["counter"] = 1
                else:
                    return_msg["authentication"] = {"authentication": {"require_otp": True}}
                    
            elif "password" not in auth_obj:
                raise AuthenticationError("Malformed message: Missing password for initial authentication")
            else:
                if self.validate_password(username, auth_obj["password"]):
                    self.active_connections[username]["pwd_auth"] = True
                    return_msg["authentication"] = {"authentication": {"require_otp": True}}
        else:
            self.active_connections[username] = {"pwd_auth": False, "pwd_attempts" : 5, "otp_attempts": 5, "session_state" : "AUTH"}





            # if "password" not in auth_obj:
            #     raise AuthenticationError("Malformed message: Missing password for initial authentication")
            # self.validate_password(auth_obj['username'], auth_obj['password'])
        



    
class AuthenticationClient:
    """
    Docstring for AuthenticationClient
    """

    def __init__(self):
        pass

class AuthenticationError(Exception):
    """
    Docstring for AuthenticationError
    """
    pass
