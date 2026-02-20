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
    Authentication Handshake logic.
    """

    # Dictionary for keeping track of current active connections.
    # {username: {"pwd_auth": False, "pwd_attempts" : 5, "otp_attempts": 5, "session_state" : "AUTH", "nonce_secret": "", "nonce_counter": 0}}
    active_connections = {}

    def __init__(self):
        pass
    
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

    def validate_password(self, username, hashed_pwd):
        """
        Validate the provided password against the saved hashed password.

        The password is assumed to have been configured and stored properly.
        Hashed passwords saved is a security mechanism to prevent against unauthorized 
        access to credentials through sniffing or data access.

        Args:
            username (string): The username to check the password against.
            hashed_pwd (string): The password provided by the client.

        Raises:
            AuthenticationError: If username is not a valid user.
            AuthenticationError: If the number of password attempts has been exhausted.

        Returns:
            bool: True if the password is correct, else False.
        """
        client_info = self.get_client_info()\
        # Handles incorrect username, malformed usernames.
        if username not in client_info:
            self.active_connections[username]["session_state"] = "CLOSED"
            raise AuthenticationError(f"User {username} not found")
        
        stored_pwd = self.get_user_info(client_info, username, "password")
        if stored_pwd != hashed_pwd:
            # The password attempt limit prevents request flooding attacks.
            if self.active_connections[username]["pwd_attempts"] > 1:
                self.active_connections[username]["pwd_attempts"] -= 1
                # Logging allows for better audits and tracing if attacks occur.
                logger.debug(f"{self.active_connections[username]['pwd_attempts']} password attempts left for {username}")
                return False
            else:
                # ASSUMPTION: function calling the Authorization module will check the session_state of the user.
                #             The caller (in the core logic module) is expected to close connections securely.
                self.active_connections[username]["session_state"] = "CLOSED"
                raise AuthenticationError(f"Incorrect password for user {username}, no attempts left")
        
        else:
            logger.info(f"User {username} has successfully logged in")
            return True

    def validate_otp(self, username, otp_val):
        """
        Validate the provided OTP against the expected current OTP.

        The client secret for the OTP is assumed to have been configured and stored properly.
        OTP allows for an extra layer of posession factor security.

        Args:
            username (string): The username to check the OTP for.
            otp_val (string): The OTP value provided by the client.

        Raises:
            AuthenticationError: If username is not a valid user.
            AuthenticationError: If the number of OTP attempts has been exhausted.

        Returns:
            bool: True if the password is correct, else False.
        """
        client_info = self.get_client_info()
        otp_secret = self.get_user_info(client_info, username, "otp_secret")

        # Time based OTP: Prevents against replay attacks during login. 
        # After a certain amount of time the OTP will no longer be valid. 
        # Even if adversaries can capture this value, they have to input it in a short amount of time.
        totp = pyotp.TOTP(otp_secret)
        if totp.verify(otp_val):
            logger.info(f"OTP validated for user {username}, user sucessfully logged in")
            self.active_connections[username]["nonce_secret"] = client_info[username]["otp_secret"]
            return True
        # The OTP attempt limit prevents request flooding attacks.
        elif self.active_connections[username]["otp_attempts"] > 1:
            self.active_connections[username]["otp_attempts"] -= 1
            # Logging allows for better audits and tracing if attacks occur.
            logger.debug(f"{self.active_connections[username]['otp_attempts']} OTP attempts left for {username}")
            return False

        else:
            # ASSUMPTION: function calling the Authorization module will check the session_state of the user.
            #             The caller (in the core logic module) is expected to close connections securely.
            self.active_connections[username]["session_state"] = "CLOSED"
            raise AuthenticationError(f"Exhausted number of OTP attempts for {username}")

    def authentication_handshake(self, message):
        """
        Given the message from the client, performs authentication for the user.

        The Multi-Factor Authentication (MFA) authentication flow adds an extra layer of 
        protection in addition to passwords. A posession factor is included, protecting against 
        leaked or unauthorized acquisition of credentials.

        Important:
            The message passed into this function is assumed to have been validated by the 
            detection module, including:
                JSON validation
                input validation (length and checks for malicious/suspicious inputs)
            
            The error message is assumed to be handled by the caller to 
            incorporate into the return message. 
            
            The caller should handle the session state by looking at the info in 
            active_connections. This function only changes the value in active_connections.
            If the session state is CLOSED the caller is expected to remove the entry after
            it closes the connection gracefully.
            

        Args:
            message (dict): The protocol message received from the client.

        Raises:
            AuthenticationError: Malformed messages without username.
            AuthenticationError: Malformed messages without authentication object.
            AuthenticationError: Malformed messages without password when expected.
            AuthenticationError: Malformed message without OTP value when expected.

        Returns:
            dict: Dictionary containing the following information:
                username, 
                authentication object (with require_otp set)
                nonce_otp (included after full authentication completed)
        """
        if "username" not in message:
            raise AuthenticationError("Malformed message: Missing username")
        
        if "authentication" not in message:
            raise AuthenticationError("Malformed message: Missing authentication object")
        auth_obj = message['authentication']

        return_msg = {}
        username = message["username"]
        return_msg["username"] = username
        
        if username not in self.active_connections:
            self.active_connections[username] = {"pwd_auth": False, "pwd_attempts" : 5, "otp_attempts": 5, "session_state" : "AUTH"}

        if not self.active_connections[username]["pwd_auth"]:
            # Input validation based on progress in authentication.
            if "password" not in auth_obj:
                raise AuthenticationError("Malformed message: Missing password for initial authentication")
            
            if self.validate_password(username, auth_obj["password"]):
                self.active_connections[username]["pwd_auth"] = True
                return_msg["authentication"] = {"require_otp": True}
        
        else:
            # Input validation based on progress in authentication.
            if "otp" not in auth_obj:
                raise AuthenticationError("Malformed message: Missing OTP value")

            if self.validate_otp(username, auth_obj["otp"]):
                # Change of state to protect against malicious repeated connections.
                self.active_connections[username]["session_state"] = "CONNECTED"

                if "nonce_secret" not in self.active_connections[username]:
                    client_info = self.get_client_info()
                    self.active_connections[username]["nonce_secret"] = self.get_user_info(client_info, username, "otp_secret")

                # Create the initial nonce using a HOTP with the counter. 
                # The client will be validating this value to prevent against replay attacks.
                # Any further messages sent or received will also require this nonce to be calculated and included.
                hotp = pyotp.HOTP(self.active_connections[username]["nonce_secret"])
                return_msg["nonce_otp"] = hotp.at(0)
                # The counter is always the number that is being expected for the next message 
                # (ie. the validation nonce should be calculated with this value).
                self.active_connections[username]["nonce_counter"] = 1
            else:
                # OTP provided was incorrect, request for OTP again.
                return_msg["authentication"] = {"require_otp": True}

        return return_msg

class AuthenticationClient:
    """
    Authentication Client logic. Only for demonstration purposes.
    """

    def __init__(self):
        pass

class AuthenticationError(Exception):
    """
    An error that occurs while inside the MFA module.
    The caller of the functions are expected to handle the exceptions.
    """
    pass
