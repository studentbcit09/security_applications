import socket
import logging
from enum import Enum

class ChatState(Enum):
    NO_CONNECTION = 0
    ACTIVE = 1

# keep track of the username and the session state
username = None
session_state = ChatState.NO_CONNECTION
logger = logging.getLogger(__name__)

# validates the message provided, expecting COMMAND|MESSAGE format
# acceptable values are HELLO, EXIT, or OK
# returns [state, message/input] containing the relevant info parsed out
def validate_input(message):
    # empty input (stripped whitespace)
    if not message:
        return ["ERROR", "Message is empty with no command or message"]
    
    # assume that anything after the split is part of the message, even if it contains the delimeter
    input_args = message.split("|", 1)
    # logger.debug("validate_input split portions: " + input_args)
    
    if (1 == len(input_args)) and ("EXIT" == input_args[0]):
        return ["EXIT", "Exiting. Goodbye."]
                                   
    if 2 != len(input_args):
        return ["ERROR", "Malformed message input: missing arguments. Message should be in the form of COMMAND|MESSAGE"]
    elif input_args[0] not in ["HELLO", "MSG"]:
        return ["ERROR", "Input command is not valid: options are HELLO, MSG, or EXIT"]
    elif input_args[0] == "HELLO":
        return ["HELLO", input_args[1]]
    else:
        return ["OK", "Message received"]
    
# reset the state of the connection and wipe the username
def reset_state():
    global username, session_state
    username = None
    session_state = ChatState.NO_CONNECTION

# main server logic
def socket_server():
    global username, session_state
    logging.basicConfig(
        level=logging.ERROR, 
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # retrieve the hostname of the machine
    hostname = socket.gethostname()
    # static assigned port for the socket server based on requirements
    port = 12345

    server_socket = socket.socket()
    server_socket.bind((hostname, port))


    has_connection = False
    while True:
        try:    
            exit_connection = False        
            return_msg = ""
            if session_state == ChatState.NO_CONNECTION and not has_connection:
                # only allow one connection to the server at a time
                server_socket.listen(1)
                conn, addr = server_socket.accept()
                has_connection = True
                logging.info("Socket connection established")

            # receive data
            data = conn.recv(4096).decode()
            print("message received: " + data)
            if not data:
                return_msg = "ERROR|Input received is blank"
            else:
                [command, msg] = validate_input(data.strip())
                logger.debug("validation return command: " + command + " message: " + msg)

                if "HELLO" == command:
                    if session_state == ChatState.ACTIVE:
                        return_msg = "ERROR|Connection already established"
                        logging.error("Sending HELLO to establish when connection already exists")
                    else:
                        session_state = ChatState.ACTIVE
                        username = msg
                        return_msg = "OK|Connection established and username " + username + " noted"
                        logging.info("Connection established with " + username)
                elif "ERROR" == command:
                    return_msg = "ERROR|" + msg
                elif "OK" and session_state == ChatState.NO_CONNECTION:
                    return_msg = "ERROR|No connection established before sending message"
                    logging.error("No connection established before sending message")
                elif command == "EXIT":
                    reset_state()
                    logging.info("Exiting and disconnecting connection")
                    return_msg = "OK|" + msg
                    exit_connection = True
                else:
                    return_msg = command + "|" + msg

            conn.send(return_msg.encode())

            if exit_connection:
                logging.info("Closing client connection")
                conn.close()
                has_connection = False
        except ConnectionAbortedError:
            print("Client aborted connection")
            conn.close()
            reset_state()
            has_connection = False
    

if __name__ == '__main__':
    socket_server()
