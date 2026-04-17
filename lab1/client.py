import socket 
import logging

def socket_client():

    logging.basicConfig(
        level=logging.DEBUG, 
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    hostname = socket.gethostname() 
    port = 12345

    # create the socket and connect to the host via port 12345
    client_socket = socket.socket()
    client_socket.connect((hostname, port))

    # prompt the user to provide a message 
    username = input("Provide a username: ")
    hello_msg = "HELLO|" + username
    client_socket.send(hello_msg.encode())
    resp = client_socket.recv(4096).decode()
    print("Connection response from server: " + resp)

    # close the program if 'exit' is entered, else send the message to the server
    try:
        while True:
            message = input("Message to send: ")
            if message.lower().strip() == 'exit':
                break

            send_msg = "MSG|" + message
            logging.debug("message to send: " + send_msg)
            client_socket.send(send_msg.encode())
            logging.debug("sent msg")
            data = client_socket.recv(4096).decode()

            print("Response from server: " + data)
        
        client_socket.send(b'EXIT')
        exit_msg = client_socket.recv(4096).decode()
        print("Server EXIT response: " + exit_msg)
        client_socket.close()
    except ConnectionResetError as err:
        logging.error(err)
        print("Server disconnected or reset by server")

if __name__ == '__main__':
    socket_client()