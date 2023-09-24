import socket
import threading
from keys import init, fetch_signing_keys, KeyStorage
from messageHandler import createJSON, MsgType, send, handle_msg
from selfsign import self_sign

HEADER = 64
PORT = 5050 
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
PREFIX = "[chatHost] "
NAME = "host"
UTF = "utf-8"

def handle_client(conn, keys):
    # Send Hello Message with Certificate
    msg = createJSON(None, keys.CERTIFICATE, MsgType.INIT, None)
    send(conn, msg)
    # Receive input and handle it
    while True:
        try:
            # handle_input()
            header = conn.recv(HEADER).decode(UTF)
            if header:
                msg_length = int(header)
                msg = conn.recv(msg_length).decode(UTF)
                handle_msg(conn, msg, keys, PREFIX)
        except socket.error:
            conn.close()


def start():
    print(PREFIX + "Starting...")
    # Keyfile creation
    init(NAME)

    # Keys are being loaded
    keys = KeyStorage()
    keys.PUBLIC_SIGNING, keys.PRIVATE_SIGNING = fetch_signing_keys(NAME)

    # Self sign certificate NOT FOR PRODUCTION
    keys.CERTIFICATE = self_sign(keys.PRIVATE_SIGNING)

    # Initialize Server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen(1)


    # Connect to Client
    print(f"{PREFIX}: Listening on {SERVER}...")
    while True:
        conn, addr = server.accept()
        if threading.active_count() - 1 == 0:
            thread = threading.Thread(target=handle_client, args=(conn,keys,))
            thread.start()
            print(f"{PREFIX} {addr} connected!")


start()