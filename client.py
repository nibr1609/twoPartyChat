import socket
from keys import init, fetch_signing_keys, KeyStorage
from messageHandler import createJSON, MsgType, send, handle_msg
from selfsign import self_sign

from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding

HEADER = 64
PORT = 5050
UTF = "utf-8"
# Reading Server Address to connect to
SERVER = input("Give Server Address: ")
ADDR = (SERVER, PORT)
NAME = "client"
PREFIX = "[chatClient] "


def start():
    print(PREFIX + "Starting...")
    # Keyfile creation
    init(NAME)

    # Keys are being loaded
    keys = KeyStorage()
    keys.PUBLIC_SIGNING, keys.PRIVATE_SIGNING = fetch_signing_keys(NAME)

    # Self sign certificate NOT FOR PRODUCTION
    keys.CERTIFICATE = self_sign(keys.PRIVATE_SIGNING)

    # Connect to Host
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(ADDR)
    print(PREFIX + "Connected!")

    # Send Hello Message with Certificate
    msg = createJSON(None, keys.CERTIFICATE, MsgType.INIT, None)
    send(conn, msg)

    # Receive input and handle it
    while True:
        try:
            header = conn.recv(HEADER).decode(UTF)
            if header:
                msg_length = int(header)
                msg = conn.recv(msg_length).decode(UTF)
                handle_msg(conn, msg, keys, PREFIX)
        except socket.error:
            conn.close()


start()