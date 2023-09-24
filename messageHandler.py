from enum import Enum
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.exceptions import InvalidSignature
from keys import get_symmetric_key, check_certificate_get_pub_peer_signing_key, encrypt, decrypt, KeyStorage
import threading

from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding

UTF = "utf-8"
LATIN = "Latin-1"
HEADER = 64


class MsgType(Enum):
    INIT = 'c'
    KEY_EXCHANGE = 'k'
    MSG = 'e'

# Send message to peer with symmetric key
def send_synced(conn, msg, keys: KeyStorage):
    json_msg = createJSON(encrypt(msg, keys.S_KEY), keys.CERTIFICATE, MsgType.MSG, keys.PRIVATE_SIGNING)
    send(conn, json_msg)

# Implements input functionality
def open_chat(conn, keys):
    while True:
        msg = input()
        send_synced(conn, msg, keys)

# Creates Message Header
def createHeader(msg):
    message = msg.encode(UTF)
    msg_length = len(message)
    return str(msg_length)

# Takes bytes as input and produces JSON
def createJSON(msg, certificate, msgType: MsgType, key: Ed25519PrivateKey):
    cer_bytes = certificate.public_bytes(Encoding.PEM)
    # Convert from bytes to UTF
    msg_utf = None
    if msg:
        msg_utf = msg.decode(LATIN)
    cer_utf = cer_bytes.decode(LATIN)
    signature = None
    if key:
        signature = key.sign(msg)
        signature = signature.decode(LATIN)
    m = {"msgType": msgType.value, "certificate": cer_utf, "signature": signature,  "msg": msg_utf}
    return json.dumps(m)


# load JSON into bytes
def loadJSON(str):
    m = json.loads(str)
    msg_type = m["msgType"]
    msg = None
    if m["msg"]:
        msg = m["msg"].encode(LATIN)
    certificate = m["certificate"].encode(LATIN)
    signature = None
    if m["signature"]:
        signature = m["signature"].encode(LATIN)
    return msg_type, msg, signature, certificate


# send a msg to a client
def send(client, msg):
    header = createHeader(msg)
    header = header.encode(UTF)
    header = header + b' ' * (HEADER-len(header))
    client.send(header)
    client.send(msg.encode(UTF))


def handle_msg(conn, msg, keys: KeyStorage, PREFIX):
    # load contents
    msg_type, msg, signature, certificate = loadJSON(msg)

    # If we accept that users certificate we always check for signature
    if keys.CA_VERIFIED:
        try:
            keys.PUBLIC_PEER_SIGNING_KEY.verify(signature, msg)
        except InvalidSignature:
            print(PREFIX + "Message with invalid signature received.")
            return
        
    # Handle init message
    if msg_type == MsgType.INIT.value and not keys.CA_VERIFIED and not keys.KEYS_EXCHANGED:
        # check certificate
        valid, keys.PUBLIC_PEER_SIGNING_KEY = check_certificate_get_pub_peer_signing_key(certificate)
        if not valid:
            print(PREFIX + "Invalid certificate received.")
            return
        print(PREFIX + "Valid certificate received. Exchanging keys...")

        # Exchange Keys, send public key to peer
        keys.PRIVATE_EXCHANGE = X25519PrivateKey.generate()
        json_msg = createJSON(keys.PRIVATE_EXCHANGE.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), keys.CERTIFICATE, MsgType.KEY_EXCHANGE, keys.PRIVATE_SIGNING)
        send(conn, json_msg)

        keys.CA_VERIFIED = True
    
    # After Certificate is Accepted await Public Key from peer
    if msg_type == MsgType.KEY_EXCHANGE.value and keys.CA_VERIFIED and not keys.KEYS_EXCHANGED:
        # Derive Key
        keys.PUBLIC_PEER_EXCHANGE_KEY = X25519PublicKey.from_public_bytes(msg)
        keys.S_KEY = get_symmetric_key(keys.PRIVATE_EXCHANGE, keys.PUBLIC_PEER_EXCHANGE_KEY)
        keys.KEYS_EXCHANGED = True
        print(PREFIX + "Keys exchanged. You can chat now")
        print("########################")
        # Start Chat function
        thread = threading.Thread(target=open_chat, args=(conn,keys,))
        thread.start()

    # After Keys exchanged, display messages from peer
    if msg_type == MsgType.MSG.value and keys.CA_VERIFIED and keys.KEYS_EXCHANGED:
        print("[MSG] " + decrypt(msg, keys.S_KEY))