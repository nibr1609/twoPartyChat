import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.padding import PKCS7

UTF = "utf-8"

# Objects of this class can contain multiple keys
class KeyStorage:
    PUBLIC_SIGNING = None
    PRIVATE_SIGNING = None
    CERTIFICATE = None
    PUBLIC_PEER_SIGNING_KEY = None
    PUBLIC_PEER_EXCHANGE_KEY = None
    PRIVATE_EXCHANGE = None
    S_KEY = None
    KEYS_EXCHANGED = False
    CA_VERIFIED = False

# derive a 32 bit symmetric key after X25519 exchange
def get_symmetric_key(privateKey: X25519PrivateKey, publicKeyPeer: X25519PublicKey):
    sk = privateKey.exchange(publicKeyPeer)
    return HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(sk)

# encrypt plaintext with symmetric key, CTR mode, PKCS7 padding 
def encrypt(plaintext, key):
    plaintext = plaintext.encode(UTF)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv + ciphertext

# decrypt ct with symmetric key, CTR mode, PKCS7 padding 
def decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode(UTF)

# Generate keys and safe them
def init(NAME):
    if not os.path.exists("./" + NAME + "keys/pub.pem"):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        # Use a real encryption algorithm w password here in production!!
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
            )
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        if not os.path.exists("./" + NAME + "keys/"):
            os.mkdir("./" + NAME + "keys/")
        with open("./" + NAME + "keys/pub.pem", 'w') as f:
            f.write(pem_public.decode(UTF))
        with open("./" + NAME + "keys/private.pem", 'w') as f:
            f.write(pem_private.decode(UTF))

# Load Keys from Files
def fetch_signing_keys(NAME):
    private = ""
    public = ""
    with open("./" + NAME + "keys/private.pem", "rb") as key_file:
        private = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    with open("./" + NAME + "keys/pub.pem", "rb") as key_file:
        public = serialization.load_pem_public_key(
            key_file.read()
        )
    return public, private

# Check Certificate and extract Public Key
def check_certificate_get_pub_peer_signing_key(cert):
    # here you should check the certificate with the CA.
    # This is just for demonstration purposes
    return True, load_pem_x509_certificate(cert).public_key()


