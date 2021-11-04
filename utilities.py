from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from decimal import Decimal
from Crypto.Random import get_random_bytes
from decimal import getcontext
from random import SystemRandom
from Crypto.Protocol.KDF import PBKDF1
from Crypto.Random.random import getrandbits


# Global settings
getcontext().prec = 2048
PORT1 = 8042
PORT2 = 8043
# Previously shared info
POWER = 128
IV = bytes([0 for _ in range(16)])

cryptogen = SystemRandom()


def client_qskef(socket, sender_pubkey, prikey):
    """
    Client.
    Does a secure key exchange and gives you the key.
    """

    getcontext().prec = 2048
    X = cryptogen.random()
    socket.send(str(X).encode())
    # Alice's secret
    a = getrandbits(POWER)
    # Alice's public key
    A = Decimal(Decimal(a) * Decimal(X)) % 1

    # Encrypting and sending A
    send_decimal(socket, sender_pubkey, A)

    # Receiving and decrypting B
    B = recv_decimal(socket, prikey)

    # Alice's Symmetric Key
    KEY_A = (Decimal(a) * Decimal(B)) % 1

    PASS = str(KEY_A)[2:]

    # Additional step for security
    KEY = PBKDF1(PASS, "01234567".encode(), 16)
    return KEY

def server_qskef(socket, sender_pubkey, prikey):
    """
    Server.
    Does a secure key exchange and gives you the key.
    """

    getcontext().prec = 2048
    X = float(socket.recv().decode())
    # Bob's secret
    b = getrandbits(POWER)
    # Bob's public int
    B = Decimal(Decimal(b) * Decimal(X)) % 1

    # Receiving and decrypting A
    A = recv_decimal(socket, prikey)

    # Encrypting and sending B
    send_decimal(socket, sender_pubkey, B)

    # Bob's Symmetric Key
    KEY_B = (Decimal(b) * Decimal(A)) % 1

    PASS = str(KEY_B)[2:]

    # Additional step for security
    KEY = PBKDF1(PASS, "01234567".encode(), 16)
    return KEY


def fn_client(socket, qskef, SENDER, sender_pubkey, prikey):
    while 1:
        sendChat(socket, qskef, SENDER, sender_pubkey, prikey)


def fn_server(socket, qskef, SENDER, sender_pubkey, prikey):
    while 1:
        receiveChat(socket, qskef, SENDER, sender_pubkey, prikey)


def sendChat(socket, kdf, SENDER, sender_pubkey, prikey):
    PT = input()
    key = kdf(socket, sender_pubkey, prikey)
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    PT = pad(PT.encode(), 16)
    CT = cipher.encrypt(PT)
    socket.send(CT)


def receiveChat(socket, kdf, SENDER, sender_pubkey, prikey):
    key = kdf(socket, sender_pubkey, prikey)
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    CT = socket.recv()
    PT = cipher.decrypt(CT)
    PT = unpad(PT, 16).decode()

    print(f"{SENDER}: {PT}")


def recv_decimal(socket, privkey):
    """
    Receive decimal using PKI
    """
    enc_session_key, nonce, tag, ciphertext = \
        [socket.recv() for _ in range(4)]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(privkey)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    D = Decimal(data.decode())
    return D


def send_decimal(socket, sender_pubkey, D):
    """
    Send across a decimal using PKI
    """
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(sender_pubkey)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(str(D).encode())
    [socket.send(x)
     for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
