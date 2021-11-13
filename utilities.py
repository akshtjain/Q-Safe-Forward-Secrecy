from Crypto.Cipher import AES
from decimal import Decimal
from decimal import getcontext
from random import SystemRandom
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random.random import getrandbits
import pyspx.shake256_128f as sphincs


# Global settings
getcontext().prec = 2048
PORT1 = 8042
PORT2 = 8043
# Previously shared info
POWER = 128
IV = bytes([0 for _ in range(16)])
BLOCK_SIZE = 256 // 8 # AES-256 for security against Grover's

cryptogen = SystemRandom()
bscolor="\033[01;34m"
gscolor="\033[01;32m"
rcolor="\033[00m"


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
    send_decimal(socket, prikey, A)

    # Receiving and decrypting B
    B = recv_decimal(socket, sender_pubkey)

    # Alice's Symmetric Key
    KEY_A = (Decimal(a) * Decimal(B)) % 1

    PASS = str(KEY_A)[2:]

    # Additional step for security
    KEY = PBKDF2(PASS, "01234567".encode(), BLOCK_SIZE)
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
    A = recv_decimal(socket, sender_pubkey)

    # Encrypting and sending B
    send_decimal(socket, prikey, B)

    # Bob's Symmetric Key
    KEY_B = (Decimal(b) * Decimal(A)) % 1

    PASS = str(KEY_B)[2:]

    # Additional step for security
    KEY = PBKDF2(PASS, "01234567".encode(), BLOCK_SIZE)
    return KEY


def fn_client(socket, qskef, sender_pubkey, prikey):
    while 1:
        send_chat(socket, qskef, sender_pubkey, prikey)


def fn_server(socket, qskef, SENDER, sender_pubkey, prikey):
    while 1:
        receive_chat(socket, qskef, SENDER, sender_pubkey, prikey)


def send_chat(socket, kdf, sender_pubkey, prikey):
    PT = input()
    key = kdf(socket, sender_pubkey, prikey)
    cipher = AES.new(key, AES.MODE_EAX)
    PT = PT.encode()
    CT, tag = cipher.encrypt_and_digest(PT)
    socket.send(CT)
    socket.send(tag)
    socket.send(cipher.nonce)


def receive_chat(socket, kdf, SENDER, sender_pubkey, prikey):
    key = kdf(socket, sender_pubkey, prikey)
    CT = socket.recv()
    tag = socket.recv()
    nonce = socket.recv()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    PT = cipher.decrypt_and_verify(CT, tag)
    PT = PT.decode()

    print(f"{bscolor}{SENDER}: {PT}{rcolor}")


def recv_decimal(socket, pubkey):
    """
    Receive decimal using PKI
    De-serialize using D = Decimal(bytes_received.decode())
    """
    msg = socket.recv()
    sig = socket.recv()
    if not sphincs.verify(msg, sig, pubkey):
        raise Exception("HACKKKKKKK!")
    D = Decimal(msg.decode())
    return D


def send_decimal(socket, priv_key, D):
    """
    Send across a decimal using PKI
    Serialize using str(D).encode()
    """
    msg = str(D).encode()
    sig = sphincs.sign(msg, priv_key)
    socket.send(msg)
    socket.send(sig)