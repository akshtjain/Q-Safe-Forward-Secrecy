from server import SENDER
from Crypto.Random.random import getrandbits
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF1
from Crypto.Util.Padding import pad, unpad
from random import SystemRandom
from decimal import Decimal, getcontext

import zmq
import pickle

PORT = 8042
USER = "ALICE"
SENDER = "Bob"
cryptogen = SystemRandom()

getcontext().prec = 2048

# Previously shared info
POWER = 128
IV = bytes([0 for _ in range(16)])


def qskef(socket):
    """
    Client.
    Does a secure key exchange and gives you the key.
    """

    X = cryptogen.random()
    socket.send(pickle.dumps(X))
    # Alice's secret
    a = getrandbits(POWER)
    # C(a) -> a' | C(y) = (x * y) % 1
    # Alice's public key
    A = Decimal(Decimal(a) * Decimal(X)) % 1

    # Replace in production
    socket.send(pickle.dumps(A))
    B = pickle.loads(socket.recv())
    # Bob gets A. Alice gets B (via sockets)

    # Alice's Symmetric Key
    KEY_A = (Decimal(a) * Decimal(B)) % 1

    PASS = str(KEY_A)[2:]

    # Additional step for security
    KEY = PBKDF1(PASS, "01234567".encode(), 16)
    return KEY


def sendChat(socket):
    """
    Client sending.
    """

    PT = input()
    key = qskef(socket)
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    PT = pad(PT.encode(), 16)
    CT = cipher.encrypt(PT)
    socket.send(CT)

    receiveChat(socket)


def receiveChat(socket):
    """
    Client receiving.
    """
    key = qskef(socket)
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    CT = socket.recv()
    PT = cipher.decrypt(CT)
    PT = unpad(PT, 16).decode()

    print(f"{SENDER}: {PT}")

    sendChat(socket)


def main():
    context = zmq.Context()
    socket = context.socket(zmq.PAIR)
    socket.connect(f"tcp://localhost:{PORT}")
    sendChat(socket)


if __name__ == "__main__":
    main()
