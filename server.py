from Crypto.Random.random import getrandbits
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF1
from Crypto.Util.Padding import unpad, pad
from decimal import Decimal, getcontext

import zmq
import pickle

PORT = 8042
USER = "BOB"
SENDER = "Alice"

getcontext().prec = 2048

# Previously shared info
POWER = 128
IV = bytes([0 for _ in range(16)])


def qskef(socket):
    """
    Server.
    Does a secure key exchange and gives you the key.
    """
    X = pickle.loads(socket.recv())
    # Bob's secret
    b = getrandbits(POWER)
    # Bob's public int
    B = Decimal(Decimal(b) * Decimal(X)) % 1

    A = pickle.loads(socket.recv())
    socket.send(pickle.dumps(B))
    # Bob gets A. Alice gets B (via sockets)

    # Bob's Symmetric Key
    KEY_B = (Decimal(b) * Decimal(A)) % 1

    PASS = str(KEY_B)[2:]

    # Additional step for security
    KEY = PBKDF1(PASS, "01234567".encode(), 16)
    return KEY


def sendChat(socket):
    """
    Server sending.
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
    Server receiving.
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
    socket.bind(f"tcp://*:{PORT}")
    receiveChat(socket)


if __name__ == "__main__":
    main()
