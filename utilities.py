from Crypto.Random.random import getrandbits
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF1
from Crypto.Util.Padding import pad, unpad
from random import SystemRandom
from decimal import Decimal, getcontext
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import zmq


getcontext().prec = 2048
PORT = 8042
# Previously shared info
POWER = 128
IV = bytes([0 for _ in range(16)])


def sendChat(socket, kdf, SENDER, sender_pubkey, prikey):
    PT = input()
    key = kdf(socket, sender_pubkey, prikey)
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    PT = pad(PT.encode(), 16)
    CT = cipher.encrypt(PT)
    socket.send(CT)

    receiveChat(socket, kdf, SENDER, sender_pubkey, prikey)


def receiveChat(socket, kdf, SENDER, sender_pubkey, prikey):
    key = kdf(socket, sender_pubkey, prikey)
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    CT = socket.recv()
    PT = cipher.decrypt(CT)
    PT = unpad(PT, 16).decode()

    print(f"{SENDER}: {PT}")

    sendChat(socket, kdf, SENDER, sender_pubkey, prikey)
