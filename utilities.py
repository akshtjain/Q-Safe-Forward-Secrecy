from Crypto.Random.random import getrandbits
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF1
from Crypto.Util.Padding import pad, unpad
from random import SystemRandom
from decimal import Decimal, getcontext

import zmq


getcontext().prec = 2048
PORT = 8042
# Previously shared info
POWER = 128
IV = bytes([0 for _ in range(16)])

def sendChat(socket, kdf, SENDER):
    PT = input()
    key = kdf(socket)
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    PT = pad(PT.encode(), 16)
    CT = cipher.encrypt(PT)
    socket.send(CT)

    receiveChat(socket, kdf, SENDER)

def receiveChat(socket, kdf, SENDER):
    key = kdf(socket)
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    CT = socket.recv()
    PT = cipher.decrypt(CT)
    PT = unpad(PT, 16).decode()

    print(f"{SENDER}: {PT}")

    sendChat(socket, kdf, SENDER)