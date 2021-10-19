from utilities import *


USER = "BOB"
SENDER = "ALICE"


def qskef(socket):
    """
    Server.
    Does a secure key exchange and gives you the key.
    """
    
    X = float(socket.recv().decode())
    # Bob's secret
    b = getrandbits(POWER)
    # Bob's public int
    B = Decimal(Decimal(b) * Decimal(X)) % 1

    A = Decimal(socket.recv().decode())
    socket.send(str(B).encode())
    # Bob gets A. Alice gets B (via sockets)

    # Bob's Symmetric Key
    KEY_B = (Decimal(b) * Decimal(A)) % 1

    PASS = str(KEY_B)[2:]

    # Additional step for security
    KEY = PBKDF1(PASS, "01234567".encode(), 16)
    return KEY


def main():
    context = zmq.Context()
    socket = context.socket(zmq.PAIR)
    socket.bind(f"tcp://*:{PORT}")
    receiveChat(socket, qskef, SENDER)


if __name__ == "__main__":
    main()
