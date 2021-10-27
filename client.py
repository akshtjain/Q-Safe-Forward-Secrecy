from utilities import *
from Crypto.PublicKey import RSA


USER = "ALICE"
SENDER = "BOB"
cryptogen = SystemRandom()


def qskef(socket, sender_pubkey, prikey):
    """
    Client.
    Does a secure key exchange and gives you the key.
    """

    X = cryptogen.random()
    socket.send(str(X).encode())
    # Alice's secret
    a = getrandbits(POWER)
    # C(a) -> a' | C(y) = (x * y) % 1
    # Alice's public key
    A = Decimal(Decimal(a) * Decimal(X)) % 1

    # Encrypting and sending A
    send_decimal(socket, sender_pubkey, A)
    # socket.send(str(A).encode())

    # Receiving and decrypting B
    B = recv_decimal(socket, prikey)
    # B = Decimal(socket.recv().decode())
    # Bob gets A. Alice gets B (via sockets)

    # Alice's Symmetric Key
    KEY_A = (Decimal(a) * Decimal(B)) % 1

    PASS = str(KEY_A)[2:]

    # Additional step for security
    KEY = PBKDF1(PASS, "01234567".encode(), 16)
    return KEY


def main():

    context = zmq.Context()
    socket = context.socket(zmq.PAIR)
    socket.connect(f"tcp://localhost:{PORT}")

    # Save public key
    prikey = RSA.generate(2048)
    pubkey = prikey.public_key()

    with open(USER+"_pubkey.pem", 'wb') as wire:
        wire.write(pubkey.export_key('PEM'))

    with open(SENDER+"_pubkey.pem", 'rb') as red:
        sender_pubkey = RSA.import_key(red.read())

    sendChat(socket, qskef, SENDER, sender_pubkey, prikey)


if __name__ == "__main__":
    main()
