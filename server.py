from utilities import *
from Crypto.PublicKey import RSA


USER = "BOB"
SENDER = "ALICE"


def qskef(socket, sender_pubkey, prikey):
    """
    Server.
    Does a secure key exchange and gives you the key.
    """

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


def main():

    context = zmq.Context()
    server_socket = context.socket(zmq.PAIR)
    server_socket.bind(f"tcp://*:{PORT1}")

    client_socket = context.socket(zmq.PAIR)
    client_socket.connect(f"tcp://localhost:{PORT2}")

    # Save public key
    prikey = RSA.generate(2048)
    pubkey = prikey.public_key()

    with open(USER+"_pubkey.pem", 'wb') as wire:
        wire.write(pubkey.export_key('PEM'))

    with open(SENDER+"_pubkey.pem", 'rb') as red:
        sender_pubkey = RSA.import_key(red.read())

    client_thread = Thread(target=fn_client, args=(
        client_socket, qskef, SENDER, sender_pubkey, prikey))
    server_thread = Thread(target=fn_server, args=(
        server_socket, qskef, SENDER, sender_pubkey, prikey))

    threadList = [client_thread, server_thread]

    for thread in threadList:
        thread.start()

    for thread in threadList:
        thread.join()


if __name__ == "__main__":
    main()
