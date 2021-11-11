from utilities import *
import zmq
from threading import Thread
from Crypto.Random import get_random_bytes


USER = "ALICE"
SENDER = "BOB"


def main():
    context = zmq.Context()
    client_socket = context.socket(zmq.PAIR)
    client_socket.connect(f"tcp://localhost:{PORT1}")

    server_socket = context.socket(zmq.PAIR)
    server_socket.bind(f"tcp://127.0.0.1:{PORT2}")

    # Save public key
    seed = get_random_bytes(sphincs.crypto_sign_SEEDBYTES)
    pubkey, priv_key = sphincs.generate_keypair(seed)

    with open(USER+"_pubkey.pem", 'wb') as wire:
        wire.write(pubkey)

    with open(SENDER+"_pubkey.pem", 'rb') as red:
        sender_pubkey = red.read()

    client_thread = Thread(target=fn_client, args=(
        client_socket, client_qskef, sender_pubkey, priv_key))
    server_thread = Thread(target=fn_server, args=(
        server_socket, server_qskef, SENDER, sender_pubkey, priv_key))

    threadList = [client_thread, server_thread]

    for thread in threadList:
        thread.start()

    print("You can now start messaging.")

    for thread in threadList:
        thread.join()


if __name__ == "__main__":
    main()
