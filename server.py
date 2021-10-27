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
    enc_session_key, nonce, tag, ciphertext = \
        [socket.recv() for _ in range(4)]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(prikey)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    A = Decimal(data.decode("utf-8"))
    # A = Decimal(socket.recv().decode())

    # Encrypting and sending B
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(sender_pubkey)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(str(B).encode())
    [socket.send(x)
     for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]

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

    # Save public key
    prikey = RSA.generate(2048)
    pubkey = prikey.public_key()

    with open(USER+"_pubkey.pem", 'wb') as wire:
        wire.write(pubkey.export_key('PEM'))
    input("Have you run the client yet?")
    with open(SENDER+"_pubkey.pem", 'rb') as red:
        sender_pubkey = RSA.import_key(red.read())

    receiveChat(socket, qskef, SENDER, sender_pubkey, prikey)


if __name__ == "__main__":
    main()
