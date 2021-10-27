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

    # Replace in production
    # socket.send(str(A).encode())

    # Encrypting and sending A
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(sender_pubkey)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(str(A).encode())
    [socket.send(x)
     for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]

    # Receiving and decrypting B
    enc_session_key, nonce, tag, ciphertext = \
        [socket.recv() for _ in range(4)]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(prikey)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    B = Decimal(data.decode("utf-8"))
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
