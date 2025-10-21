import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

SERVER = "192.168.1.11"
PORT = 5000

# Carregar chave pública do servidor
with open("server_public_key.txt", "r") as f:
    e, n = map(int, f.read().split(","))
    server_public = RSA.construct((n, e))

def encrypt_rsa(data):
    cipher_rsa = PKCS1_OAEP.new(server_public)
    return cipher_rsa.encrypt(data)

def encrypt_aes(msg, key, iv):
    cipher_aes = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher_aes.encrypt(msg.encode())

def decrypt_aes(ciphertext, key, iv):
    cipher_aes = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher_aes.decrypt(ciphertext).decode()

def handle_recv(sock, session_key, iv):
    while True:
        data = sock.recv(4096)
        if not data:
            break
        msg = decrypt_aes(data, session_key, iv)
        print("\n> " + msg)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER, PORT))
        print("Conectado ao servidor")

        session_key = get_random_bytes(32)
        iv = get_random_bytes(16)
        key_iv = session_key + iv

        s.sendall(encrypt_rsa(key_iv))

        t = threading.Thread(target=handle_recv, args=(s, session_key, iv), daemon=True)
        t.start()

        while True:
            msg = input()
            s.sendall(encrypt_aes(msg, session_key, iv))

if __name__ == "__main__":
    main()
