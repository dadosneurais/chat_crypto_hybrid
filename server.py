import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

HOST = "192.168.1.11"
PORT = 5000

with open("server_private_key.txt", "r") as f:
    d, n = map(int, f.read().split(","))
    server_private = RSA.construct((n, 65537, d))

def decrypt_rsa(data):
    cipher_rsa = PKCS1_OAEP.new(server_private)
    return cipher_rsa.decrypt(data)

def decrypt_aes(ciphertext, key, iv):
    cipher_aes = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher_aes.decrypt(ciphertext).decode()

def encrypt_aes(msg, key, iv):
    cipher_aes = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher_aes.encrypt(msg.encode())

def save_chat(message, filename="chat.txt"):
    with open(filename, "a", encoding="utf-8") as f:
        f.write(message + "\n")

def handle_recv(conn, session_key, iv):
    while True:
        data = conn.recv(4096)
        if not data:
            break
        msg = decrypt_aes(data, session_key, iv)
        print("\n> " + msg)
        save_chat(f"Cliente: {msg}")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print("Aguardando conexão...")
        conn, addr = s.accept()
        print("Conectado por", addr)

        enc_key = conn.recv(1024)
        session_key_iv = decrypt_rsa(enc_key)
        session_key = session_key_iv[:32]
        iv = session_key_iv[32:]
   
        t = threading.Thread(target=handle_recv, args=(conn, session_key, iv), daemon=True)
        t.start()

        while True:
            msg = input()
            enc_msg = encrypt_aes(msg, session_key, iv)
            conn.sendall(enc_msg)
            save_chat(f"Servidor: {msg}")

if __name__ == "__main__":
    main()
