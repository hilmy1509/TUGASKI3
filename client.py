import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
import base64
import os
import getpass

HOST = '127.0.0.1'  
PORT = 65434        

def decrypt_des_key_with_rsa(private_key, encrypted_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    des_key = cipher_rsa.decrypt(encrypted_key)
    return des_key

def encrypt_message(message, des_key):
    iv = os.urandom(16)
    cipher = AES.new(des_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def load_private_key(path):
    with open(path, "r") as file:
        private_key_pem = file.read()
    return RSA.import_key(private_key_pem)

private_key_path = r"E:\OneDrive - Institut Teknologi Sepuluh Nopember\Dokumen\Keamanan Informasi\Tugas 3\private.pem"

private_key = load_private_key(private_key_path)

print("Masukkan pesan yang ingin dienkripsi dan dikirim:")

user_input = ""
while True:
    char = getpass.getpass(prompt="")  
    if char == '':  
        break
    user_input += char  

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    encrypted_des_key = s.recv(256)  # Panjang buffer harus cukup
    print("Kunci DES terenkripsi diterima dari server.")
    
    try:
        des_key = decrypt_des_key_with_rsa(private_key, encrypted_des_key)
        print("Kunci DES berhasil didekripsi.")
    except Exception as e:
        print("Gagal mendekripsi kunci DES:", e)
        s.close()
        exit()
    
    encrypted_message = encrypt_message(user_input, des_key)
    
    s.sendall(encrypted_message.encode('utf-8'))
    print("Pesan telah terenkripsi dan dikirim ke server.")
