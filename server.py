import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
import base64

HOST = '127.0.0.1'  
PORT = 65434        

key_des = b'1234567890123456'  

def decrypt_message(encrypted_message, key_des):
    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:16]  # Initial Vector (IV)
    cipher = AES.new(key_des, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
    return decrypted_data.decode('utf-8')

def get_public_key_from_pka():
    public_key_pem = """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmC93r+vBdtpTni2sY7FH
    kZXuFbCWdY+dE2ANzMfVvc5Uq3+F8XLT5ZQwGookKT59S3f0RjIbbjAmk6w2bvYT
    +veTiVbjbZdf90k2e4Ezw5fys34sIyU6u8V7we29Pg7nvO4RGLEyqlaIzn6qrr0y
    wtvtmz+/LVkz1HzZ5bp7RPTfbCS/+W9fksXCxKD7KqZqaMUW1DWAhEqA/D4Ahzlj
    LDL0E0ETluywudmuGr52/Rzua6qE5RgKUWoHziTeLxxqOWcIUedKBOT/i3cbhBln
    KckwflLv2ojZgqxsKeVZCdgOfQcUJM1VnVeiwExlBVf0Ly5kD2u058vnzOc272Gw
    3wIDAQAB
    -----END PUBLIC KEY-----
    """
    return RSA.import_key(public_key_pem)

def encrypt_des_key_with_rsa(public_key, key_des):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(key_des)
    return encrypted_key

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("Server menunggu koneksi...")
    conn, addr = s.accept()
    with conn:
        print('Terhubung oleh', addr)
        
        rsa_public_key = get_public_key_from_pka()
        
        encrypted_des_key = encrypt_des_key_with_rsa(rsa_public_key, key_des)
        
        conn.sendall(encrypted_des_key)
        print("Kunci DES terenkripsi telah dikirim.")
        
        encrypted_message = conn.recv(1024).decode('utf-8')
        print("Pesan terenkripsi:", encrypted_message)
        
        try:
            decrypted_message = decrypt_message(encrypted_message, key_des)
            print("Pesan didekripsi:", decrypted_message)
        except Exception as e:
            print("Gagal mendekripsi pesan:", e)
