from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cocks.cocks import CocksPKG, Cocks


class ClientCryptoModule:
    def __init__(self):
        print()

    @staticmethod
    def encrypt_aes_cbc(aes_key, iv, data):
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return ciphertext

    @staticmethod
    def decrypt_aes_cbc(aes_key, ciphertext, iv):
        #iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    @staticmethod
    def generate_aes_key_and_iv():
        aes_key = get_random_bytes(32)
        iv = get_random_bytes(16)
        return aes_key, iv

    @staticmethod
    def pad_key(unpadded_key):
        padded_key = pad(unpadded_key, 32)
        return padded_key

    @staticmethod
    def encrypt_aes_eax(aes_key, data):
        cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, tag, cipher.nonce

    @staticmethod
    def decrypt_aes_eax(aes_key, tag, nonce, ciphertext):
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce= nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext

    @staticmethod
    def decrypt_cocks(r, a, n, ciphertext):
        cocks = Cocks(n)
        msg = cocks.decrypt(ciphertext, r, a)
        return msg


