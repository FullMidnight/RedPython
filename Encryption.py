import base64
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA3_256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome import Random
from Cryptodome.Util import Padding
from cryptography.fernet import Fernet



class Cipher_RSA(object):
    def __init__(self, path, private_key_decryptor=""):
        self.key = RSA.importKey(open(path).read(), passphrase=private_key_decryptor)
        self.cipher = PKCS1_OAEP.new(self.key)
    def encrypt(self, text):
        return self.cipher.encrypt(text)
    def decrypt(self, ciphertext):
        return self.cipher.decrypt(ciphertext)

class Cipher_Public_RSA:
    def __init__(self, key_bytes):
        self.key = RSA.importKey(key_bytes)
        self.cipher = PKCS1_OAEP.new(self.key)
    def encrypt(self, text):
        if isinstance(text, str):
            bytes_obj =  self.cipher.encrypt(text.encode('utf-8'))
            return str(base64.b64encode(bytes_obj),'utf-8')
        bytes_obj =  self.cipher.encrypt(text)
        return str(base64.b64encode(bytes_obj),'utf-8')

class FernetHelper:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.encryptor = Fernet(self.key)
    def encrypt(self, plain_text):
        string = ''
        try:
            string = plain_text.encode('utf-8')
        except AttributeError:
            string = plain_text
        return self.encryptor.encrypt(string)
    def decrypt(self, cipher_text):
        string = ''
        try:
            string = cipher_text.encode('utf-8')
        except AttributeError:
            string = cipher_text
        return self.encryptor.decrypt(string)
    def set_key(self, key):
        self.key = key
        self.encryptor = Fernet(self.key)
    def get_key(self):
        return self.key
    def rotate_key(self):
        self.key = Fernet.generate_key()
        self.encryptor = Fernet(self.key)

class AesEncryptamajig:
    """Based off Encryptamajig from John Bubriski"""
    def __init__(self, key):
        self.password = key
    def encrypt(plain_text):
        salt = Random.get_random_bytes(32)
        key_and_iv = KDF.PBKDF2(self.password, salt, dkLen=48)
        key = key_and_iv[:32]
        iv = key_and_iv[32:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        if type(plain_text) is not str:
            plain_text = str(plain_text,'utf-8')
        ready = pad(plain_text.encode('utf-8'), AES.block_size)
        cipher_text = cipher.encrypt(ready)
        res = salt + cipher_text
        return str(base64.b64encode(res),'utf-8')
    def decrypt(encrypted_text):
        if type(encrypted_text) is not str:
            encrypted_text = str(encrypted_text, 'utf-8')
        encrypted_text = base64.b64decode(encrypted_text)
        salt = encrypted_text[:32]
        cipher_text = encrypted_text[32:]
        key_and_iv = KDF.PBKDF2(self.password, salt, dkLen=48)
        key = key_and_iv[:32]
        iv = key_and_iv[32:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(cipher_text),AES.block_size)
        return str(plaintext,'utf-8').strip()