import random
import string
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
import random, string, base64
from Cryptodome.Random import get_random_bytes
from base64 import b64encode
from base64 import b64decode


class Cryptography:

    def Create_key(self):
        return ''.join(
            random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(32))

    def Create_IV(self):
        return ''.join(
            random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(16))

    @staticmethod
    def Encrypt(vkey, viv, text_plane):
        iv = bytes(viv, 'UTF-8')
        key = bytes(vkey, 'UTF-8')
        text = bytes(text_plane, 'utf-8')
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ct_bytes = cipher.encrypt(text)

        return b64encode(ct_bytes).decode('utf-8')

    @staticmethod
    def Decrypt(vkey, viv, encoded_message):
        iv = bytes(viv, 'UTF-8')
        key = bytes(vkey, 'UTF-8')
        ct = b64decode(encoded_message)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        pt = cipher.decrypt(ct)
        return pt.decode('utf-8')
