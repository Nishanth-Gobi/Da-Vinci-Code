import binascii
import pbkdf2
import pyaes


# noinspection PyShadowingNames
class AES:

    def __init__(self, password: str, iv: int, password_salt: bytes):
        self.password = password
        self.key = pbkdf2.PBKDF2(password, password_salt).read(32)
        self.iv = iv

    def encrypt(self, plain_text: str) -> str:
        aes = pyaes.AESModeOfOperationCTR(self.key, pyaes.Counter(self.iv))
        cipher_text = aes.encrypt(plain_text)
        return binascii.hexlify(cipher_text).decode("utf-8")

    def decrypt(self, cipher_text: str) -> str:
        aes = pyaes.AESModeOfOperationCTR(self.key, pyaes.Counter(self.iv))
        plain_text = binascii.unhexlify(cipher_text.encode("utf-8"))
        return aes.decrypt(plain_text).decode("utf-8")


if __name__ == '__main__':
    iv = 51492790537106978759285991234174886429065841288914036130886759345104714272607
    password_salt = b'n\xb8\x86s\xf7 \xf0\x9ed\xc6\xb1\xb6G{\x9e\x96'
    test = AES(password="pass", iv=iv, password_salt=password_salt)

    secret = test.encrypt("a secret")
    print("encrypt: ", secret)
    print("decrypt: ", test.decrypt(secret))
