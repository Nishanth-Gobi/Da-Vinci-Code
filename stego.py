from PIL import Image
from os.path import join
from aes import AES


# noinspection PyShadowingNames
class Steganography:

    def __init__(self, filepath: str, key: str):
        self.filepath = filepath
        self.key = key
        # Note it's safer to use a randomly generated iv and salt every time
        iv = 51492790537106978759285991234174886429065841288914036130886759345104714272607
        password_salt = b'n\xb8\x86s\xf7 \xf0\x9ed\xc6\xb1\xb6G{\x9e\x96'
        self.aes = AES(password=self.key, iv=iv, password_salt=password_salt)

    @staticmethod
    def get_binary_data(secret: str) -> list:
        # Convert message from ASCII to Binary
        bd = []
        for i in secret:
            bd.append(format(ord(i), '08b'))
        return bd

    @staticmethod
    def mod_pixel(pix, secret: list):

        im_data = iter(pix)

        for byte in secret:

            # Choose 3 pixels per iteration
            # Each pixel is represented by a tuple to 3 values
            pix = [i for i in im_data.__next__()[:3] + im_data.__next__()[:3] + im_data.__next__()[:3]]

            # In each iteration we store 8 bits of the message (1 byte) in the LSBs of 3 pixels
            for pos in range(0, 8):
                if byte[pos] == '0' and pix[pos] % 2 != 0:
                    pix[pos] -= 1
                elif byte[pos] == '1' and pix[pos] % 2 == 0:
                    if pix[pos] != 0:
                        pix[pos] -= 1
                    else:
                        pix[pos] += 1

            # The last value in every 3rd pixel is used to indicate if we should continue reading for the message
            # upon decryption. If the last value was odd, we stop reading, if it was even we continue reading.
            if byte == len(secret) - 1:
                if pix[-1] % 2 == 0:
                    if pix[-1] != 0:
                        pix[-1] -= 1
                    else:
                        pix[-1] += 1

            else:
                if pix[-1] % 2 != 0:
                    pix[-1] -= 1

            pix = tuple(pix)
            yield pix[0:3]
            yield pix[3:6]
            yield pix[6:9]

    def encode_enc(self, secret: list, image=None):
        if not image:
            print('Error: No Image')
        w = image.size[0]
        x, y = 0, 0

        for pixel in self.mod_pixel(pix=image.getdata(), secret=secret):
            image.putpixel((x, y), pixel)
            if x == w - 1:
                x = 0
                y += 1
            else:
                x += 1

    def encode(self, message: str):
        # Encrypting the message with key using AES

        secret = self.aes.encrypt(message)
        secret_bin = self.get_binary_data(secret=secret)

        cover_image = Image.open(join(self.filepath, "cover_image.png"), 'r')
        stego_image = cover_image.copy()

        self.encode_enc(secret=secret_bin, image=stego_image)

        new_filename = "stego_image.png"
        stego_image.save(join(self.filepath, new_filename))

        cover_image.close()
        stego_image.close()

    def decode(self) -> str:
        im = Image.open(join(self.filepath, "stego_image.png"), 'r')
        secret = ''
        im_data = iter(im.getdata())

        while True:
            pixels = [i for i in im_data.__next__()[:3] + im_data.__next__()[:3] + im_data.__next__()[:3]]
            bin_str = ''
            for pixel in pixels[:8]:
                if pixel % 2 == 0:
                    bin_str += '0'
                else:
                    bin_str += '1'
            secret += chr(int(bin_str, 2))
            if pixels[-1] % 2 != 0:
                return self.aes.decrypt(secret[0:-1])


if __name__ == '__main__':

    filepath = "static/files/"

    test = Steganography(filepath=filepath, key="pass")
    message = input("Enter secret: ")
    test.encode(message=message)
    print(test.decode())
