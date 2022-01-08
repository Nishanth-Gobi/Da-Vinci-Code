from flask import Flask, render_template, request, redirect, url_for
from os.path import join

from stego import Steganography

app = Flask(__name__)
UPLOAD_FOLDER = 'static/files/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}


@app.route("/")
def home():
    return render_template('home.html')


@app.route("/encrypt", methods=['GET', 'POST'])
def get_image():

    if request.method == 'GET':
        return render_template('encrypt.html')

    # Check if the user has entered the secret message
    if 'file' in request.files and 'Secret' in request.values:
        uploaded_image = request.files['file']
        message = request.values.get('Secret')
        password = request.values.get("key")

        filepath = join(app.config['UPLOAD_FOLDER'], "cover_image.png")
        uploaded_image.save(filepath)

        im = Steganography(filepath=app.config['UPLOAD_FOLDER'], key=password)
        im.encode(message=message)
        return render_template('encrypt.html', value=filepath, image_flag=True, secret_flag=True)

    return redirect(url_for('encrypt'))


@app.route("/decrypt", methods=['GET', 'POST'])
def get_image_to_decrypt():

    if request.method == 'GET':
        return render_template('decrypt.html')

    if 'key' in request.values:
        password = request.values.get('key')
        filepath = join(app.config['UPLOAD_FOLDER'], "stego_image.png")
        im = Steganography(filepath=app.config['UPLOAD_FOLDER'], key=password)
        message = im.decode()
        return render_template('decrypt.html', value=filepath, message=message)

    if 'file' in request.files:
        uploaded_image = request.files['file']
        filepath = join(app.config['UPLOAD_FOLDER'], "stego_image.png")
        uploaded_image.save(filepath)
        return render_template('decrypt.html', value=filepath)


if __name__ == '__main__':
    app.run(debug=True)
