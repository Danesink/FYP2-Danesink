from flask import Flask, render_template, request, redirect, flash
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import shutil

app = Flask(__name__)
app.secret_key = 'secret'  # Needed for flashing messages

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('Node1', exist_ok=True)
os.makedirs('Node2', exist_ok=True)

def pad(data):
    while len(data) % 16 != 0:
        data += b' '
    return data

def encrypt_file(key, filepath):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(filepath, 'rb') as f:
        plaintext = pad(f.read())
    ciphertext = cipher.encrypt(plaintext)

    encrypted_path = filepath + '.enc'
    with open(encrypted_path, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)
    
    return encrypted_path

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    uploaded_file = request.files['file']
    if uploaded_file.filename != '':
        filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(filepath)

        # Encrypt the uploaded file
        key = get_random_bytes(16)
        enc_path = encrypt_file(key, filepath)
        
    
        # Store in nodes
        
        for node in ['Node1', 'Node2']:
            shutil.copy(enc_path, os.path.join(node, os.path.basename(enc_path)))

        flash('File encrypted and stored in Node1 and Node2.')
        return render_template('index.html', key=key.hex())  #--pass key here
        
    return redirect('/')    

@app.route('/decrypt', methods=['POST'])
def decrypt():
    enc_file = request.files['enc_file']
    key_hex = request.form['key']

    if enc_file.filename == '':
        flash("No file selected for decryption.")
        return redirect('/')

    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        flash("Invalid key format. Please enter a valid hex key.")
        return redirect('/')

    # Save uploaded encrypted file temporarily
    enc_path = os.path.join(UPLOAD_FOLDER, enc_file.filename)
    enc_file.save(enc_path)

    # Decrypt
    with open(enc_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)

    # Save decrypted file
    decrypted_filename = enc_file.filename.replace('.enc', '.dec')
    decrypted_path = os.path.join(UPLOAD_FOLDER, decrypted_filename)

    with open(decrypted_path, 'wb') as f:
        f.write(plaintext.rstrip(b' '))

    flash(f"File decrypted successfully as '{decrypted_filename}'. Check uploads folder.")

    return redirect('/')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
