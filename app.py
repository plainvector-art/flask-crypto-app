import os
import base64
from io import BytesIO
from flask import Flask, render_template, request, send_file, redirect, flash, url_for
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

# Fallback random string for sessions if environment variable isn't configured
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))

# Fixed salt for key derivation. Ensures identical passwords always derive 
# the identical key on this machine across different operations.
STATIC_SALT = b'\x1c\x9f\xae\xfa\xbc\xdd\x11\xeb\x8d\xcd\x02\x42\xac\x13\x00\x03'

def generate_secure_key(password: str) -> bytes:
    """Uses PBKDF2HMAC to securely convert a user password into a 32-byte key."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=STATIC_SALT,
        iterations=480_000, # Slow processing prevents automated dictionary attacks
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        action = request.form.get('action')
        password = request.form.get('password')
        file = request.files.get('file')

        # Form safety checks
        if not file or file.filename == '':
            flash("Please choose a file to proceed.", "error")
            return redirect(url_for('index'))
        if not password:
            flash("A password is required to encrypt or decrypt data.", "error")
            return redirect(url_for('index'))

        filename = secure_filename(file.filename)
        if not filename.lower().endswith('.txt'):
            flash("Unsupported file format. Please upload a '.txt' file.", "warning")
            return redirect(url_for('index'))

        # Read into RAM safely - no local system disk write
        file_data = file.read()

        key = generate_secure_key(password)
        fernet = Fernet(key)

        try:
            if action == 'encrypt':
                processed = fernet.encrypt(file_data)
                out_filename = f'encrypted_{filename}'
                flash("Success! Your file has been safely encrypted.", "success")
            elif action == 'decrypt':
                processed = fernet.decrypt(file_data)
                out_filename = f'decrypted_{filename}'
                flash("Success! Your file has been safely decrypted.", "success")
            else:
                flash("Invalid action execution block selected.", "error")
                return redirect(url_for('index'))
        except Exception:
            # Shields structural validation error traces from crashing the UI
            flash("Cryptographic failure: Verify the input password matches the original cryptographic key.", "error")
            return redirect(url_for('index'))

        # Download directly back out via streams
        return send_file(
            BytesIO(processed),
            as_attachment=True,
            download_name=out_filename,
            mimetype='application/octet-stream'
        )

    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)