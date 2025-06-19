from flask import Flask, render_template, request, send_file, jsonify
from PIL import Image
import io
import os
import binascii
from base64 import urlsafe_b64encode, urlsafe_b64decode
from flask_cors import CORS

# For encryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# Configure upload folder and maximum content length
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 MB max upload size

# Ensure the upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Encryption/Decryption Helper Functions ---

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a strong key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # For AES256
        salt=salt,
        iterations=100000, # More iterations for stronger security
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key

def encrypt_message(message: str, password: str) -> bytes:
    """Encrypts a message using AES GCM and a password. Returns IV + Ciphertext + Tag."""
    salt = os.urandom(16) # Generate a random salt for each encryption
    key = derive_key(password, salt)
    
    iv = os.urandom(16) # AES block size is 16 bytes for IV
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt and get the tag
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag

    # Combine salt, IV, ciphertext, and tag for storage
    # The salt is needed to derive the key during decryption
    # The IV is needed for GCM mode
    # The tag is needed for GCM integrity verification
    return salt + iv + ciphertext + tag

def decrypt_message(encrypted_data: bytes, password: str) -> str | None:
    """Decrypts a message using AES GCM and a password. Returns decrypted message or None if decryption fails."""
    # Salt (16 bytes) + IV (16 bytes) + GCM Tag (16 bytes) = 48 bytes minimum overhead
    if len(encrypted_data) < 48: 
        print(f"Decryption failed: Encrypted data too short. Length: {len(encrypted_data)}")
        return None # Not enough data for salt, IV, and tag/ciphertext

    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext_with_tag = encrypted_data[32:] # Renamed for clarity

    # The GCM tag is the last 16 bytes of the ciphertext_with_tag
    tag = ciphertext_with_tag[-16:]
    ciphertext = ciphertext_with_tag[:-16]

    try:
        key = derive_key(password, salt)
        # When decrypting with GCM, the tag is passed to the mode constructor
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_message_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_message_bytes.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None # Decryption failed (e.g., incorrect password, corrupted data, or integrity check failed)


# --- Steganography Helper Functions (Modified to handle bytes) ---
def bytes_to_bits(data: bytes) -> str:
    """Converts bytes into a binary string."""
    return ''.join(f'{byte:08b}' for byte in data)

def bits_to_bytes(bits: str) -> bytes:
    """Converts a binary string back into bytes."""
    # Pad bits to be a multiple of 8 if necessary for the last byte
    if len(bits) % 8 != 0:
        bits = bits + '0' * (8 - (len(bits) % 8))

    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = int(bits[i:i+8], 2)
        byte_array.append(byte)
    return bytes(byte_array)

def hide_message_lsb(image_input_path, message_bytes: bytes, output_path):
    """
    Hides a message (as bytes) within an image using LSB steganography.
    """
    try:
        img = Image.open(image_input_path).convert("RGBA")
        width, height = img.size

        # Append a terminator to the message bits.
        # Use a longer, more robust terminator in binary, ensuring it's not easily part of encrypted data
        TERMINATOR = '00000000111111110000000011111111' # A distinct 4-byte pattern (00FF00FF)
        message_bits = bytes_to_bits(message_bytes) + TERMINATOR
        
        # We use 3 bits per pixel (R, G, B channels)
        max_bits_capacity = width * height * 3
        if len(message_bits) > max_bits_capacity:
            raise ValueError(f"Message ({len(message_bits)} bits) is too large for the image "
                             f"({max_bits_capacity} bits capacity). Max message size: {max_bits_capacity // 8} bytes.")

        data_index = 0
        pixels = img.load()

        for row in range(height):
            for col in range(width):
                pixel = list(pixels[col, row])
                
                for i in range(3): # Iterate over R, G, B channels
                    if data_index < len(message_bits):
                        # Clear the LSB and set it to the message bit
                        pixel[i] = pixel[i] & ~1 | int(message_bits[data_index])
                        data_index += 1
                
                pixels[col, row] = tuple(pixel)
                
                if data_index >= len(message_bits):
                    break # All bits hidden
            if data_index >= len(message_bits):
                break # All bits hidden

        img.save(output_path)
        return True
    except ValueError as e:
        # Re-raise ValueError from capacity check
        raise e
    except Exception as e:
        print(f"Error hiding message: {e}")
        return False

def extract_message_lsb(image_input_path) -> bytes | None:
    """
    Extracts a hidden message (as bytes) from an image using LSB steganography.
    """
    try:
        img = Image.open(image_input_path).convert("RGBA")
        width, height = img.size
        binary_message = ""
        TERMINATOR = '00000000111111110000000011111111' # Must match hiding terminator

        pixels = img.load()

        for row in range(height):
            for col in range(width):
                pixel = list(pixels[col, row])
                
                for i in range(3): # Iterate over R, G, B channels
                    binary_message += str(pixel[i] & 1)
                    
                    if TERMINATOR in binary_message:
                        end_index = binary_message.find(TERMINATOR)
                        # Return the decoded bytes up to the terminator
                        return bits_to_bytes(binary_message[:end_index])
        
        # If loop finishes without finding the terminator
        print("Terminator not found in the image.")
        return None 
    except Exception as e:
        print(f"Error extracting message: {e}")
        return None

# --- Flask Routes ---

@app.route('/')
def index():
    """Renders the main index page (Steganography Module)."""
    return render_template('index.html')

@app.route('/how-it-works.html')
def how_it_works():
    """Renders the Protocol Overview page."""
    return render_template('how-it-works.html')

@app.route('/about-us.html')
def about_us():
    """Renders the About CipherGuard page."""
    return render_template('about-us.html')

@app.route('/contact.html')
def contact():
    """Renders the Contact Operations page."""
    return render_template('contact.html')


@app.route('/embed', methods=['POST'])
def embed():
    """Handles the message embedding request with password protection."""
    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400
    if 'message' not in request.form:
        return jsonify({'error': 'No message provided'}), 400
    if 'password' not in request.form or not request.form['password']:
        return jsonify({'error': 'No password provided'}), 400

    file = request.files['image']
    message = request.form['message']
    password = request.form['password']

    if file.filename == '':
        return jsonify({'error': 'No selected image file'}), 400
    
    if not file.mimetype.startswith('image/'):
        return jsonify({'error': 'Uploaded file is not an image.'}), 400

    temp_input_filepath = None
    try:
        # Generate a unique filename for the temporary input file
        unique_filename = f"{os.urandom(16).hex()}_{file.filename}"
        temp_input_filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(temp_input_filepath)

        # Encrypt the message before hiding
        encrypted_message_bytes = encrypt_message(message, password)
        
        base, ext = os.path.splitext(file.filename)
        output_filename = f"stego_{base}.png"
        output_filepath = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

        # Pass the raw encrypted bytes to the LSB hiding function
        if hide_message_lsb(temp_input_filepath, encrypted_message_bytes, output_filepath):
            return send_file(output_filepath, mimetype='image/png', as_attachment=True, download_name=output_filename)
        else:
            return jsonify({'error': 'Failed to embed message. Message might be too large or image format issues.'}), 500
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        print(f"An unexpected error occurred during embedding: {e}")
        return jsonify({'error': f'An unexpected error occurred during embedding: {e}'}), 500
    finally:
        # Ensure temporary input file is removed
        if temp_input_filepath and os.path.exists(temp_input_filepath):
            os.remove(temp_input_filepath)
        # In a production environment, you might also want to ensure the output_filepath is cleaned up
        # if the send_file operation somehow fails or is interrupted.
        # For this simple example, it's generally handled by Flask or OS cleanup.

@app.route('/extract', methods=['POST'])
def extract():
    """Handles the message extraction request with password protection."""
    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400
    if 'password' not in request.form or not request.form['password']:
        return jsonify({'error': 'No password provided'}), 400

    file = request.files['image']
    password = request.form['password']

    if file.filename == '':
        return jsonify({'error': 'No selected image file'}), 400
    
    if not file.mimetype.startswith('image/'):
        return jsonify({'error': 'Uploaded file is not an image.'}), 400

    temp_input_filepath = None
    try:
        # Generate a unique filename for the temporary input file
        unique_filename = f"{os.urandom(16).hex()}_{file.filename}"
        temp_input_filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(temp_input_filepath)

        extracted_encrypted_bytes = extract_message_lsb(temp_input_filepath)
        
        if extracted_encrypted_bytes:
            # Decrypt the extracted bytes using the provided password
            extracted_message = decrypt_message(extracted_encrypted_bytes, password)
            
            if extracted_message is not None:
                return jsonify({'message': extracted_message})
            else:
                return jsonify({'message': 'Decryption failed. Incorrect password or corrupted message.'}), 400
        else:
            return jsonify({'message': 'No hidden message found or extraction failed. Possible incorrect image.'})
    except Exception as e:
        print(f"An unexpected error occurred during extraction or decryption: {e}")
        return jsonify({'error': f'An unexpected error occurred during extraction or decryption: {e}'}), 500
    finally:
        if temp_input_filepath and os.path.exists(temp_input_filepath):
            os.remove(temp_input_filepath)

if __name__ == '__main__':
    # When deploying, set debug=False and use a production-ready WSGI server like Gunicorn or uWSGI
    app.run()
