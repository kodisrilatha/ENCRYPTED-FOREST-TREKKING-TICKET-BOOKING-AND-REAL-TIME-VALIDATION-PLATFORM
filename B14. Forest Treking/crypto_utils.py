from Crypto.Hash import RIPEMD160
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import base64

def get_ripemd_hash(data):
    """Generate RIPEMD-160 hash of data"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    h = RIPEMD160.new()
    h.update(data)
    return h.hexdigest()

def derive_key_from_hash(hash_value):
    """Derive a 32-byte key from RIPEMD hash for AES encryption"""
    extended_hash = (hash_value * 2)[:32]
    return extended_hash.encode('utf-8')

def encrypt_file(file_path, output_path):
    """Encrypt a file using RIPEMD-160 based key derivation and AES"""
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    file_hash = get_ripemd_hash(plaintext)
    key = derive_key_from_hash(file_hash)
    
    iv = os.urandom(16)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)
    
    return file_hash

def decrypt_file(encrypted_path, output_path, encryption_hash):
    """Decrypt a file using the RIPEMD hash"""
    with open(encrypted_path, 'rb') as f:
        data = f.read()
    
    iv = data[:16]
    ciphertext = data[16:]
    
    key = derive_key_from_hash(encryption_hash)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    return True

def encrypt_text(text):
    """Encrypt text using RIPEMD-160 based key and AES"""
    if isinstance(text, str):
        text = text.encode('utf-8')
    
    text_hash = get_ripemd_hash(text)
    key = derive_key_from_hash(text_hash)
    
    iv = os.urandom(16)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(text, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
    
    return encrypted_data, text_hash

def decrypt_text(encrypted_data, encryption_hash):
    """Decrypt text using the RIPEMD hash"""
    data = base64.b64decode(encrypted_data)
    
    iv = data[:16]
    ciphertext = data[16:]
    
    key = derive_key_from_hash(encryption_hash)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    return plaintext.decode('utf-8')

def verify_file_integrity(file_path, original_hash):
    """Verify file integrity using RIPEMD-160 hash"""
    with open(file_path, 'rb') as f:
        content = f.read()
    
    current_hash = get_ripemd_hash(content)
    return current_hash == original_hash
