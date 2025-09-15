import os
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
import getpass

# Folder where keys are saved
KEYS_FOLDER = r"D:\Keys"

# Key file names
AES_KEY_FILE = os.path.join(KEYS_FOLDER, ".aes_key.sys")
DES_KEY_FILE = os.path.join(KEYS_FOLDER, ".des_key.sys")
RSA_PRIVATE_FILE = os.path.join(KEYS_FOLDER, ".rsa_private.sys")

# Check if all keys exist
for key_file in [AES_KEY_FILE, DES_KEY_FILE, RSA_PRIVATE_FILE]:
    if not os.path.exists(key_file):
        print(f"❌ Key file not found: {key_file}")
        exit(1)

# Load keys from KEYS_FOLDER
with open(AES_KEY_FILE, "rb") as f:
    aes_key = f.read()
with open(DES_KEY_FILE, "rb") as f:
    des_key = f.read()
with open(RSA_PRIVATE_FILE, "rb") as f:
    rsa_private = RSA.import_key(f.read())

SOURCE_FOLDERS = [
    r"D:\RANSOMWARE\documenation",
    r"D:\RANSOMWARE\photos",
    r"D:\RANSOMWARE\songs"
]

# Decryption functions
def decrypt_aes(file_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return data

def decrypt_des(file_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(8)
        ciphertext = f.read()
    cipher = DES.new(key, DES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return data

def decrypt_rsa_hybrid(file_path, priv_key):
    with open(file_path, 'rb') as f:
        encrypted_key_iv = f.read(256)   # RSA 2048-bit size = 256 bytes
        ciphertext = f.read()
    rsa_cipher = PKCS1_OAEP.new(priv_key)
    key_iv = rsa_cipher.decrypt(encrypted_key_iv)
    aes_key_local = key_iv[:16]
    iv = key_iv[16:]
    aes_cipher = AES.new(aes_key_local, AES.MODE_CBC, iv)
    data = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
    return data

def decrypt_all_files():
    for root_folder in SOURCE_FOLDERS:
        if not os.path.exists(root_folder):
            print(f"⚠ Folder does not exist: {root_folder}  - Skipping")
            continue
        for root, dirs, files in os.walk(root_folder):
            for filename in files:
                src_path = os.path.join(root, filename)
                ext = filename.split('.')[-1].lower()
                try:
                    if ext in ['txt', 'csv', 'json', 'jpg', 'jpeg', 'png']:
                        data = decrypt_aes(src_path, aes_key)
                    elif ext in ['mp3', 'wav']:
                        data = decrypt_des(src_path, des_key)
                    elif ext in ['docx', 'pptx']:
                        data = decrypt_rsa_hybrid(src_path, rsa_private)
                    else:
                        print(f"❌ Skipped (unsupported file): {src_path}")
                        continue

                    with open(src_path, 'wb') as f:
                        f.write(data)
                    print(f"✅ Decrypted: {src_path}")
                except Exception as e:
                    print(f"⚠ Error decrypting {src_path}: {e}")

if __name__ == "__main__":
    correct_code = "2004"
    
    entered_code = getpass.getpass("Enter decryption code: ").strip()
    
    if entered_code == correct_code:
        print("Code accepted. Starting decryption...")
        decrypt_all_files()
        print("\n📥 Decryption complete! All supported files have been restored in-place.")
    else:
        print("❌ Incorrect code. Decryption aborted.")