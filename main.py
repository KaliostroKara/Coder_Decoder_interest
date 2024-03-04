import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode

def get_file_key(file_path):
    with open(file_path, 'rb') as f:
        file_content = f.read()
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(file_content)
    return digest.finalize()

def derive_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=103050,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key, salt

def encrypt(message, password):
    key, salt = derive_key(password)
    algorithm = algorithms.AES(key)
    iv = os.urandom(12)
    cipher = Cipher(algorithm, modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()
    return f"{urlsafe_b64encode(iv).decode('utf-8')}${urlsafe_b64encode(salt).decode('utf-8')}${urlsafe_b64encode(ct).decode('utf-8')}${urlsafe_b64encode(encryptor.tag).decode('utf-8')}"

def decrypt(combined, password):
    iv, salt, ct, tag = combined.split('$')
    iv = urlsafe_b64decode(iv)
    salt = urlsafe_b64decode(salt)
    ct = urlsafe_b64decode(ct)
    tag = urlsafe_b64decode(tag)
    key, _ = derive_key(password, salt)
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def main():
    while True:
        file_path = input("Введіть шлях до файлу-ключа: ")
        if os.path.exists(file_path):
            file_key = get_file_key(file_path)
        else:
            print("Файл не знайдено, спробуйте знову.")
            continue

        while True:
            action = input("Виберіть дію (1 - шифрування, 2 - дешифрування, 3 - вихід): ")
            if action == "1":
                message = input("Введіть повідомлення для шифрування: ")
                encrypted_message = encrypt(message, file_key)
                print("Зашифроване повідомлення:  \n ... ", encrypted_message)
            elif action == "2":
                encrypted_message = input("Введіть зашифроване повідомлення:  ")
                try:
                    decrypted_data = decrypt(encrypted_message, file_key)
                    print("Розшифроване повідомлення:  \n ... ", decrypted_data.decode('utf-8'))
                except Exception as e:
                    print(f"Помилка при дешифруванні: {e}")
            elif action == "3":
                print("Вихід з програми.")
                return
            else:
                print("Неправильний вибір, спробуйте знову.")

if __name__ == "__main__":
    main()
