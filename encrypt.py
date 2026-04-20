from cryptoutils import cryptolibo
import misc_utils
import os
import pathlib
import shutil
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
def encrypt_folder(password, folder):
    files_list = [f for f in folder.rglob("*") if f.is_file() and f.parent.name != "backup" and f.name not in ("pass.hash", "pass.salt")]
    # salt generated automatic
    hash_password, salt = cryptolibo.hash.argon2(password, hash_len=64)
    password_len = len(password)
    iteration = round(password_len)
    # we don't need salt, we just need to stretch the password
    key_password, _ = cryptolibo.hash.pbkdf2(password, salt=password, length=128)
    with open (fr"{folder}\pass.hash", "w") as f:
        f.write(cryptolibo.encrypt.chacha20_poly1305(key_password, hash_password))
    with open (fr"{folder}\pass.salt", "w") as f:
        f.write(cryptolibo.encrypt.aes_gcm(key_password, salt))
    pathlib.Path(fr"{folder}\backup").mkdir(exist_ok=True)

    def process_file(file):
        with open(file, "rb") as f:
            read_bytes = f.read()
            encrypted_bytes = cryptolibo.encrypt.chacha20_poly1305(key_password, read_bytes)
        with open(fr"{folder}\backup\{file.name}.backup", "wb") as f:
            f.write(read_bytes)
        with open(file, "wb") as f:
            f.write(encrypted_bytes.encode('utf-8'))
        encrypted_name = cryptolibo.encrypt.aes_gcm(key_password, file.name)
        encrypted_name = encrypted_name.replace("/", "_").replace("+", "-")
        os.rename(file, file.with_name(encrypted_name))
        misc_utils.safe_delete(fr"{folder}\backup\{file.name}.backup")

    with ThreadPoolExecutor(max_workers=6) as executor:
        list(tqdm(executor.map(process_file, files_list), total=len(files_list), desc="Encrypting", unit="file"))
    shutil.rmtree(fr"{folder}\backup")