from cryptoutils import cryptolibo
import misc_utils
import os
import pathlib
import shutil
from tqdm import tqdm
def encrypt_folder(password, folder):
    files_list = [f for f in folder.rglob("*") if f.is_file() and f.parent.name != "backup" and f.name not in ("pass.hash", "pass.salt")]
    # salt generated automatic
    hash_password, salt = cryptolibo.hash.pbkdf2(password, length=64)
    password_len = len(password)
    while password_len < 200000:
        # This will add a little bit of secure
        password_len = password_len * 1.5
    iteration = round(password_len)
    # we don't need salt, we just need to stretch the password
    key_password, _ = cryptolibo.hash.pbkdf2(password, salt=password, length=128, iterations=iteration)
    with open (fr"{folder}\pass.hash", "w") as f:
        f.write(cryptolibo.encrypt.chacha20_poly1305(key_password, hash_password))
    with open (fr"{folder}\pass.salt", "w") as f:
        f.write(cryptolibo.encrypt.aes_gcm(key_password, salt))
    pathlib.Path(fr"{folder}\backup").mkdir(exist_ok=True)
    for file in tqdm(files_list, desc="Encrypting", unit="file"):
        with open(file, "rb") as f:
            read_bytes = f.read()
            encrypted_bytes = cryptolibo.encrypt.chacha20_poly1305(key_password, read_bytes)
        with open(fr"{folder}\backup\{file.name}.backup", "wb") as f:
            f.write(read_bytes)
        with open(file, "wb") as f:
            # encode needed! chacha20_poly1305 always returns base64 (str)!
            f.write(encrypted_bytes.encode('utf-8'))
        encrypted_name = cryptolibo.encrypt.aes_gcm(key_password, file.name)
        encrypted_name = encrypted_name.replace("/", "_").replace("+", "-")
        os.rename(file, file.with_name(encrypted_name))
        misc_utils.safe_delete(fr"{folder}\backup\{file.name}.backup")
    shutil.rmtree(fr"{folder}\backup")