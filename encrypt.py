from cryptoutils import cryptolibo
import misc_utils
import os
import pathlib
import shutil
def encrypt_folder(password, folder):
    total = [f for f in folder.rglob("*") if f.is_file()]
    total = len(total)
    curr_count = 1
    # salt generated automatic
    hash_password, salt = cryptolibo.hash.pbkdf2(password, length=64)
    password_len = len(password)
    while password_len < 200000:
        password_len = password_len * 1.5
    iteration = round(password_len)
    # we don't need salt, we just need to stretch the password
    key_password, _ = cryptolibo.hash.pbkdf2(password, salt=password, length=128, iterations=iteration)
    with open (fr"{folder}\pass.hash", "w") as f:
        f.write(cryptolibo.encrypt.chacha20_poly1305(key_password, hash_password))
    with open (fr"{folder}\pass.salt", "w") as f:
        f.write(cryptolibo.encrypt.aes_gcm(key_password, salt))
    pathlib.Path(fr"{folder}\backup").mkdir(exist_ok=True)
    for file in list(folder.rglob("*")):
        if not file.is_file():
            continue
        if file.parent.name == "backup":
            continue
        if file.name in ("pass.hash", "pass.salt"):
            continue
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
        print(f"\rEncrypted {curr_count}/{total} Files", end="", flush=True)
        curr_count += 1
        misc_utils.safe_delete(fr"{folder}\backup\{file.name}.backup")
    shutil.rmtree(fr"{folder}\backup")
    print("\n")