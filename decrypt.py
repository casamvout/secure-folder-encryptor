from cryptoutils import cryptolibo
import pathlib
import os
import shutil
import misc_utils
def decrypt_folder(password, folder):
    curr_count = 1
    total = [f for f in folder.rglob("*") if f.is_file()]
    total = len(total)
    password_len = len(password)
    while password_len < 200000:
        password_len = password_len * 1.5
    iteration = round(password_len)
    key_password, _ = cryptolibo.hash.pbkdf2(password, salt=password, iterations=iteration, length=128)
    with open(fr"{folder}\pass.hash", "r") as f:
        data = f.read
        read_password = cryptolibo.decrypt.chacha20_poly1305(key_password, f.read())
    with open(fr"{folder}\pass.salt", "r")as f:
        read_salt = cryptolibo.decrypt.aes_gcm(key_password, (f.read()))
    hashed_password, _ = cryptolibo.hash.pbkdf2(password, bytes.fromhex(read_salt), length=64)
    if hashed_password != read_password:
        raise ValueError("Decryption Error: Passwords do not match")
    else:
        # Protection against interruption of code execution during decryption
        pathlib.Path(fr"{folder}\tmp").mkdir(exist_ok=True)
        for file in list(folder.rglob("*")):
            if file.name in ("pass.hash", "pass.salt"):
                continue
            if not file.is_file():
                continue
            if file.name in os.listdir(fr"{folder}\tmp"):
                continue
            with open(file, "rb") as f:
                data = f.read()
                decrypted_data = cryptolibo.decrypt.chacha20_poly1305(key_password, data.decode())
            with open(file, "wb") as f:
                # encode needed! chacha20_poly1305 always returns base64 (str)!
                try:
                    f.write(decrypted_data.encode('utf-8'))
                except AttributeError:
                    f.write(decrypted_data)
            clear_name = file.name.replace("_", "/").replace("-", "+")
            decrypted_name = cryptolibo.decrypt.aes_gcm(key_password, clear_name)
            os.rename(file, file.with_name(decrypted_name))
            with open(fr"{folder}\tmp\{decrypted_name}", "w"):
                pass
            print(f"\rDecrypted {curr_count}/{total - 2} Files", end="", flush=True)
            curr_count += 1
        misc_utils.safe_delete(fr"{folder}\pass.hash")
        misc_utils.safe_delete(fr"{folder}\pass.salt")
        shutil.rmtree(fr"{folder}\tmp")
        print("\n")