from cryptoutils import cryptolibo
import pathlib
import os
import shutil
import misc_utils
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
def decrypt_folder(password, folder):
    pathlib.Path(fr"{folder}\tmp").mkdir(exist_ok=True)
    files_list = [f for f in folder.rglob("*") if f.is_file() and f.name not in ("pass.hash", "pass.salt") and f.name not in os.listdir(fr"{folder}\tmp")]
    key_password = misc_utils.stretch_password(password, 128)
    with open(fr"{folder}\pass.hash", "r") as f:
        read_password = cryptolibo.decrypt.chacha20_poly1305(key_password, f.read())
    with open(fr"{folder}\pass.salt", "r")as f:
        read_salt = cryptolibo.decrypt.aes_gcm(key_password, (f.read()))
    hashed_password, _ = cryptolibo.hash.argon2(password, salt=bytes.fromhex(read_salt), hash_len=64)
    if hashed_password != read_password:
        raise ValueError("Decryption Error: Passwords do not match")
    else:
        # Protection against interruption of code execution during decryption
        def decrypt_one_file(file):
            with open(file, "rb") as f:
                data = f.read()
                decrypted_data = cryptolibo.decrypt.chacha20_poly1305(key_password, data.decode())
            with open(file, "wb") as f:
                try:
                    f.write(decrypted_data.encode('utf-8'))
                except AttributeError:
                    f.write(decrypted_data)

            clear_name = file.name.replace("_", "/").replace("-", "+")
            decrypted_name = cryptolibo.decrypt.aes_gcm(key_password, clear_name)
            os.rename(file, file.with_name(decrypted_name))

            with open(fr"{folder}\tmp\{decrypted_name}", "w"):
                pass

        with ThreadPoolExecutor(max_workers=6) as executor:
            list(
                tqdm(executor.map(decrypt_one_file, files_list), total=len(files_list), desc="Decrypting", unit="file"))

        misc_utils.safe_delete(fr"{folder}\pass.hash")
        misc_utils.safe_delete(fr"{folder}\pass.salt")
        shutil.rmtree(fr"{folder}\tmp")