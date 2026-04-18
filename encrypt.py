from cryptoutils import cryptolibo
import misc_utils
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
    for file in folder.rglob("*"):
        with open(file, "rb") as f:
            read_bytes = f.read()
            encrypted_bytes = cryptolibo.encrypt.chacha20_poly1305(key_password, read_bytes)
        with open(f"{file}.backup", "wb") as f:
            f.write(read_bytes)
        with open(file, "wb") as f:
            # encode needed! chacha20_poly1305 always returns base64 (str)!
            f.write(encrypted_bytes.encode('utf-8'))
        print(f"\rEncrypted {curr_count}/{total - 2} Files", end="", flush=True)
        curr_count += 1
        misc_utils.safe_delete(f"{file}.backup")
    with open (fr"{folder}\pass.hash", "w") as f:
        f.write(cryptolibo.encrypt.aes_gcm(key_password, hash_password))
    with open (fr"{folder}\pass.salt", "w") as f:
        f.write(cryptolibo.encrypt.aes_gcm(key_password, salt))
    print("\n")
