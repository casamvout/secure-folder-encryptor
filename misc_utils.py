import os
def is_exists(path):
    if os.path.exists(path):
        return True
    else:
        return False
def safe_delete(path):
    # Maybe will not totally help if files are on SSD (On HDD it may work great)
    if os.path.exists(path):
        file_size = os.path.getsize(path)
        with open(path, "wb") as f:
            for _ in range(2):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
