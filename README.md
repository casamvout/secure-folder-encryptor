![Python](https://img.shields.io/badge/Python-3.7+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen)
# SECURE FOLDER ENCRYPTOR
**Safe and easy to use folder protector**

# Possibilities
- 🔐 Encrypt/Decrypt Folder
Using **secure** and **proven** algorithms:
1. ChaCha20_Poly1305 (Main file encryption)
2. AES_GCM (pass.hash/pass.salt encryption)
3. PBKDF2 (Main password stretching)

- 🛡️ Has mechanisms to protect against ***file damage***:
1. Creates **backup** before encryption and deletes it after encryption
2. Marks files as **already decrypted** to prevent re-decryption in case the program closes during decryption.

- ⚙️ Misc:
1. **Verifyng** password before decryption
2. Masking password while typing (maskpass)
3. Safe delete (overwrites with random data before deletion)

## 📦 Requirements
- Python 3.7+
- maskpass
- cryptography

## ⚠️ Important warnings
- **For HOME USE only** (not intended for enterprise/critical data)
- **Losing password = losing data forever** (no backdoor, no recovery)

## 🚀 Quick start

### Installation
```bash
git clone https://github.com/casamvout/secure-folder-encryptor.git
cd secure-folder-encryptor
pip install maskpass
pip install cryptography
```
### Usage
```bash
python main.py
```
### Project structure
secure-folder-encryptor/  
├── main.py           # CLI interface  
├── encrypt.py        # Encryption logic  
├── decrypt.py        # Decryption logic  
├── misc_utils.py     # Utilities (safe_delete, etc.)  
├── cryptoutils/      # Cryptographic core  
└── README.md         # This file  

## 🙏 Credits
- Created for home users who need ***simple*** but ***secure*** file protection.

## 🔬 How it works
1. User enters password
2. PBKDF2 stretches password (dynamic iterations based on password length)
3. ChaCha20-Poly1305 encrypts each file
4. AES-GCM encrypts metadata (pass.hash, pass.salt)
5. Safe delete removes temporary files
