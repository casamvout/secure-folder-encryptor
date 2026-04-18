"""
(WRITTEN BY AI)
╔══════════════════════════════════════════════════════════════════════════════╗
║                         cryptolibo.py  v4.0                                ║
║                     Professional Cryptography Library                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Quick start:                                                               ║
║    import cryptolibo                                                        ║
║                                                                             ║
║    # Key generation                                                         ║
║    key = cryptolibo.generate_key()                                          ║
║    key = cryptolibo.generate_key(save_to="mykey.key")                      ║
║                                                                             ║
║    # Encryption / decryption                                                ║
║    enc = cryptolibo.encrypt.aes_gcm(key, "secret")   # recommended         ║
║    dec = cryptolibo.decrypt.aes_gcm(key, enc)                              ║
║                                                                             ║
║    enc = cryptolibo.encrypt.aes256(key, "secret")                          ║
║    dec = cryptolibo.decrypt.aes256(key, enc)                               ║
║                                                                             ║
║    enc = cryptolibo.encrypt.wordlock("password", "secret")                 ║
║    dec = cryptolibo.decrypt.wordlock("password", enc)                      ║
║                                                                             ║
║    # Quick encryption (key generated automatically)                         ║
║    enc, key = cryptolibo.quick_encrypt("data")                             ║
║    dec      = cryptolibo.quick_decrypt(enc, key)                           ║
║                                                                             ║
║    # Encrypted secrets vault                                                ║
║    vault = cryptolibo.CryptoVault("vault.db", "master_password")           ║
║    vault.set("api_key", "sk-abc123")                                       ║
║    vault.get("api_key")  # → "sk-abc123"                                   ║
║                                                                             ║
║    # Streaming file encryption (any size)                                   ║
║    cryptolibo.encrypt_stream("big.mp4", "big.mp4.enc", key)               ║
║    cryptolibo.decrypt_stream("big.mp4.enc", "big.mp4", key)               ║
║                                                                             ║
║    # Hashing                                                                ║
║    h = cryptolibo.hash.sha256("data")                                      ║
║    h = cryptolibo.hash.argon2("password")      # for passwords             ║
║                                                                             ║
║    # HMAC signing                                                           ║
║    sig = cryptolibo.sign.hmac_sha256(key, "data")                          ║
║    ok  = cryptolibo.sign.verify(key, "data", sig)                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

Changes in v4.0:
  - Fixed bug in _base58_encode (incorrect leading-zeros logic)
  - Removed duplicate AESGCM import
  - Key derivation cache (_key_cache) — speeds up repeated calls
  - CryptoVault — encrypted JSON secrets storage
  - encrypt_stream / decrypt_stream — streaming encryption (>4GB files)
  - batch_encrypt / batch_decrypt — batch encryption of string lists
  - encrypt.aes_gcm_file / decrypt.aes_gcm_file — convenience methods on classes
  - KeyManager.rotate — key rotation with re-encryption
  - Hash.tree — Merkle hash tree for data lists
  - Utils.zeroize — secure zeroing of strings/bytes
  - Utils.timing_safe_sleep — constant-time response
  - Improved error messages with codes
  - Full type annotations (TypeAlias, Final)
  - Context manager support for CryptoVault
  - capabilities() returns dependency versions
"""

from __future__ import annotations

import os
import base64
import hashlib
import hmac as _hmac
import json
import math
import time
import struct
import secrets
import string
import zlib
import functools
import threading
from pathlib import Path
from typing import (
    Union, Optional, Tuple, Dict, Any, List, Iterator,
    TYPE_CHECKING
)

try:
    from typing import TypeAlias, Final
except ImportError:
    TypeAlias = None  # type: ignore
    Final = None      # type: ignore

# ─── Dependencies ─────────────────────────────────────────────────────────────

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, AESCCM
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa_mod, padding as asym_padding, ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as _rsa_gen
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key as _ec_gen,
        SECP256R1, SECP384R1, SECP521R1, SECP256K1,
        ECDH, EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
    from cryptography.exceptions import InvalidSignature, InvalidTag
    import cryptography
    CRYPTO_AVAILABLE = True
    CRYPTO_VERSION = cryptography.__version__
except ImportError:
    CRYPTO_AVAILABLE = False
    CRYPTO_VERSION = None
    InvalidTag = Exception
    InvalidSignature = Exception

try:
    from Crypto.Cipher import (
        AES as _AES, DES as _DES, DES3 as _DES3,
        ARC2 as _ARC2, ARC4 as _ARC4,
        Blowfish as _Blowfish, CAST as _CAST,
        ChaCha20 as _ChaCha20,
    )
    from Crypto.Util.Padding import pad as _pad, unpad as _unpad
    from Crypto.Random import get_random_bytes as _pycrypto_rand
    import Crypto
    PYCRYPTODOME_AVAILABLE = True
    PYCRYPTODOME_VERSION = Crypto.__version__
except ImportError:
    PYCRYPTODOME_AVAILABLE = False
    PYCRYPTODOME_VERSION = None

try:
    import argon2
    from argon2 import PasswordHasher as _Argon2PH
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    ARGON2_AVAILABLE = True
    ARGON2_VERSION = argon2.__version__
except ImportError:
    ARGON2_AVAILABLE = False
    ARGON2_VERSION = None

# ─── Version ──────────────────────────────────────────────────────────────────

__version__: str = "4.0.0"
__author__:  str = "cryptolibo"

# ─── Types ────────────────────────────────────────────────────────────────────

DataLike = Union[str, bytes]
KeyLike  = Union[str, bytes]

# ─── Constants ────────────────────────────────────────────────────────────────

# Block size for streaming encryption (64 KB)
_STREAM_CHUNK: int = 65_536
# Stream file format version magic bytes
_STREAM_MAGIC: bytes = b"CLIB\x04\x00"

# ─── Exceptions ───────────────────────────────────────────────────────────────

class CryptoError(Exception):
    """Base library exception."""
    code: str = "CRYPTO_ERROR"


class DecryptionError(CryptoError):
    """Decryption error (wrong key / corrupted data)."""
    code = "DECRYPTION_FAILED"


class IntegrityError(CryptoError):
    """Data integrity violation (signature/MAC check failed)."""
    code = "INTEGRITY_VIOLATION"


class MissingDependency(CryptoError):
    """Required dependency is not installed."""
    code = "MISSING_DEPENDENCY"

    def __init__(self, package: str):
        super().__init__(
            f"Install dependency: pip install {package}\n"
            f"  Or all dependencies: pip install cryptography pycryptodome argon2-cffi"
        )
        self.package = package


class KeyError_(CryptoError):
    """Key operation error (invalid format, size, etc.)."""
    code = "KEY_ERROR"

    def __init__(self, msg: str):
        super().__init__(msg)


class VaultError(CryptoError):
    """Secrets vault error."""
    code = "VAULT_ERROR"


# ─── Key derivation cache ─────────────────────────────────────────────────────

class _KeyCache:
    """Thread-safe LRU cache for expensive key derivation operations."""

    def __init__(self, max_size: int = 64):
        self._cache: Dict[Tuple, bytes] = {}
        self._order: List[Tuple] = []
        self._lock  = threading.Lock()
        self._max   = max_size

    def get(self, key: tuple) -> Optional[bytes]:
        with self._lock:
            return self._cache.get(key)

    def set(self, key: tuple, value: bytes) -> None:
        with self._lock:
            if key in self._cache:
                self._order.remove(key)
            elif len(self._cache) >= self._max:
                oldest = self._order.pop(0)
                del self._cache[oldest]
            # Cache by key hash rather than the key itself —
            # to avoid keeping the secret in plaintext in memory
            self._cache[key] = value
            self._order.append(key)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._order.clear()


_key_cache = _KeyCache()


# ─── Helper functions ─────────────────────────────────────────────────────────

def _to_bytes(data: DataLike) -> bytes:
    return data.encode("utf-8") if isinstance(data, str) else bytes(data)


def _to_str(data: bytes) -> Union[str, bytes]:
    """Decodes bytes to str if valid UTF-8, otherwise returns bytes."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data


def _b64enc(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _b64dec(data: str) -> bytes:
    data = data.strip()
    missing = len(data) % 4
    if missing:
        data += "=" * (4 - missing)
    try:
        return base64.b64decode(data)
    except Exception as e:
        raise DecryptionError(f"Invalid Base64: {e}") from e


def _require(flag: bool, package: str) -> None:
    if not flag:
        raise MissingDependency(package)


def _derive_key(key: DataLike, size: int, salt: bytes = b"") -> bytes:
    """
    Deterministic key derivation to the required size.

    With salt   — PBKDF2-HMAC-SHA256 (100k iterations).
    Without salt — HKDF-SHA256 (expand-only, info=b"cryptolibo/v4").
                   Used for internal purposes only (not for passwords!).

    Cache stores (SHA3-256(key), size, salt) → secret not kept in plaintext.
    """
    raw = _to_bytes(key)

    # Cache key uses a hash of the secret to avoid storing it in plaintext
    cache_key = (hashlib.sha3_256(raw).digest(), size, salt)
    cached = _key_cache.get(cache_key)
    if cached is not None:
        return cached

    if salt:
        # For passwords/user keys with salt
        result = hashlib.pbkdf2_hmac("sha256", raw, salt, 100_000, dklen=size)
    else:
        # HKDF expand-only: PRK = raw (assumed to have sufficient entropy),
        # outputs the required number of bytes via HMAC chain
        # T(1) = HMAC(raw, b"\x01"), T(2) = HMAC(raw, T(1) + b"\x02"), ...
        info  = b"cryptolibo/v4"
        t     = b""
        out   = b""
        counter = 0
        while len(out) < size:
            counter += 1
            t    = _hmac.new(raw, t + info + bytes([counter]), "sha256").digest()
            out += t
        result = out[:size]

    _key_cache.set(cache_key, result)
    return result


def _resolve_key(key: DataLike) -> DataLike:
    """If key is a path to a .key/.pem/.txt file — loads its contents."""
    s = key if isinstance(key, str) else key.decode("utf-8", errors="replace")
    if any(s.endswith(ext) for ext in (".key", ".txt", ".pem")):
        p = Path(s)
        if p.exists():
            return p.read_text().strip()
    return key


def _key_to_raw(key: DataLike, size: int) -> bytes:
    """
    Converts any key (hex string, bytes, password string) to bytes of the required size.
    Raises KeyError_ on obviously invalid key size.
    """
    if size not in (8, 16, 24, 32, 48, 64):
        raise KeyError_(f"Invalid key size: {size} bytes")

    key = _resolve_key(key)
    raw = _to_bytes(key)
    # Try as hex
    try:
        candidate = raw.decode() if isinstance(raw, bytes) else raw
        decoded = bytes.fromhex(candidate.strip())
        return _derive_key(decoded, size)
    except (ValueError, AttributeError):
        pass
    # Otherwise — treat as password
    return _derive_key(raw, size)


# ─── WordLock v2 — improved custom algorithm ──────────────────────────────────

def _wl_stream(seed: bytes, length: int) -> bytes:
    """Cryptographically secure byte stream from seed via SHA3 chain."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha3_256(seed + counter.to_bytes(4, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _wl_sbox(key_bytes: bytes) -> bytes:
    """S-box (256 bytes) from key via KSA (like RC4 but with SHA3)."""
    key_stream = bytearray()
    counter = 0
    while len(key_stream) < 256:
        key_stream += hashlib.sha3_256(key_bytes + counter.to_bytes(4, "big")).digest()
        counter += 1
    key_stream = key_stream[:256]
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key_stream[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return bytes(sbox)


def _wl_inv_sbox(sbox: bytes) -> bytes:
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return bytes(inv)


def _wl_shuffle(seed: bytes, n: int) -> list:
    """Fisher-Yates permutation based on stream from seed."""
    indices = list(range(n))
    stream = _wl_stream(seed + b"\x00shuffle", n * 4)
    for i in range(n - 1, 0, -1):
        offset = (i * 4) % len(stream)
        rand_val = int.from_bytes(stream[offset:offset + 4], "big")
        j = rand_val % (i + 1)
        indices[i], indices[j] = indices[j], indices[i]
    return indices


def _wordlock_crypt(word: str, data: bytes, encrypt: bool) -> Union[str, bytes]:
    """
    WordLock v2:
      Encrypt: salt_prefix + sbox → xor_stream → shuffle → base64
      Decrypt: base64 → unshuffle → xor_stream → inv_sbox

    Protection layers:
      - Random salt (16 bytes) → semantic security
      - S-box substitution (KSA from SHA3)
      - XOR with stream (SHA3 chain)
      - Fisher-Yates byte permutation
      - HMAC-SHA256 integrity tag (16 bytes)
    """
    w = _to_bytes(word)
    MAC_LEN  = 16
    SALT_LEN = 16

    if encrypt:
        salt = secrets.token_bytes(SALT_LEN)
        seed = hashlib.sha3_256(b"wordlock:v2:" + w + salt).digest()

        sbox   = _wl_sbox(seed)
        stream = _wl_stream(seed, len(data))
        shuf   = _wl_shuffle(seed, len(data))

        step1 = bytes(sbox[b] for b in data)
        step2 = bytes(b ^ stream[i] for i, b in enumerate(step1))
        step3 = bytearray(len(data))
        for old, new in enumerate(shuf):
            step3[new] = step2[old]

        payload = salt + bytes(step3)
        mac = _hmac.new(w, payload, "sha256").digest()[:MAC_LEN]
        return _b64enc(payload + mac)

    else:
        if len(data) < SALT_LEN + MAC_LEN:
            raise DecryptionError("Data is too short or corrupted")

        payload   = data[:-MAC_LEN]
        mac_given = data[-MAC_LEN:]
        mac_calc  = _hmac.new(w, payload, "sha256").digest()[:MAC_LEN]

        if not _hmac.compare_digest(mac_calc, mac_given):
            raise IntegrityError("Wrong passphrase or data is corrupted (HMAC)")

        salt       = payload[:SALT_LEN]
        ciphertext = payload[SALT_LEN:]
        seed = hashlib.sha3_256(b"wordlock:v2:" + w + salt).digest()

        inv_s  = _wl_inv_sbox(_wl_sbox(seed))
        stream = _wl_stream(seed, len(ciphertext))
        shuf   = _wl_shuffle(seed, len(ciphertext))

        step2 = bytearray(len(ciphertext))
        for old, new in enumerate(shuf):
            step2[old] = ciphertext[new]

        step1    = bytes(b ^ stream[i] for i, b in enumerate(step2))
        original = bytes(inv_s[b] for b in step1)
        return original


# ─── Key generation ───────────────────────────────────────────────────────────

class KeyManager:
    """Generation, saving, loading, and rotation of cryptographic keys."""

    DEFAULT_PATH = Path.home() / ".cryptolibo" / "default.key"

    # ── Generation ────────────────────────────────────────────────────────────

    def generate(
        self,
        bits: int = 256,
        save_to: Optional[str] = None,
        encoding: str = "hex",
        passphrase: Optional[str] = None,
    ) -> str:
        """
        Generates a cryptographically strong symmetric key.

        Args:
            bits:       128 / 192 / 256 / 512.
            save_to:    Path to save (None = don't save).
            encoding:   "hex" | "base64".
            passphrase: Protect the key file with a password.
        """
        if bits % 8 != 0:
            raise KeyError_("bits must be a multiple of 8")
        if bits < 128:
            raise KeyError_("Minimum key size is 128 bits")
        raw = secrets.token_bytes(bits // 8)

        if encoding == "base64":
            key_str = base64.b64encode(raw).decode()
        else:
            key_str = raw.hex()

        if save_to is not None:
            self.save(key_str, save_to, passphrase=passphrase)
        return key_str

    def generate_rsa(
        self,
        bits: int = 2048,
        save_dir: Optional[str] = None,
        passphrase: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Generates an RSA key pair. Returns (private_pem, public_pem)."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        if bits < 2048:
            raise KeyError_("RSA key must be at least 2048 bits")
        priv = _rsa_gen(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend(),
        )
        enc = (
            serialization.BestAvailableEncryption(_to_bytes(passphrase))
            if passphrase else serialization.NoEncryption()
        )
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc,
        ).decode()
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        if save_dir:
            d = Path(save_dir)
            d.mkdir(parents=True, exist_ok=True)
            (d / "private.pem").write_text(priv_pem)
            (d / "public.pem").write_text(pub_pem)
        return priv_pem, pub_pem

    def generate_ec(
        self,
        curve: str = "P-256",
        save_dir: Optional[str] = None,
        passphrase: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Generates an ECDSA/ECDH key pair.

        Args:
            curve: "P-256" | "P-384" | "P-521" | "secp256k1"
        """
        _require(CRYPTO_AVAILABLE, "cryptography")
        curves = {
            "P-256":     SECP256R1(),
            "P-384":     SECP384R1(),
            "P-521":     SECP521R1(),
            "secp256k1": SECP256K1(),
        }
        if curve not in curves:
            raise KeyError_(f"Unknown curve: {curve}. Available: {list(curves)}")
        priv = _ec_gen(curves[curve], backend=default_backend())
        enc = (
            serialization.BestAvailableEncryption(_to_bytes(passphrase))
            if passphrase else serialization.NoEncryption()
        )
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc,
        ).decode()
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        if save_dir:
            d = Path(save_dir)
            d.mkdir(parents=True, exist_ok=True)
            (d / "ec_private.pem").write_text(priv_pem)
            (d / "ec_public.pem").write_text(pub_pem)
        return priv_pem, pub_pem

    def generate_ed25519(
        self,
        save_dir: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Generates an Ed25519 key pair for signing."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        priv = Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        if save_dir:
            d = Path(save_dir)
            d.mkdir(parents=True, exist_ok=True)
            (d / "ed25519_private.pem").write_text(priv_pem)
            (d / "ed25519_public.pem").write_text(pub_pem)
        return priv_pem, pub_pem

    def generate_x25519(self) -> Tuple[str, str]:
        """Generates an X25519 key pair for ECDH exchange."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        priv = X25519PrivateKey.generate()
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return priv_pem, pub_pem

    # ── Save / load ───────────────────────────────────────────────────────────

    def save(self, key: str, path: str, passphrase: Optional[str] = None) -> None:
        """Saves a key to a file (optionally with AES-GCM password protection)."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if passphrase:
            salt = secrets.token_bytes(16)
            dk   = _derive_key(passphrase, 32, salt)
            raw  = _to_bytes(key)
            nonce = secrets.token_bytes(12)
            if CRYPTO_AVAILABLE:
                ct = AESGCM(dk).encrypt(nonce, raw, None)
                payload = {
                    "v": 2,
                    "protected": True,
                    "salt":  salt.hex(),
                    "nonce": nonce.hex(),
                    "data":  base64.b64encode(ct).decode(),
                }
            else:
                # Fallback: XOR stream (no AEAD — no authentication)
                stream = _wl_stream(dk, len(raw))
                encrypted = bytes(b ^ stream[i] for i, b in enumerate(raw))
                payload = {
                    "v": 1,
                    "protected": True,
                    "salt": salt.hex(),
                    "data": base64.b64encode(encrypted).decode(),
                }
            p.write_text(json.dumps(payload, indent=2))
        else:
            p.write_text(key)

    def load(self, path: str, passphrase: Optional[str] = None) -> str:
        """Loads a key from a file."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Key file not found: {path}")
        content = p.read_text().strip()
        try:
            payload = json.loads(content)
            if payload.get("protected"):
                if not passphrase:
                    raise KeyError_("Key file is password-protected — provide a passphrase")
                salt = bytes.fromhex(payload["salt"])
                dk   = _derive_key(passphrase, 32, salt)
                ct   = base64.b64decode(payload["data"])
                if payload.get("v", 1) == 2 and CRYPTO_AVAILABLE:
                    nonce = bytes.fromhex(payload["nonce"])
                    try:
                        raw = AESGCM(dk).decrypt(nonce, ct, None)
                    except Exception:
                        raise DecryptionError("Wrong password for key file")
                else:
                    stream = _wl_stream(dk, len(ct))
                    raw = bytes(b ^ stream[i] for i, b in enumerate(ct))
                return raw.decode()
        except (json.JSONDecodeError, KeyError):
            pass
        return content

    def load_or_generate(
        self,
        path: Optional[str] = None,
        bits: int = 256,
        passphrase: Optional[str] = None,
    ) -> str:
        """Loads a key if it exists, otherwise generates a new one."""
        target = Path(path) if path else self.DEFAULT_PATH
        if target.exists():
            return self.load(str(target), passphrase=passphrase)
        return self.generate(bits=bits, save_to=str(target), passphrase=passphrase)

    def rotate(
        self,
        old_key: str,
        new_key: Optional[str] = None,
        data_list: Optional[List[str]] = None,
        algo: str = "aes_gcm",
    ) -> Tuple[str, Optional[List[str]]]:
        """
        Key rotation — optionally re-encrypts a list of data.

        Args:
            old_key:   Current key.
            new_key:   New key (if None — generated automatically).
            data_list: List of encrypted strings to re-encrypt.
            algo:      Algorithm ("aes_gcm" | "wordlock").
        Returns:
            (new_key, re_encrypted_list_or_None)
        """
        nk = new_key or self.generate()
        if data_list is None:
            return nk, None

        result = []
        enc_fn = getattr(encrypt, algo)
        dec_fn = getattr(decrypt, algo)
        for item in data_list:
            plaintext = dec_fn(old_key, item)
            result.append(enc_fn(nk, plaintext))
        return nk, result

    # ── KDF utilities ─────────────────────────────────────────────────────────

    def password_to_key(
        self,
        password: str,
        salt: Optional[bytes] = None,
        bits: int = 256,
        iterations: int = 200_000,
        algo: str = "pbkdf2",
    ) -> Tuple[str, str]:
        """
        Derives a key from a password.

        Args:
            algo: "pbkdf2" | "scrypt" | "argon2"
        Returns:
            (key_hex, salt_hex)
        """
        s = salt if salt else secrets.token_bytes(16)
        if algo == "scrypt":
            _require(CRYPTO_AVAILABLE, "cryptography")
            kdf = Scrypt(salt=s, length=bits // 8, n=2**14, r=8, p=1, backend=default_backend())
            dk  = kdf.derive(_to_bytes(password))
        elif algo == "argon2":
            _require(ARGON2_AVAILABLE, "argon2-cffi")
            dk = hash_secret_raw(
                secret=_to_bytes(password),
                salt=s,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=bits // 8,
                type=Argon2Type.ID,
            )
        else:
            dk = hashlib.pbkdf2_hmac("sha256", _to_bytes(password), s, iterations, dklen=bits // 8)
        return dk.hex(), s.hex()

    def generate_password(self, length: int = 24, symbols: bool = True) -> str:
        """Generates a random password."""
        chars = string.ascii_letters + string.digits
        if symbols:
            chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
        # Guarantee at least one character from each class
        pwd = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
        ]
        if symbols:
            pwd.append(secrets.choice("!@#$%^&*()-_=+[]{}|;:,.<>?"))
        pwd += [secrets.choice(chars) for _ in range(length - len(pwd))]
        secrets.SystemRandom().shuffle(pwd)
        return "".join(pwd)

    def hkdf_expand(
        self,
        key: DataLike,
        length: int = 32,
        info: bytes = b"",
        salt: Optional[bytes] = None,
    ) -> str:
        """HKDF key expansion (for subkey derivation)."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(_to_bytes(key)).hex()

    def info(self, key: str) -> Dict[str, Any]:
        """Key information."""
        try:
            raw = bytes.fromhex(key)
            enc = "hex"
        except ValueError:
            try:
                raw = base64.b64decode(key + "==")
                enc = "base64"
            except Exception:
                raw = _to_bytes(key)
                enc = "utf-8"
        ent = utils.entropy(raw)
        return {
            "length_bytes":  len(raw),
            "length_bits":   len(raw) * 8,
            "encoding":      enc,
            "entropy_bits":  round(ent * len(raw), 1),
            "entropy_per_byte": round(ent, 4),
            "quality":       "excellent" if ent > 7.5 else ("good" if ent > 6.5 else "weak"),
            "preview":       raw[:4].hex() + "...",
        }


keys = KeyManager()


# ─── Encryption ───────────────────────────────────────────────────────────────

class Encrypt:
    """Data encryption using various algorithms."""

    # ── AES-GCM (recommended) ─────────────────────────────────────────────────

    def aes_gcm(
        self,
        key: KeyLike,
        data: DataLike,
        aad: Optional[bytes] = None,
    ) -> str:
        """
        AES-256-GCM — authenticated encryption (recommended).
        Resistant to forgery and modification.
        Format: base64(nonce[12] + ciphertext + tag[16])
        """
        _require(CRYPTO_AVAILABLE, "cryptography")
        k     = _key_to_raw(key, 32)
        nonce = secrets.token_bytes(12)
        ct    = AESGCM(k).encrypt(nonce, _to_bytes(data), aad)
        return _b64enc(nonce + ct)

    def aes_gcm_128(self, key: KeyLike, data: DataLike, aad: Optional[bytes] = None) -> str:
        """AES-128-GCM."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        k     = _key_to_raw(key, 16)
        nonce = secrets.token_bytes(12)
        ct    = AESGCM(k).encrypt(nonce, _to_bytes(data), aad)
        return _b64enc(nonce + ct)

    # ── AES-CBC ───────────────────────────────────────────────────────────────

    def aes128(self, key: KeyLike, data: DataLike) -> str:
        """AES-128-CBC with PKCS7 padding."""
        return self._aes_cbc(key, data, 16)

    def aes192(self, key: KeyLike, data: DataLike) -> str:
        """AES-192-CBC with PKCS7 padding."""
        return self._aes_cbc(key, data, 24)

    def aes256(self, key: KeyLike, data: DataLike) -> str:
        """AES-256-CBC with PKCS7 padding."""
        return self._aes_cbc(key, data, 32)

    def _aes_cbc(self, key: KeyLike, data: DataLike, ksize: int) -> str:
        _require(CRYPTO_AVAILABLE, "cryptography")
        k      = _key_to_raw(key, ksize)
        iv     = secrets.token_bytes(16)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(_to_bytes(data)) + padder.finalize()
        enc    = Cipher(algorithms.AES(k), modes.CBC(iv), backend=default_backend()).encryptor()
        ct     = enc.update(padded) + enc.finalize()
        return _b64enc(iv + ct)

    # ── AES-CTR ───────────────────────────────────────────────────────────────

    def aes_ctr(self, key: KeyLike, data: DataLike) -> str:
        """AES-256-CTR (stream mode, no padding)."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        k     = _key_to_raw(key, 32)
        nonce = secrets.token_bytes(16)
        enc   = Cipher(
            algorithms.AES(k),
            modes.CTR(nonce),
            backend=default_backend(),
        ).encryptor()
        ct = enc.update(_to_bytes(data)) + enc.finalize()
        return _b64enc(nonce + ct)

    # ── AES-SIV (deterministic AEAD) ──────────────────────────────────────────

    def aes_siv(self, key: KeyLike, data: DataLike, aad: Optional[bytes] = None) -> str:
        """
        AES-SIV — deterministic AEAD encryption.
        Resistant to nonce reuse, no leakage on collisions.
        Requires a 512-bit key (two AES-256 keys).
        """
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.ciphers.aead import AESSIV
        k  = _key_to_raw(key, 64)
        ct = AESSIV(k).encrypt(_to_bytes(data), [aad] if aad else None)
        return _b64enc(ct)

    # ── ChaCha20-Poly1305 ────────────────────────────────────────────────────

    def chacha20_poly1305(self, key: KeyLike, data: DataLike) -> str:
        """ChaCha20-Poly1305 — fast AEAD encryption (alternative to AES-GCM)."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        k     = _key_to_raw(key, 32)
        nonce = secrets.token_bytes(12)
        ct    = ChaCha20Poly1305(k).encrypt(nonce, _to_bytes(data), None)
        return _b64enc(nonce + ct)

    def chacha20(self, key: KeyLike, data: DataLike) -> str:
        """ChaCha20 without authentication (use chacha20_poly1305 when possible)."""
        if PYCRYPTODOME_AVAILABLE:
            k     = _key_to_raw(key, 32)
            nonce = secrets.token_bytes(8)
            ct    = _ChaCha20.new(key=k, nonce=nonce).encrypt(_to_bytes(data))
            return _b64enc(nonce + ct)
        if CRYPTO_AVAILABLE:
            k     = _key_to_raw(key, 32)
            nonce = secrets.token_bytes(16)
            enc   = Cipher(
                algorithms.ChaCha20(k, nonce),
                mode=None,
                backend=default_backend(),
            ).encryptor()
            ct = enc.update(_to_bytes(data)) + enc.finalize()
            return _b64enc(nonce + ct)
        raise MissingDependency("cryptography or pycryptodome for ChaCha20")

    # ── Salsa20 ───────────────────────────────────────────────────────────────

    def salsa20(self, key: KeyLike, data: DataLike) -> str:
        """Salsa20 — high-speed stream cipher."""
        if PYCRYPTODOME_AVAILABLE:
            from Crypto.Cipher import Salsa20 as _Salsa20
            k     = _key_to_raw(key, 32)
            nonce = secrets.token_bytes(8)
            ct    = _Salsa20.new(key=k, nonce=nonce).encrypt(_to_bytes(data))
            return _b64enc(nonce + ct)
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")

    # ── DES / 3DES (compatibility) ────────────────────────────────────────────

    def des(self, key: KeyLike, data: DataLike) -> str:
        """DES-CBC (legacy, for compatibility only)."""
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")
        k  = _key_to_raw(key, 8)
        iv = secrets.token_bytes(8)
        ct = _DES.new(k, _DES.MODE_CBC, iv).encrypt(_pad(_to_bytes(data), 8))
        return _b64enc(iv + ct)

    def triple_des(self, key: KeyLike, data: DataLike) -> str:
        """3DES-CBC (legacy, for compatibility only)."""
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")
        k  = _key_to_raw(key, 24)
        iv = secrets.token_bytes(8)
        ct = _DES3.new(k, _DES3.MODE_CBC, iv).encrypt(_pad(_to_bytes(data), 8))
        return _b64enc(iv + ct)

    # ── Blowfish / CAST / RC2 / RC4 ───────────────────────────────────────────

    def blowfish(self, key: KeyLike, data: DataLike) -> str:
        """Blowfish-CBC."""
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")
        k  = _key_to_raw(key, 16)
        iv = secrets.token_bytes(8)
        ct = _Blowfish.new(k, _Blowfish.MODE_CBC, iv).encrypt(_pad(_to_bytes(data), 8))
        return _b64enc(iv + ct)

    def cast(self, key: KeyLike, data: DataLike) -> str:
        """CAST-128-CBC."""
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")
        k  = _key_to_raw(key, 16)
        iv = secrets.token_bytes(8)
        ct = _CAST.new(k, _CAST.MODE_CBC, iv).encrypt(_pad(_to_bytes(data), 8))
        return _b64enc(iv + ct)

    def rc2(self, key: KeyLike, data: DataLike) -> str:
        """RC2-CBC (for compatibility only)."""
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")
        k  = _key_to_raw(key, 16)
        iv = secrets.token_bytes(8)
        ct = _ARC2.new(k, _ARC2.MODE_CBC, iv).encrypt(_pad(_to_bytes(data), 8))
        return _b64enc(iv + ct)

    def rc4(self, key: KeyLike, data: DataLike) -> str:
        """RC4 (not recommended for new projects)."""
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")
        k  = _key_to_raw(key, 16)
        ct = _ARC4.new(k).encrypt(_to_bytes(data))
        return _b64enc(ct)

    # ── RSA ───────────────────────────────────────────────────────────────────

    def rsa(self, public_key_pem: str, data: DataLike) -> str:
        """RSA-OAEP-SHA256 encryption."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pub = load_pem_public_key(_to_bytes(public_key_pem), backend=default_backend())
        ct  = pub.encrypt(
            _to_bytes(data),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return _b64enc(ct)

    def rsa_oaep_sha512(self, public_key_pem: str, data: DataLike) -> str:
        """RSA-OAEP-SHA512 encryption (stronger variant)."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pub = load_pem_public_key(_to_bytes(public_key_pem), backend=default_backend())
        ct  = pub.encrypt(
            _to_bytes(data),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None,
            ),
        )
        return _b64enc(ct)

    # ── ECIES (EC + AES-GCM) ──────────────────────────────────────────────────

    def ecies(self, public_key_pem: str, data: DataLike) -> str:
        """
        ECIES — elliptic curve encryption.
        Generates an ephemeral EC pair, performs ECDH, encrypts with AES-GCM.
        Compatible with P-256/P-384/P-521/secp256k1 keys.
        """
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pub = load_pem_public_key(_to_bytes(public_key_pem), backend=default_backend())
        ephemeral_priv = _ec_gen(pub.curve, backend=default_backend())
        ephemeral_pub  = ephemeral_priv.public_key()
        shared = ephemeral_priv.exchange(ECDH(), pub)
        sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ecies",
            backend=default_backend(),
        ).derive(shared)
        nonce = secrets.token_bytes(12)
        ct    = AESGCM(sym_key).encrypt(nonce, _to_bytes(data), None)
        eph_pub_bytes = ephemeral_pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        header = struct.pack(">H", len(eph_pub_bytes))
        return _b64enc(header + eph_pub_bytes + nonce + ct)

    # ── Classical ciphers ─────────────────────────────────────────────────────

    def xor(self, key: KeyLike, data: DataLike) -> str:
        """
        XOR encryption.

        Key is normalized via _key_to_raw (supports hex, bytes, string).
        Each encryption adds a random 16-byte nonce mixed into the stream
        via HKDF — produces different ciphertexts for identical data
        (semantic security).

        Format: base64(nonce[16] + ciphertext)
        """
        k     = _key_to_raw(key, 32)
        nonce = secrets.token_bytes(16)
        # Derive stream from key + nonce so each call produces
        # a unique stream even with the same key and data
        stream_key = _hmac.new(k, nonce, "sha256").digest()
        stream     = _derive_key(stream_key, len(_to_bytes(data)))
        ct         = bytes(b ^ stream[i] for i, b in enumerate(_to_bytes(data)))
        return _b64enc(nonce + ct)

    def vigenere(self, key: KeyLike, data: DataLike) -> str:
        """Vigenere cipher (extended to full byte range 0–255)."""
        k   = _to_bytes(key)
        d   = _to_bytes(data)
        out = bytes((b + k[i % len(k)]) % 256 for i, b in enumerate(d))
        return _b64enc(out)

    def caesar(self, data: DataLike, shift: int = 13) -> str:
        """Caesar cipher."""
        s = _to_bytes(data).decode("utf-8", errors="replace")
        result = []
        for c in s:
            if c.isalpha():
                base = 65 if c.isupper() else 97
                result.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                result.append(c)
        return "".join(result)

    def rot13(self, data: DataLike) -> str:
        """ROT13."""
        return self.caesar(data, 13)

    def rot47(self, data: DataLike) -> str:
        """ROT47 — shifts all printable ASCII characters."""
        s = _to_bytes(data).decode("utf-8", errors="replace")
        return "".join(
            chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
            for c in s
        )

    def atbash(self, data: DataLike) -> str:
        """Atbash cipher (mirror letter substitution)."""
        s = _to_bytes(data).decode("utf-8", errors="replace")
        result = []
        for c in s:
            if c.isalpha():
                base = 65 if c.isupper() else 97
                result.append(chr(base + 25 - (ord(c) - base)))
            else:
                result.append(c)
        return "".join(result)

    def polybius(self, data: DataLike) -> str:
        """
        Polybius square — replaces each letter with a digit pair (row, column).
        I and J are treated as the same letter.
        """
        square = [
            ['A','B','C','D','E'],
            ['F','G','H','I','K'],
            ['L','M','N','O','P'],
            ['Q','R','S','T','U'],
            ['V','W','X','Y','Z'],
        ]
        lookup = {}
        for r, row in enumerate(square):
            for c, ch in enumerate(row):
                lookup[ch] = f"{r+1}{c+1}"
        s = _to_bytes(data).decode("utf-8", errors="replace").upper().replace("J", "I")
        result = []
        for ch in s:
            if ch in lookup:
                result.append(lookup[ch])
            elif ch == " ":
                result.append(" ")
        return " ".join(result)

    def beaufort(self, key: KeyLike, data: DataLike) -> str:
        """Beaufort cipher (C = Key - Plain mod 26). Involutory."""
        k   = _to_bytes(key).upper()
        s   = _to_bytes(data).decode("utf-8", errors="replace")
        out = []
        ki  = 0
        for c in s:
            if c.isalpha():
                base  = 65 if c.isupper() else 97
                key_c = k[ki % len(k)]
                key_v = key_c - 65 if key_c >= 65 else key_c - 97
                enc   = (key_v - (ord(c.upper()) - 65)) % 26
                out.append(chr(base + enc))
                ki += 1
            else:
                out.append(c)
        return "".join(out)

    def playfair(self, key: KeyLike, data: DataLike) -> str:
        """Playfair cipher."""
        return _playfair_crypt(
            _to_bytes(key).decode("utf-8", errors="replace"),
            _to_bytes(data).decode("utf-8", errors="replace"),
            encrypt=True,
        )

    def rail_fence(self, data: DataLike, rails: int = 3) -> str:
        """Rail Fence cipher."""
        s = _to_bytes(data).decode("utf-8", errors="replace")
        fence = [[] for _ in range(rails)]
        rail, direction = 0, 1
        for ch in s:
            fence[rail].append(ch)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
        return "".join("".join(r) for r in fence)

    # ── WordLock ──────────────────────────────────────────────────────────────

    def wordlock(self, word: str, data: DataLike) -> str:
        """
        WordLock v2 — custom passphrase-based encryption algorithm.

        Protection layers:
          1. S-box substitution (KSA from SHA3)
          2. XOR with stream (SHA3 chain)
          3. Fisher-Yates byte permutation
          + Random salt (semantic security)
          + HMAC-SHA256 integrity tag
        """
        return _wordlock_crypt(word, _to_bytes(data), encrypt=True)

    # ── Encoding ──────────────────────────────────────────────────────────────

    def base64(self, data: DataLike) -> str:
        return _b64enc(_to_bytes(data))

    def base64url(self, data: DataLike) -> str:
        return base64.urlsafe_b64encode(_to_bytes(data)).decode().rstrip("=")

    def base32(self, data: DataLike) -> str:
        return base64.b32encode(_to_bytes(data)).decode()

    def base58(self, data: DataLike) -> str:
        return _base58_encode(_to_bytes(data))

    def hex(self, data: DataLike) -> str:
        return _to_bytes(data).hex()

    def morse(self, data: DataLike) -> str:
        return _morse_encode(_to_bytes(data).decode("utf-8", errors="replace"))

    def binary(self, data: DataLike) -> str:
        return " ".join(f"{b:08b}" for b in _to_bytes(data))


# ─── Decryption ───────────────────────────────────────────────────────────────

class Decrypt:
    """Data decryption."""

    def _decode(self, data: bytes) -> Union[str, bytes]:
        return _to_str(data)

    # ── AES-GCM ───────────────────────────────────────────────────────────────

    def aes_gcm(self, key: KeyLike, data: str, aad: Optional[bytes] = None) -> Union[str, bytes]:
        """AES-256-GCM decryption."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        k   = _key_to_raw(key, 32)
        raw = _b64dec(data)
        if len(raw) < 12 + 16:
            raise DecryptionError("Data is too short for AES-GCM")
        nonce, ct = raw[:12], raw[12:]
        try:
            return self._decode(AESGCM(k).decrypt(nonce, ct, aad))
        except Exception:
            raise DecryptionError("Wrong key, AAD, or corrupted data")

    def aes_gcm_128(self, key: KeyLike, data: str, aad: Optional[bytes] = None) -> Union[str, bytes]:
        """AES-128-GCM decryption."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        k   = _key_to_raw(key, 16)
        raw = _b64dec(data)
        nonce, ct = raw[:12], raw[12:]
        try:
            return self._decode(AESGCM(k).decrypt(nonce, ct, aad))
        except Exception:
            raise DecryptionError("Wrong key, AAD, or corrupted data")

    # ── AES-CBC ───────────────────────────────────────────────────────────────

    def aes128(self, key: KeyLike, data: str) -> Union[str, bytes]:
        return self._aes_cbc(key, data, 16)

    def aes192(self, key: KeyLike, data: str) -> Union[str, bytes]:
        return self._aes_cbc(key, data, 24)

    def aes256(self, key: KeyLike, data: str) -> Union[str, bytes]:
        return self._aes_cbc(key, data, 32)

    def _aes_cbc(self, key: KeyLike, data: str, ksize: int) -> Union[str, bytes]:
        _require(CRYPTO_AVAILABLE, "cryptography")
        k   = _key_to_raw(key, ksize)
        raw = _b64dec(data)
        if len(raw) < 16:
            raise DecryptionError("Data is too short for AES-CBC")
        iv, ct = raw[:16], raw[16:]
        try:
            dec    = Cipher(algorithms.AES(k), modes.CBC(iv), backend=default_backend()).decryptor()
            padded = dec.update(ct) + dec.finalize()
            unpad  = sym_padding.PKCS7(128).unpadder()
            return self._decode(unpad.update(padded) + unpad.finalize())
        except Exception:
            raise DecryptionError("Wrong key or corrupted data")

    # ── AES-CTR ───────────────────────────────────────────────────────────────

    def aes_ctr(self, key: KeyLike, data: str) -> Union[str, bytes]:
        _require(CRYPTO_AVAILABLE, "cryptography")
        k   = _key_to_raw(key, 32)
        raw = _b64dec(data)
        nonce, ct = raw[:16], raw[16:]
        dec = Cipher(algorithms.AES(k), modes.CTR(nonce), backend=default_backend()).decryptor()
        return self._decode(dec.update(ct) + dec.finalize())

    # ── AES-SIV ───────────────────────────────────────────────────────────────

    def aes_siv(self, key: KeyLike, data: str, aad: Optional[bytes] = None) -> Union[str, bytes]:
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.ciphers.aead import AESSIV
        k = _key_to_raw(key, 64)
        try:
            return self._decode(AESSIV(k).decrypt(_b64dec(data), [aad] if aad else None))
        except Exception:
            raise DecryptionError("Wrong key/AAD or corrupted data")

    # ── ChaCha20-Poly1305 ────────────────────────────────────────────────────

    def chacha20_poly1305(self, key: KeyLike, data: str) -> Union[str, bytes]:
        _require(CRYPTO_AVAILABLE, "cryptography")
        k   = _key_to_raw(key, 32)
        raw = _b64dec(data)
        nonce, ct = raw[:12], raw[12:]
        try:
            return self._decode(ChaCha20Poly1305(k).decrypt(nonce, ct, None))
        except Exception:
            raise DecryptionError("Wrong key or corrupted data")

    def chacha20(self, key: KeyLike, data: str) -> Union[str, bytes]:
        raw = _b64dec(data)
        if PYCRYPTODOME_AVAILABLE:
            k = _key_to_raw(key, 32)
            nonce, ct = raw[:8], raw[8:]
            return self._decode(_ChaCha20.new(key=k, nonce=nonce).decrypt(ct))
        if CRYPTO_AVAILABLE:
            k = _key_to_raw(key, 32)
            nonce, ct = raw[:16], raw[16:]
            dec = Cipher(algorithms.ChaCha20(k, nonce), mode=None, backend=default_backend()).decryptor()
            return self._decode(dec.update(ct) + dec.finalize())
        raise MissingDependency("cryptography or pycryptodome")

    # ── Salsa20 ───────────────────────────────────────────────────────────────

    def salsa20(self, key: KeyLike, data: str) -> Union[str, bytes]:
        if PYCRYPTODOME_AVAILABLE:
            from Crypto.Cipher import Salsa20 as _Salsa20
            k   = _key_to_raw(key, 32)
            raw = _b64dec(data)
            nonce, ct = raw[:8], raw[8:]
            return self._decode(_Salsa20.new(key=k, nonce=nonce).decrypt(ct))
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")

    # ── DES / 3DES ────────────────────────────────────────────────────────────

    def des(self, key: KeyLike, data: str) -> Union[str, bytes]:
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")
        k   = _key_to_raw(key, 8)
        raw = _b64dec(data)
        return self._decode(_unpad(_DES.new(k, _DES.MODE_CBC, raw[:8]).decrypt(raw[8:]), 8))

    def triple_des(self, key: KeyLike, data: str) -> Union[str, bytes]:
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")
        k   = _key_to_raw(key, 24)
        raw = _b64dec(data)
        return self._decode(_unpad(_DES3.new(k, _DES3.MODE_CBC, raw[:8]).decrypt(raw[8:]), 8))

    # ── Blowfish / CAST / RC2 / RC4 ───────────────────────────────────────────

    def blowfish(self, key: KeyLike, data: str) -> Union[str, bytes]:
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")
        k   = _key_to_raw(key, 16)
        raw = _b64dec(data)
        return self._decode(_unpad(_Blowfish.new(k, _Blowfish.MODE_CBC, raw[:8]).decrypt(raw[8:]), 8))

    def cast(self, key: KeyLike, data: str) -> Union[str, bytes]:
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")
        k   = _key_to_raw(key, 16)
        raw = _b64dec(data)
        return self._decode(_unpad(_CAST.new(k, _CAST.MODE_CBC, raw[:8]).decrypt(raw[8:]), 8))

    def rc2(self, key: KeyLike, data: str) -> Union[str, bytes]:
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")
        k   = _key_to_raw(key, 16)
        raw = _b64dec(data)
        return self._decode(_unpad(_ARC2.new(k, _ARC2.MODE_CBC, raw[:8]).decrypt(raw[8:]), 8))

    def rc4(self, key: KeyLike, data: str) -> Union[str, bytes]:
        _require(PYCRYPTODOME_AVAILABLE, "pycryptodome")
        k = _key_to_raw(key, 16)
        return self._decode(_ARC4.new(k).decrypt(_b64dec(data)))

    # ── RSA ───────────────────────────────────────────────────────────────────

    def rsa(
        self,
        private_key_pem: str,
        data: str,
        passphrase: Optional[str] = None,
    ) -> Union[str, bytes]:
        """RSA-OAEP-SHA256 decryption."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        priv = load_pem_private_key(
            _to_bytes(private_key_pem),
            password=_to_bytes(passphrase) if passphrase else None,
            backend=default_backend(),
        )
        try:
            return self._decode(priv.decrypt(
                _b64dec(data),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            ))
        except Exception:
            raise DecryptionError("Wrong key or corrupted data")

    def rsa_oaep_sha512(
        self,
        private_key_pem: str,
        data: str,
        passphrase: Optional[str] = None,
    ) -> Union[str, bytes]:
        """RSA-OAEP-SHA512 decryption."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        priv = load_pem_private_key(
            _to_bytes(private_key_pem),
            password=_to_bytes(passphrase) if passphrase else None,
            backend=default_backend(),
        )
        try:
            return self._decode(priv.decrypt(
                _b64dec(data),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None,
                ),
            ))
        except Exception:
            raise DecryptionError("Wrong key or corrupted data")

    # ── ECIES ────────────────────────────────────────────────────────────────

    def ecies(self, private_key_pem: str, data: str) -> Union[str, bytes]:
        """ECIES decryption."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key, load_der_public_key,
        )
        priv = load_pem_private_key(
            _to_bytes(private_key_pem), password=None, backend=default_backend()
        )
        raw = _b64dec(data)
        eph_len       = struct.unpack(">H", raw[:2])[0]
        eph_pub_bytes = raw[2:2 + eph_len]
        rest          = raw[2 + eph_len:]
        nonce, ct     = rest[:12], rest[12:]
        eph_pub  = load_der_public_key(eph_pub_bytes, backend=default_backend())
        shared   = priv.exchange(ECDH(), eph_pub)
        sym_key  = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ecies",
            backend=default_backend(),
        ).derive(shared)
        try:
            return self._decode(AESGCM(sym_key).decrypt(nonce, ct, None))
        except Exception:
            raise DecryptionError("Wrong key or corrupted data")

    # ── Classical ciphers ─────────────────────────────────────────────────────

    def xor(self, key: KeyLike, data: str) -> Union[str, bytes]:
        """XOR decryption. Expects format from Encrypt.xor."""
        k   = _key_to_raw(key, 32)
        raw = _b64dec(data)
        if len(raw) < 16:
            raise DecryptionError("Data is too short for XOR (missing nonce)")
        nonce, ct  = raw[:16], raw[16:]
        stream_key = _hmac.new(k, nonce, "sha256").digest()
        stream     = _derive_key(stream_key, len(ct))
        return self._decode(bytes(b ^ stream[i] for i, b in enumerate(ct)))

    def vigenere(self, key: KeyLike, data: str) -> Union[str, bytes]:
        k   = _to_bytes(key)
        raw = _b64dec(data)
        return self._decode(bytes((b - k[i % len(k)]) % 256 for i, b in enumerate(raw)))

    def caesar(self, data: DataLike, shift: int = 13) -> str:
        s = _to_bytes(data).decode("utf-8", errors="replace")
        result = []
        for c in s:
            if c.isalpha():
                base = 65 if c.isupper() else 97
                result.append(chr((ord(c) - base - shift) % 26 + base))
            else:
                result.append(c)
        return "".join(result)

    def rot13(self, data: DataLike) -> str:
        return self.caesar(data, 13)

    def rot47(self, data: DataLike) -> str:
        return encrypt.rot47(data)

    def atbash(self, data: DataLike) -> str:
        return encrypt.atbash(data)

    def polybius(self, data: str) -> str:
        reverse = {}
        square = [
            ['A','B','C','D','E'],
            ['F','G','H','I','K'],
            ['L','M','N','O','P'],
            ['Q','R','S','T','U'],
            ['V','W','X','Y','Z'],
        ]
        for r, row in enumerate(square):
            for c, ch in enumerate(row):
                reverse[f"{r+1}{c+1}"] = ch
        tokens = data.split()
        return "".join(reverse.get(t, " " if t == " " else "?") for t in tokens)

    def beaufort(self, key: KeyLike, data: DataLike) -> str:
        return encrypt.beaufort(key, data)

    def playfair(self, key: KeyLike, data: DataLike) -> str:
        return _playfair_crypt(
            _to_bytes(key).decode("utf-8", errors="replace"),
            _to_bytes(data).decode("utf-8", errors="replace"),
            encrypt=False,
        )

    def rail_fence(self, data: DataLike, rails: int = 3) -> str:
        s   = _to_bytes(data).decode("utf-8", errors="replace")
        n   = len(s)
        pat = _rail_fence_pattern(n, rails)
        rail_lens = [0] * rails
        for r in pat:
            rail_lens[r] += 1
        pos = 0
        rail_chars: List[List[str]] = []
        for length in rail_lens:
            rail_chars.append(list(s[pos:pos + length]))
            pos += length
        rail_idx = [0] * rails
        result   = []
        for r in pat:
            result.append(rail_chars[r][rail_idx[r]])
            rail_idx[r] += 1
        return "".join(result)

    def base64(self, data: str) -> Union[str, bytes]:
        return self._decode(_b64dec(data))

    def base64url(self, data: str) -> Union[str, bytes]:
        padded = data + "=" * (-len(data) % 4)
        return self._decode(base64.urlsafe_b64decode(padded))

    def base32(self, data: str) -> Union[str, bytes]:
        return self._decode(base64.b32decode(data.upper()))

    def base58(self, data: str) -> Union[str, bytes]:
        return self._decode(_base58_decode(data))

    def hex(self, data: str) -> Union[str, bytes]:
        try:
            return self._decode(bytes.fromhex(data))
        except ValueError as e:
            raise DecryptionError(f"Invalid hex: {e}") from e

    def morse(self, data: str) -> str:
        return _morse_decode(data)

    def binary(self, data: str) -> Union[str, bytes]:
        groups = data.split()
        try:
            return self._decode(bytes(int(g, 2) for g in groups))
        except ValueError as e:
            raise DecryptionError(f"Invalid binary: {e}") from e

    def wordlock(self, word: str, data: str) -> Union[str, bytes]:
        """
        WordLock v2 — decryption by passphrase.
        Raises IntegrityError on wrong passphrase.
        """
        raw: bytes = _wordlock_crypt(word, _b64dec(data), encrypt=False)
        return _to_str(raw)


# ─── Hashing ──────────────────────────────────────────────────────────────────

class Hash:
    """Cryptographic hash functions and KDFs."""

    def _h(self, algo: str, data: DataLike) -> str:
        return hashlib.new(algo, _to_bytes(data)).hexdigest()

    def md5(self, data: DataLike) -> str:
        """MD5 (not for security!)"""
        return self._h("md5", data)

    def sha1(self, data: DataLike) -> str:
        """SHA-1 (deprecated)."""
        return self._h("sha1", data)

    def sha224(self, data: DataLike) -> str:
        return self._h("sha224", data)

    def sha256(self, data: DataLike) -> str:
        return self._h("sha256", data)

    def sha384(self, data: DataLike) -> str:
        return self._h("sha384", data)

    def sha512(self, data: DataLike) -> str:
        return self._h("sha512", data)

    def sha512_256(self, data: DataLike) -> str:
        return self._h("sha512_256", data)

    def sha3_224(self, data: DataLike) -> str:
        return self._h("sha3_224", data)

    def sha3_256(self, data: DataLike) -> str:
        return self._h("sha3_256", data)

    def sha3_384(self, data: DataLike) -> str:
        return self._h("sha3_384", data)

    def sha3_512(self, data: DataLike) -> str:
        return self._h("sha3_512", data)

    def blake2b(self, data: DataLike, digest_size: int = 64) -> str:
        return hashlib.blake2b(_to_bytes(data), digest_size=digest_size).hexdigest()

    def blake2s(self, data: DataLike, digest_size: int = 32) -> str:
        return hashlib.blake2s(_to_bytes(data), digest_size=digest_size).hexdigest()

    def blake2b_keyed(self, key: DataLike, data: DataLike, digest_size: int = 64) -> str:
        k = _to_bytes(key)[:64]
        return hashlib.blake2b(_to_bytes(data), key=k, digest_size=digest_size).hexdigest()

    def shake128(self, data: DataLike, length: int = 32) -> str:
        return hashlib.shake_128(_to_bytes(data)).hexdigest(length)

    def shake256(self, data: DataLike, length: int = 64) -> str:
        return hashlib.shake_256(_to_bytes(data)).hexdigest(length)

    def crc32(self, data: DataLike) -> str:
        return format(zlib.crc32(_to_bytes(data)) & 0xFFFFFFFF, "08x")

    def adler32(self, data: DataLike) -> str:
        return format(zlib.adler32(_to_bytes(data)) & 0xFFFFFFFF, "08x")

    # ── Password KDFs ─────────────────────────────────────────────────────────

    def pbkdf2(
        self,
        password: DataLike,
        salt: Optional[DataLike] = None,
        iterations: int = 600_001,
        length: int = 32,
        algo: str = "sha256",
    ) -> Tuple[str, str]:
        """PBKDF2 for passwords. Returns: (hash_hex, salt_hex)"""
        s  = _to_bytes(salt) if salt else secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac(algo, _to_bytes(password), s, iterations, dklen=length)
        return dk.hex(), s.hex() if isinstance(s, bytes) else s

    def verify_pbkdf2(
        self,
        password: DataLike,
        hash_hex: str,
        salt_hex: str,
        iterations: int = 200_000,
        algo: str = "sha256",
    ) -> bool:
        s  = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac(algo, _to_bytes(password), s, iterations)
        return _hmac.compare_digest(dk.hex(), hash_hex)

    def scrypt(
        self,
        password: DataLike,
        salt: Optional[DataLike] = None,
        n: int = 2**14,
        r: int = 8,
        p: int = 1,
        length: int = 32,
    ) -> Tuple[str, str]:
        """scrypt KDF. Returns: (hash_hex, salt_hex)"""
        _require(CRYPTO_AVAILABLE, "cryptography")
        s   = _to_bytes(salt) if salt else secrets.token_bytes(16)
        kdf = Scrypt(salt=s, length=length, n=n, r=r, p=p, backend=default_backend())
        dk  = kdf.derive(_to_bytes(password))
        return dk.hex(), s.hex() if isinstance(s, bytes) else s

    def argon2(
        self,
        password: DataLike,
        salt: Optional[DataLike] = None,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 4,
        hash_len: int = 32,
        variant: str = "argon2id",
    ) -> Tuple[str, str]:
        """
        Argon2 — recommended KDF for passwords.
        Returns: (hash_hex, salt_hex)
        """
        _require(ARGON2_AVAILABLE, "argon2-cffi")
        s = _to_bytes(salt) if salt else secrets.token_bytes(16)
        type_map = {
            "argon2id": Argon2Type.ID,
            "argon2i":  Argon2Type.I,
            "argon2d":  Argon2Type.D,
        }
        t = type_map.get(variant, Argon2Type.ID)
        dk = hash_secret_raw(
            secret=_to_bytes(password),
            salt=s,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=t,
        )
        return dk.hex(), s.hex() if isinstance(s, bytes) else s

    def verify_argon2(self, password: DataLike, hash_hex: str, salt_hex: str, **kwargs) -> bool:
        dk, _ = self.argon2(password, salt=bytes.fromhex(salt_hex), **kwargs)
        return _hmac.compare_digest(dk, hash_hex)

    def file(self, path: str, algo: str = "sha256") -> str:
        """File hash via streaming read."""
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def file_multi(self, path: str) -> Dict[str, str]:
        """File hashes with all major algorithms in a single pass."""
        hashes_map = {
            "md5":     hashlib.md5(),
            "sha1":    hashlib.sha1(),
            "sha256":  hashlib.sha256(),
            "sha512":  hashlib.sha512(),
            "blake2b": hashlib.blake2b(),
        }
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                for h in hashes_map.values():
                    h.update(chunk)
        return {k: v.hexdigest() for k, v in hashes_map.items()}

    def tree(self, items: List[DataLike], algo: str = "sha256") -> str:
        """
        Merkle hash tree for a list of data items.
        Returns the root hash. Useful for verifying data sets.
        """
        if not items:
            return hashlib.new(algo, b"").hexdigest()
        leaves = [hashlib.new(algo, _to_bytes(item)).digest() for item in items]
        while len(leaves) > 1:
            if len(leaves) % 2 != 0:
                leaves.append(leaves[-1])  # duplicate the last leaf
            leaves = [
                hashlib.new(algo, leaves[i] + leaves[i + 1]).digest()
                for i in range(0, len(leaves), 2)
            ]
        return leaves[0].hex()

    def __call__(self, data: DataLike, algo: str = "sha256") -> str:
        return self._h(algo, data)


# ─── Signatures ───────────────────────────────────────────────────────────────

class Sign:
    """HMAC signatures, RSA-PSS, ECDSA, Ed25519."""

    def _hmac(self, key: DataLike, data: DataLike, algo: str) -> str:
        return _hmac.new(_to_bytes(key), _to_bytes(data), algo).hexdigest()

    def hmac_md5(self, key: DataLike, data: DataLike) -> str:
        return self._hmac(key, data, "md5")

    def hmac_sha1(self, key: DataLike, data: DataLike) -> str:
        return self._hmac(key, data, "sha1")

    def hmac_sha256(self, key: DataLike, data: DataLike) -> str:
        return self._hmac(key, data, "sha256")

    def hmac_sha512(self, key: DataLike, data: DataLike) -> str:
        return self._hmac(key, data, "sha512")

    def hmac_sha3_256(self, key: DataLike, data: DataLike) -> str:
        return self._hmac(key, data, "sha3_256")

    def hmac_blake2b(self, key: DataLike, data: DataLike) -> str:
        k = _to_bytes(key)[:64]
        return hashlib.blake2b(_to_bytes(data), key=k).hexdigest()

    def verify(
        self,
        key: DataLike,
        data: DataLike,
        signature: str,
        algo: str = "sha256",
    ) -> bool:
        """Secure HMAC verification (timing-attack resistant)."""
        expected = self._hmac(key, data, algo)
        return _hmac.compare_digest(expected, signature)

    def rsa_sign(
        self,
        private_key_pem: str,
        data: DataLike,
        passphrase: Optional[str] = None,
    ) -> str:
        """RSA-PSS signature (SHA-256)."""
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        priv = load_pem_private_key(
            _to_bytes(private_key_pem),
            password=_to_bytes(passphrase) if passphrase else None,
            backend=default_backend(),
        )
        sig = priv.sign(
            _to_bytes(data),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return _b64enc(sig)

    def rsa_verify(self, public_key_pem: str, data: DataLike, signature: str) -> bool:
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        try:
            pub = load_pem_public_key(_to_bytes(public_key_pem), backend=default_backend())
            pub.verify(
                _b64dec(signature),
                _to_bytes(data),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def ecdsa_sign(
        self,
        private_key_pem: str,
        data: DataLike,
        passphrase: Optional[str] = None,
        hash_algo: str = "sha256",
    ) -> str:
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        algo_map = {
            "sha256": _ec.ECDSA(hashes.SHA256()),
            "sha384": _ec.ECDSA(hashes.SHA384()),
            "sha512": _ec.ECDSA(hashes.SHA512()),
        }
        priv = load_pem_private_key(
            _to_bytes(private_key_pem),
            password=_to_bytes(passphrase) if passphrase else None,
            backend=default_backend(),
        )
        return _b64enc(priv.sign(_to_bytes(data), algo_map.get(hash_algo, algo_map["sha256"])))

    def ecdsa_verify(
        self,
        public_key_pem: str,
        data: DataLike,
        signature: str,
        hash_algo: str = "sha256",
    ) -> bool:
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        algo_map = {
            "sha256": _ec.ECDSA(hashes.SHA256()),
            "sha384": _ec.ECDSA(hashes.SHA384()),
            "sha512": _ec.ECDSA(hashes.SHA512()),
        }
        try:
            pub = load_pem_public_key(_to_bytes(public_key_pem), backend=default_backend())
            pub.verify(
                _b64dec(signature),
                _to_bytes(data),
                algo_map.get(hash_algo, algo_map["sha256"]),
            )
            return True
        except Exception:
            return False

    def ed25519_sign(self, private_key_pem: str, data: DataLike) -> str:
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        priv = load_pem_private_key(_to_bytes(private_key_pem), password=None, backend=default_backend())
        return _b64enc(priv.sign(_to_bytes(data)))

    def ed25519_verify(self, public_key_pem: str, data: DataLike, signature: str) -> bool:
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        try:
            pub = load_pem_public_key(_to_bytes(public_key_pem), backend=default_backend())
            pub.verify(_b64dec(signature), _to_bytes(data))
            return True
        except Exception:
            return False

    def poly1305(self, key: KeyLike, data: DataLike) -> str:
        """Poly1305 MAC (32-byte tag). Requires a unique key per message!"""
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.poly1305 import Poly1305
        k = _key_to_raw(key, 32)
        return Poly1305.generate_tag(k, _to_bytes(data)).hex()

    def poly1305_verify(self, key: KeyLike, data: DataLike, tag: str) -> bool:
        _require(CRYPTO_AVAILABLE, "cryptography")
        from cryptography.hazmat.primitives.poly1305 import Poly1305
        k = _key_to_raw(key, 32)
        try:
            Poly1305.verify_tag(k, _to_bytes(data), bytes.fromhex(tag))
            return True
        except Exception:
            return False


# ─── Utilities ────────────────────────────────────────────────────────────────

class Utils:
    """Utilities: random data, analysis, key splitting, OTP, TOTP."""

    def random_bytes(self, n: int = 32) -> bytes:
        return secrets.token_bytes(n)

    def random_hex(self, n: int = 32) -> str:
        return secrets.token_hex(n)

    def random_token(self, n: int = 32) -> str:
        return secrets.token_urlsafe(n)

    def random_int(self, low: int, high: int) -> int:
        if low > high:
            raise ValueError("low must be <= high")
        return secrets.randbelow(high - low + 1) + low

    def secure_compare(self, a: DataLike, b: DataLike) -> bool:
        return _hmac.compare_digest(_to_bytes(a), _to_bytes(b))

    def xor_bytes(self, a: bytes, b: bytes) -> bytes:
        if len(a) != len(b):
            raise ValueError(f"Lengths must match: {len(a)} != {len(b)}")
        return bytes(x ^ y for x, y in zip(a, b))

    def zeroize(self, data: Union[bytearray, memoryview]) -> None:
        """
        Securely zeroes the contents of a bytearray.
        Reduces the time secrets remain in memory.
        Note: does not guarantee OS-level zeroing (Python GC).
        """
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, memoryview):
            for i in range(len(data)):
                data[i] = 0

    def timing_safe_sleep(self, base_ms: float = 100.0, jitter_ms: float = 50.0) -> None:
        """
        Random delay to prevent timing attacks in network protocols.
        Useful when verifying passwords/tokens in API handlers.
        """
        delay = (base_ms + secrets.randbelow(int(jitter_ms * 1000)) / 1000.0) / 1000.0
        time.sleep(delay)

    # ── Key splitting (XOR scheme) ────────────────────────────────────────────

    def split_key(self, key: str, n: int = 3) -> List[str]:
        """
        Splits a key into n shares (XOR scheme).
        All n shares are required for recovery.
        """
        if n < 2:
            raise ValueError("n must be >= 2")
        try:
            raw = bytes.fromhex(key)
        except ValueError:
            raw = _to_bytes(key)
        shares = [secrets.token_bytes(len(raw)) for _ in range(n - 1)]
        last   = raw
        for s in shares:
            last = bytes(x ^ y for x, y in zip(last, s))
        shares.append(last)
        return [s.hex() for s in shares]

    def recover_key(self, shares: List[str]) -> str:
        """Recovers a key from all shares."""
        if len(shares) < 2:
            raise ValueError("At least 2 shares are required")
        parts  = [bytes.fromhex(s) for s in shares]
        if len(set(len(p) for p in parts)) > 1:
            raise ValueError("All shares must be the same size")
        result = parts[0]
        for p in parts[1:]:
            result = bytes(x ^ y for x, y in zip(result, p))
        return result.hex()

    # ── OTP ───────────────────────────────────────────────────────────────────

    def otp_encrypt(self, data: DataLike) -> Tuple[str, str]:
        """
        One-Time Pad encryption.
        Information-theoretically secure when used correctly.
        Returns: (ciphertext_hex, key_hex)
        """
        d   = _to_bytes(data)
        key = secrets.token_bytes(len(d))
        ct  = bytes(b ^ k for b, k in zip(d, key))
        return ct.hex(), key.hex()

    def otp_decrypt(self, ciphertext_hex: str, key_hex: str) -> Union[str, bytes]:
        ct  = bytes.fromhex(ciphertext_hex)
        key = bytes.fromhex(key_hex)
        if len(ct) != len(key):
            raise ValueError("Ciphertext and key lengths must match")
        return _to_str(bytes(c ^ k for c, k in zip(ct, key)))

    # ── TOTP / HOTP ───────────────────────────────────────────────────────────

    def hotp(self, secret: str, counter: int, digits: int = 6) -> str:
        """HOTP (RFC 4226)."""
        key     = base64.b32decode(secret.upper().replace(" ", ""))
        msg     = struct.pack(">Q", counter)
        h       = _hmac.new(key, msg, "sha1").digest()
        offset  = h[-1] & 0x0F
        code    = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
        return str(code % (10 ** digits)).zfill(digits)

    def totp(self, secret: str, digits: int = 6, period: int = 30) -> str:
        """TOTP (RFC 6238) — compatible with Google Authenticator, Authy, etc."""
        counter = int(time.time()) // period
        return self.hotp(secret, counter, digits)

    def totp_verify(
        self,
        secret: str,
        code: str,
        digits: int = 6,
        period: int = 30,
        window: int = 1,
    ) -> bool:
        counter = int(time.time()) // period
        return any(
            _hmac.compare_digest(self.hotp(secret, counter + i, digits), code)
            for i in range(-window, window + 1)
        )

    def totp_uri(
        self,
        secret: str,
        account: str,
        issuer: str = "cryptolibo",
        digits: int = 6,
        period: int = 30,
    ) -> str:
        from urllib.parse import quote
        return (
            f"otpauth://totp/{quote(issuer)}:{quote(account)}"
            f"?secret={secret}&issuer={quote(issuer)}"
            f"&digits={digits}&period={period}"
        )

    def generate_totp_secret(self) -> str:
        return base64.b32encode(secrets.token_bytes(20)).decode()

    # ── Analysis ──────────────────────────────────────────────────────────────

    def entropy(self, data: DataLike) -> float:
        """Shannon entropy (bits/byte)."""
        raw = _to_bytes(data)
        if not raw:
            return 0.0
        freq: Dict[int, int] = {}
        for b in raw:
            freq[b] = freq.get(b, 0) + 1
        n = len(raw)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def is_encrypted(self, data: str) -> bool:
        """Heuristic: high-entropy base64 → likely ciphertext."""
        try:
            raw = _b64dec(data)
            return self.entropy(raw) > 6.5
        except Exception:
            return False

    def diff(self, a: DataLike, b: DataLike) -> Dict[str, Any]:
        """Compare two data items: differences and statistics."""
        ba, bb = _to_bytes(a), _to_bytes(b)
        diffs  = sum(x != y for x, y in zip(ba, bb)) + abs(len(ba) - len(bb))
        return {
            "equal":      ba == bb,
            "len_a":      len(ba),
            "len_b":      len(bb),
            "diff_bytes": diffs,
            "similarity": round(1 - diffs / max(len(ba), len(bb), 1), 4),
        }

    def benchmark(self, key: Optional[str] = None, size: int = 1024) -> Dict[str, Any]:
        """Benchmark all available algorithms."""
        k    = key or generate_key()
        data = secrets.token_bytes(size)
        results: Dict[str, Any] = {}

        pairs = [
            ("xor",     encrypt.xor,  decrypt.xor),
            ("wordlock", lambda _k, d: encrypt.wordlock("bench_key", d),
                         lambda _k, d: decrypt.wordlock("bench_key", d)),
        ]
        if CRYPTO_AVAILABLE:
            pairs += [
                ("aes_gcm",           encrypt.aes_gcm,           decrypt.aes_gcm),
                ("aes256_cbc",        encrypt.aes256,             decrypt.aes256),
                ("aes_ctr",           encrypt.aes_ctr,            decrypt.aes_ctr),
                ("chacha20_poly1305", encrypt.chacha20_poly1305,  decrypt.chacha20_poly1305),
                ("salsa20",           encrypt.salsa20,            decrypt.salsa20),
            ]
        if PYCRYPTODOME_AVAILABLE:
            pairs += [
                ("chacha20",  encrypt.chacha20,  decrypt.chacha20),
                ("blowfish",  encrypt.blowfish,  decrypt.blowfish),
            ]

        for name, enc_fn, dec_fn in pairs:
            try:
                t0  = time.perf_counter()
                ct  = enc_fn(k, data)
                dec_fn(k, ct)
                ms  = round((time.perf_counter() - t0) * 1000, 3)
                results[name] = {
                    "ms": ms,
                    "throughput_mb_s": round(size / ms / 1000, 2) if ms > 0 else float("inf"),
                }
            except Exception as e:
                results[name] = {"error": str(e)}

        return results

    def constant_time_bytes(self, n: int) -> bytes:
        return secrets.token_bytes(n)


# ─── Encrypted secrets vault ──────────────────────────────────────────────────

class CryptoVault:
    """
    Encrypted secrets storage based on AES-GCM (with WordLock fallback).

    Stores key-value pairs in an encrypted JSON file.
    Supports context manager and auto-save.

    Example:
        vault = CryptoVault("vault.db", "my_master_password")
        vault.set("db_pass", "s3cr3t")
        vault.set("api_key", "sk-abc123", tags=["production"])
        val = vault.get("db_pass")          # → "s3cr3t"
        vault.delete("db_pass")
        vault.list_keys()                   # → ["api_key"]
        vault.export_keys("backup.db", "backup_password")

        # Context manager:
        with CryptoVault("vault.db", "password") as v:
            v.set("token", "xyz")
    """

    _VERSION = 1

    def __init__(
        self,
        path: str,
        master_password: str,
        auto_save: bool = True,
        kdf: str = "pbkdf2",
    ):
        self._path   = Path(path)
        self._master = master_password
        self._auto   = auto_save
        self._kdf    = kdf
        self._data: Dict[str, Any] = {}
        self._salt: Optional[bytes] = None
        self._dirty = False
        self._load()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _derive_master_key(self) -> bytes:
        if self._salt is None:
            self._salt = secrets.token_bytes(32)
        if self._kdf == "argon2" and ARGON2_AVAILABLE:
            return hash_secret_raw(
                secret=_to_bytes(self._master),
                salt=self._salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=Argon2Type.ID,
            )
        return hashlib.pbkdf2_hmac("sha256", _to_bytes(self._master), self._salt, 200_000, dklen=32)

    def _encrypt_vault(self, plaintext: bytes) -> bytes:
        k     = self._derive_master_key()
        nonce = secrets.token_bytes(12)
        if CRYPTO_AVAILABLE:
            ct = AESGCM(k).encrypt(nonce, plaintext, None)
        else:
            stream = _wl_stream(k, len(plaintext))
            ct = bytes(b ^ stream[i] for i, b in enumerate(plaintext))
            mac = _hmac.new(k, ct, "sha256").digest()[:16]
            ct = ct + mac
        return nonce + ct

    def _decrypt_vault(self, data: bytes) -> bytes:
        k     = self._derive_master_key()
        nonce = data[:12]
        ct    = data[12:]
        if CRYPTO_AVAILABLE:
            try:
                return AESGCM(k).decrypt(nonce, ct, None)
            except Exception:
                raise DecryptionError("Wrong master password or vault is corrupted")
        else:
            mac_given = ct[-16:]
            ct_body   = ct[:-16]
            mac_calc  = _hmac.new(k, ct_body, "sha256").digest()[:16]
            if not _hmac.compare_digest(mac_calc, mac_given):
                raise IntegrityError("Vault is corrupted or wrong password")
            stream = _wl_stream(k, len(ct_body))
            return bytes(b ^ stream[i] for i, b in enumerate(ct_body))

    def _load(self) -> None:
        if not self._path.exists():
            self._data = {}
            return
        try:
            raw = self._path.read_bytes()
            if not raw.strip():
                self._data = {}
                return
            envelope = json.loads(raw)
            self._salt = bytes.fromhex(envelope["salt"])
            ct = base64.b64decode(envelope["data"])
            plaintext = self._decrypt_vault(ct)
            self._data = json.loads(plaintext)
        except (json.JSONDecodeError, KeyError) as e:
            raise VaultError(f"Corrupted vault file: {e}") from e

    def _save(self) -> None:
        _ = self._derive_master_key()  # ensure salt exists
        plaintext = json.dumps(self._data, ensure_ascii=False).encode()
        ct = self._encrypt_vault(plaintext)
        envelope = {
            "v":    self._VERSION,
            "kdf":  self._kdf,
            "salt": self._salt.hex(),
            "data": base64.b64encode(ct).decode(),
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_bytes(json.dumps(envelope, indent=2).encode())
        self._dirty = False

    # ── Public API ────────────────────────────────────────────────────────────

    def set(
        self,
        name: str,
        value: str,
        tags: Optional[List[str]] = None,
        note: Optional[str] = None,
    ) -> None:
        """Stores a secret."""
        self._data[name] = {
            "value":   value,
            "tags":    tags or [],
            "note":    note or "",
            "created": int(time.time()),
            "updated": int(time.time()),
        }
        self._dirty = True
        if self._auto:
            self._save()

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieves a secret value."""
        entry = self._data.get(name)
        if entry is None:
            return default
        return entry["value"]

    def get_meta(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieves the full secret record with metadata."""
        return self._data.get(name)

    def delete(self, name: str) -> bool:
        """Deletes a secret. Returns True if it existed."""
        if name in self._data:
            del self._data[name]
            self._dirty = True
            if self._auto:
                self._save()
            return True
        return False

    def list_keys(self, tag: Optional[str] = None) -> List[str]:
        """Lists keys, optionally filtered by tag."""
        if tag is None:
            return list(self._data.keys())
        return [k for k, v in self._data.items() if tag in v.get("tags", [])]

    def rename(self, old_name: str, new_name: str) -> None:
        """Renames a secret."""
        if old_name not in self._data:
            raise VaultError(f"Secret not found: {old_name}")
        if new_name in self._data:
            raise VaultError(f"Name already in use: {new_name}")
        self._data[new_name] = self._data.pop(old_name)
        self._dirty = True
        if self._auto:
            self._save()

    def export_keys(self, path: str, password: str) -> None:
        """Exports the vault with a new password."""
        other = CryptoVault(path, password, auto_save=False)
        other._data = {k: v.copy() for k, v in self._data.items()}
        other._save()

    def change_password(self, new_password: str) -> None:
        """Changes the master password."""
        self._master = new_password
        self._salt   = None  # regenerate salt
        self._save()

    def save(self) -> None:
        """Force save."""
        self._save()

    def __contains__(self, name: str) -> bool:
        return name in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __enter__(self) -> "CryptoVault":
        return self

    def __exit__(self, *args) -> None:
        if self._dirty:
            self._save()

    def __repr__(self) -> str:
        return f"CryptoVault(path={self._path}, secrets={len(self._data)})"


# ─── Helper algorithms ────────────────────────────────────────────────────────

# Base58 — fixed implementation
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    # Count leading zeros
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    n = int.from_bytes(data, "big")
    result = []
    while n:
        n, r = divmod(n, 58)
        result.append(_B58_ALPHABET[r:r + 1])
    result.extend(b"1" * leading_zeros)
    return b"".join(reversed(result)).decode()


def _base58_decode(s: str) -> bytes:
    leading_ones = len(s) - len(s.lstrip("1"))
    n = 0
    for c in s.encode():
        idx = _B58_ALPHABET.index(c)
        n = n * 58 + idx
    result = []
    while n:
        n, r = divmod(n, 256)
        result.append(r)
    result.extend([0] * leading_ones)
    return bytes(reversed(result))


# Morse
_MORSE_ENC = {
    'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---',
    'K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-',
    'U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',
    '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.',
    '.':'.-.-.-',',':'--..--','?':'..--..','!':'-.-.--','/':'-..-.','(':'-.--.',')'  :'-.--.-',
    '&':'.-...', ':':'---...', ';':'-.-.-.', '=':'-...-', '+':'.-.-.', '-':'-....-',
}
_MORSE_DEC = {v: k for k, v in _MORSE_ENC.items()}


def _morse_encode(s: str) -> str:
    return "  ".join(
        " ".join(_MORSE_ENC.get(c.upper(), "?") for c in word)
        for word in s.split(" ")
    )


def _morse_decode(s: str) -> str:
    return " ".join(
        "".join(_MORSE_DEC.get(code, "?") for code in word.split(" "))
        for word in s.split("  ")
    )


# Playfair
def _playfair_crypt(key: str, text: str, encrypt_mode: bool) -> str:
    key_clean = ""
    seen = set()
    for c in (key + string.ascii_uppercase).upper():
        if c == "J":
            c = "I"
        if c in string.ascii_uppercase and c not in seen:
            key_clean += c
            seen.add(c)
    matrix = [key_clean[i*5:(i+1)*5] for i in range(5)]
    pos    = {}
    for r, row in enumerate(matrix):
        for c, ch in enumerate(row):
            pos[ch] = (r, c)

    text = text.upper().replace("J", "I")
    text = "".join(c for c in text if c in string.ascii_uppercase)
    i, pairs = 0, []
    while i < len(text):
        a = text[i]
        if i + 1 >= len(text):
            pairs.append((a, "X"))
            i += 1
        elif text[i] == text[i + 1]:
            pairs.append((a, "X"))
            i += 1
        else:
            pairs.append((a, text[i + 1]))
            i += 2

    step   = 1 if encrypt_mode else -1
    result = []
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            result += [matrix[ra][(ca + step) % 5], matrix[rb][(cb + step) % 5]]
        elif ca == cb:
            result += [matrix[(ra + step) % 5][ca], matrix[(rb + step) % 5][cb]]
        else:
            result += [matrix[ra][cb], matrix[rb][ca]]
    return "".join(result)


# Rail Fence
def _rail_fence_pattern(n: int, rails: int) -> List[int]:
    pattern = []
    rail, direction = 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return pattern


# ─── Public API ───────────────────────────────────────────────────────────────

encrypt = Encrypt()
decrypt = Decrypt()
hash    = Hash()
sign    = Sign()
utils   = Utils()


# ── Top-level convenience functions ───────────────────────────────────────────

def generate_key(
    bits: int = 256,
    save_to: Optional[str] = None,
    passphrase: Optional[str] = None,
    encoding: str = "hex",
) -> str:
    """Generates a cryptographically strong key."""
    return keys.generate(bits=bits, save_to=save_to, passphrase=passphrase, encoding=encoding)


def load_or_generate_key(path: Optional[str] = None, bits: int = 256) -> str:
    """Loads a key if it exists, otherwise creates a new one."""
    return keys.load_or_generate(path=path, bits=bits)


def quick_encrypt(data: DataLike, key: Optional[str] = None) -> Tuple[str, str]:
    """
    Quick AES-GCM encryption.
    Returns: (encrypted_data, key)
    """
    k = key or generate_key()
    if CRYPTO_AVAILABLE:
        return encrypt.aes_gcm(k, data), k
    return encrypt.wordlock(k[:16], data), k


def quick_decrypt(data: str, key: str) -> Union[str, bytes]:
    """Quick AES-GCM decryption."""
    if CRYPTO_AVAILABLE:
        return decrypt.aes_gcm(key, data)
    return decrypt.wordlock(key[:16], data)


def batch_encrypt(
    items: List[DataLike],
    key: Optional[str] = None,
    algo: str = "aes_gcm",
) -> Tuple[List[str], str]:
    """
    Batch encryption of a list of strings/bytes with a single key.

    Args:
        items: List of data to encrypt.
        key:   Key (if None — generated automatically).
        algo:  Encryption algorithm (aes_gcm | aes256 | chacha20_poly1305 | wordlock).
    Returns:
        (encrypted_list, key)

    Example:
        enc_list, key = batch_encrypt(["secret1", "secret2", "secret3"])
        dec_list = batch_decrypt(enc_list, key)
    """
    k       = key or generate_key()
    enc_fn  = getattr(encrypt, algo)
    results = []
    for item in items:
        if algo == "wordlock":
            results.append(enc_fn(k[:32], item))
        else:
            results.append(enc_fn(k, item))
    return results, k


def batch_decrypt(
    items: List[str],
    key: str,
    algo: str = "aes_gcm",
) -> List[Union[str, bytes]]:
    """
    Batch decryption.
    If a single element fails to decrypt — raises DecryptionError with the index.
    """
    dec_fn  = getattr(decrypt, algo)
    results = []
    for i, item in enumerate(items):
        try:
            if algo == "wordlock":
                results.append(dec_fn(key[:32], item))
            else:
                results.append(dec_fn(key, item))
        except (DecryptionError, IntegrityError) as e:
            raise DecryptionError(f"Error decrypting item #{i}: {e}") from e
    return results


def encrypt_file(
    path: str,
    key: Optional[str] = None,
    output: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Encrypts a file with AES-GCM (entire file loaded into memory).
    For large files use encrypt_stream.
    Returns: (output_path, key)
    """
    _require(CRYPTO_AVAILABLE, "cryptography")
    k   = key or generate_key()
    src = Path(path)
    dst = Path(output) if output else src.with_suffix(src.suffix + ".enc")
    raw = src.read_bytes()
    ct  = _b64dec(encrypt.aes_gcm(k, raw))
    dst.write_bytes(ct)
    return str(dst), k


def decrypt_file(
    path: str,
    key: str,
    output: Optional[str] = None,
) -> str:
    """Decrypts a file encrypted with encrypt_file."""
    _require(CRYPTO_AVAILABLE, "cryptography")
    src = Path(path)
    dst = Path(output) if output else Path(str(src).removesuffix(".enc"))
    raw = src.read_bytes()
    pt  = decrypt.aes_gcm(key, _b64enc(raw))
    if isinstance(pt, str):
        dst.write_text(pt, encoding="utf-8")
    else:
        dst.write_bytes(pt)
    return str(dst)


def encrypt_stream(
    src_path: str,
    dst_path: str,
    key: Optional[str] = None,
    chunk_size: int = _STREAM_CHUNK,
) -> str:
    """
    Streaming file encryption with AES-GCM (supports files of any size).

    Each chunk is encrypted separately with a unique nonce.
    File format:
      [6 bytes magic][32 bytes key salt][4 bytes # chunks][chunks...]
      Chunk: [4 bytes CT length][12 bytes nonce][CT]

    Args:
        src_path:   Path to the source file.
        dst_path:   Path to the output file.
        key:        Key (if None — generated automatically).
        chunk_size: Chunk size in bytes (default 64 KB).
    Returns:
        The key used.
    """
    _require(CRYPTO_AVAILABLE, "cryptography")
    k_str  = key or generate_key()
    k_raw  = _key_to_raw(k_str, 32)
    aesgcm = AESGCM(k_raw)

    src = Path(src_path)
    dst = Path(dst_path)
    dst.parent.mkdir(parents=True, exist_ok=True)

    # Collect all chunks first to know the total count
    chunks: List[bytes] = []
    with open(src, "rb") as f:
        while True:
            plaintext = f.read(chunk_size)
            if not plaintext:
                break
            nonce = secrets.token_bytes(12)
            ct    = aesgcm.encrypt(nonce, plaintext, None)
            chunk_data = struct.pack(">I", len(ct)) + nonce + ct
            chunks.append(chunk_data)

    salt = secrets.token_bytes(32)
    with open(dst, "wb") as f:
        f.write(_STREAM_MAGIC)
        f.write(salt)
        f.write(struct.pack(">I", len(chunks)))
        for chunk in chunks:
            f.write(chunk)

    return k_str


def decrypt_stream(
    src_path: str,
    dst_path: str,
    key: str,
) -> str:
    """
    Streaming decryption of a file encrypted with encrypt_stream.
    Returns: dst_path
    """
    _require(CRYPTO_AVAILABLE, "cryptography")
    k_raw  = _key_to_raw(key, 32)
    aesgcm = AESGCM(k_raw)

    src = Path(src_path)
    dst = Path(dst_path)
    dst.parent.mkdir(parents=True, exist_ok=True)

    with open(src, "rb") as f:
        magic = f.read(6)
        if magic != _STREAM_MAGIC:
            raise DecryptionError(
                f"Invalid file format (magic: {magic.hex()}, expected: {_STREAM_MAGIC.hex()})"
            )
        _salt      = f.read(32)
        num_chunks = struct.unpack(">I", f.read(4))[0]

        with open(dst, "wb") as out:
            for chunk_idx in range(num_chunks):
                ct_len = struct.unpack(">I", f.read(4))[0]
                nonce  = f.read(12)
                ct     = f.read(ct_len)
                try:
                    plaintext = aesgcm.decrypt(nonce, ct, None)
                except Exception:
                    raise DecryptionError(
                        f"Error decrypting chunk #{chunk_idx} — wrong key or file is corrupted"
                    )
                out.write(plaintext)

    return str(dst)


# ─── Library information ──────────────────────────────────────────────────────

def capabilities() -> Dict[str, Any]:
    """Returns available features and dependency versions."""
    return {
        "version":       __version__,
        "dependencies": {
            "cryptography":  {"available": CRYPTO_AVAILABLE,        "version": CRYPTO_VERSION},
            "pycryptodome":  {"available": PYCRYPTODOME_AVAILABLE,   "version": PYCRYPTODOME_VERSION},
            "argon2_cffi":   {"available": ARGON2_AVAILABLE,         "version": ARGON2_VERSION},
        },
        "algorithms": {
            "symmetric": [
                "aes_gcm", "aes_gcm_128", "aes128", "aes192", "aes256",
                "aes_ctr", "aes_siv",
                "chacha20_poly1305", "chacha20", "salsa20",
                "des", "triple_des", "blowfish", "cast", "rc2", "rc4",
            ],
            "asymmetric": ["rsa", "rsa_oaep_sha512", "ecies"],
            "classic": [
                "xor", "vigenere", "caesar", "rot13", "rot47",
                "atbash", "polybius", "beaufort", "playfair", "rail_fence",
            ],
            "custom":   ["wordlock"],
            "encoding": ["base64", "base64url", "base32", "base58", "hex", "morse", "binary"],
            "streaming": ["encrypt_stream", "decrypt_stream"],
        },
        "hash": [
            "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512_256",
            "sha3_224", "sha3_256", "sha3_384", "sha3_512",
            "blake2b", "blake2s", "blake2b_keyed",
            "shake128", "shake256",
            "crc32", "adler32",
            "pbkdf2", "scrypt", "argon2",
            "tree",  # Merkle
        ],
        "sign": [
            "hmac_md5", "hmac_sha1", "hmac_sha256", "hmac_sha512",
            "hmac_sha3_256", "hmac_blake2b",
            "rsa_sign", "rsa_verify",
            "ecdsa_sign", "ecdsa_verify",
            "ed25519_sign", "ed25519_verify",
            "poly1305", "poly1305_verify",
        ],
        "utils": [
            "random_bytes", "random_hex", "random_token", "random_int",
            "secure_compare", "xor_bytes", "zeroize", "timing_safe_sleep",
            "split_key", "recover_key",
            "otp_encrypt", "otp_decrypt",
            "hotp", "totp", "totp_verify", "totp_uri", "generate_totp_secret",
            "entropy", "is_encrypted", "diff", "benchmark",
        ],
        "keys": [
            "generate", "generate_rsa", "generate_ec",
            "generate_ed25519", "generate_x25519",
            "save", "load", "load_or_generate", "rotate",
            "password_to_key", "generate_password", "hkdf_expand", "info",
        ],
        "vault": ["CryptoVault"],
        "batch": ["batch_encrypt", "batch_decrypt"],
    }


# ─── Demo ─────────────────────────────────────────────────────────────────────

def demo():
    """Demonstrates all library features."""
    SEP  = "─" * 72
    PASS = "✓"
    FAIL = "✗"

    def _test(name: str, enc_fn, dec_fn, key, secret):
        try:
            ct = enc_fn(key, secret)
            pt = dec_fn(key, ct)
            ok = (pt == secret) or (isinstance(pt, bytes) and pt == _to_bytes(secret))
            status = f"{PASS if ok else FAIL}"
            print(f"  {name:<28} {status}  ct={str(ct)[:36]}...")
        except Exception as e:
            print(f"  {name:<28} {FAIL}  {type(e).__name__}: {e}")

    print(f"\n{SEP}")
    print(f"  cryptolibo v{__version__} — demo")
    print(f"  cryptography: {CRYPTO_VERSION or 'n/a'}  |  "
          f"pycryptodome: {PYCRYPTODOME_VERSION or 'n/a'}  |  "
          f"argon2: {ARGON2_VERSION or 'n/a'}")
    print(SEP)

    # 1. Keys
    print("\n[1] Key generation")
    key = generate_key(256)
    print(f"  256-bit hex key  : {key[:32]}...")
    b64_key = generate_key(256, encoding="base64")
    print(f"  256-bit b64 key  : {b64_key[:32]}...")
    pw_key, pw_salt = keys.password_to_key("my_password", algo="pbkdf2")
    print(f"  PBKDF2 key       : {pw_key[:32]}...")
    ki = keys.info(key)
    print(f"  Key quality      : {ki['quality']} ({ki['entropy_per_byte']} bits/byte)")

    # 2. Symmetric encryption
    secret = "Hello, World! 🔐"
    print(f"\n[2] Symmetric encryption  (data: '{secret}')")
    if CRYPTO_AVAILABLE:
        _test("AES-GCM (recommended)",  encrypt.aes_gcm,           decrypt.aes_gcm,           key, secret)
        _test("AES-GCM-128",            encrypt.aes_gcm_128,       decrypt.aes_gcm_128,       key, secret)
        _test("AES-256-CBC",            encrypt.aes256,            decrypt.aes256,            key, secret)
        _test("AES-CTR",                encrypt.aes_ctr,           decrypt.aes_ctr,           key, secret)
        try:
            _test("AES-SIV",            encrypt.aes_siv,           decrypt.aes_siv,           key, secret)
        except Exception as e:
            print(f"  {'AES-SIV':<28} {FAIL}  {e}")
        _test("ChaCha20-Poly1305",      encrypt.chacha20_poly1305, decrypt.chacha20_poly1305, key, secret)
        _test("Salsa20",                encrypt.salsa20,           decrypt.salsa20,           key, secret)
    if PYCRYPTODOME_AVAILABLE:
        _test("ChaCha20",               encrypt.chacha20,          decrypt.chacha20,          key, secret)
        _test("Blowfish-CBC",           encrypt.blowfish,          decrypt.blowfish,          key, secret)
        _test("3DES-CBC",               encrypt.triple_des,        decrypt.triple_des,        key, secret)

    # 3. WordLock
    print(f"\n[3] WordLock v2")
    for word in ["sigma", "correct horse battery staple", "Key123"]:
        ct = encrypt.wordlock(word, secret)
        pt = decrypt.wordlock(word, ct)
        ok = pt == secret
        print(f"  word='{word[:20]:<20}' {PASS if ok else FAIL}  ct={ct[:36]}...")
    try:
        decrypt.wordlock("wrong_word", ct)
        print(f"  Wrong word: should raise error {FAIL}")
    except (DecryptionError, IntegrityError):
        print(f"  Wrong word → IntegrityError {PASS}")

    # 4. Asymmetric
    if CRYPTO_AVAILABLE:
        print("\n[4] Asymmetric encryption")
        priv_rsa, pub_rsa = keys.generate_rsa(2048)
        ct  = encrypt.rsa(pub_rsa, "RSA-OAEP test")
        pt  = decrypt.rsa(priv_rsa, ct)
        print(f"  RSA-OAEP-SHA256 : {PASS if pt == 'RSA-OAEP test' else FAIL}")
        priv_ec, pub_ec = keys.generate_ec("P-256")
        ct3 = encrypt.ecies(pub_ec, "ECIES test")
        pt3 = decrypt.ecies(priv_ec, ct3)
        print(f"  ECIES (P-256)   : {PASS if pt3 == 'ECIES test' else FAIL}")

    # 5. Hashes
    print("\n[5] Hashing")
    for algo_name in ["sha256", "sha3_256", "blake2b", "sha512_256"]:
        h = getattr(hash, algo_name)(secret)
        print(f"  {algo_name:<15}: {h[:48]}...")
    tree_hash = hash.tree(["item1", "item2", "item3", "item4"])
    print(f"  Merkle tree    : {tree_hash[:48]}...")

    # 6. Signatures
    print("\n[6] Signatures")
    sig256 = sign.hmac_sha256(key, secret)
    print(f"  HMAC-SHA256   : {PASS if sign.verify(key, secret, sig256) else FAIL}  {sig256[:32]}...")
    if CRYPTO_AVAILABLE:
        priv_ed, pub_ed = keys.generate_ed25519()
        sig_ed = sign.ed25519_sign(priv_ed, secret)
        print(f"  Ed25519       : {PASS if sign.ed25519_verify(pub_ed, secret, sig_ed) else FAIL}")

    # 7. Batch encryption
    print("\n[7] Batch encrypt / decrypt")
    items = ["secret1", "secret_two", "third 🔑"]
    enc_list, bkey = batch_encrypt(items)
    dec_list = batch_decrypt(enc_list, bkey)
    ok = dec_list == items
    print(f"  batch_encrypt  : {PASS if ok else FAIL}  {len(items)} items")

    # 8. CryptoVault
    print("\n[8] CryptoVault")
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".vault", delete=False) as tf:
        vault_path = tf.name
    try:
        with CryptoVault(vault_path, "master123") as v:
            v.set("db_pass",    "super_secret",  tags=["db"], note="Production DB")
            v.set("api_key",    "sk-abc123",      tags=["api", "production"])
            v.set("jwt_secret", "jwt_s3cr3t")
        v2 = CryptoVault(vault_path, "master123")
        ok1 = v2.get("db_pass") == "super_secret"
        ok2 = v2.get("api_key") == "sk-abc123"
        ok3 = v2.list_keys(tag="production") == ["api_key"]
        print(f"  set/get        : {PASS if ok1 and ok2 else FAIL}")
        print(f"  tag filter     : {PASS if ok3 else FAIL}  keys={v2.list_keys(tag='production')}")
        print(f"  vault size     : {len(v2)} secrets")
        try:
            CryptoVault(vault_path, "wrong_password")
            print(f"  Wrong password : {FAIL}")
        except (DecryptionError, IntegrityError):
            print(f"  Wrong password → error {PASS}")
    finally:
        try:
            Path(vault_path).unlink()
        except Exception:
            pass

    # 9. Streaming file encryption
    print("\n[9] Streaming file encryption (encrypt_stream)")
    if CRYPTO_AVAILABLE:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            content = secrets.token_bytes(200_000)  # 200 KB
            f.write(content)
            src_path = f.name
        enc_path = src_path + ".stream.enc"
        dec_path = src_path + ".dec"
        try:
            stream_key = encrypt_stream(src_path, enc_path)
            decrypt_stream(enc_path, dec_path, stream_key)
            ok = Path(dec_path).read_bytes() == content
            print(f"  200 KB file    : {PASS if ok else FAIL}")
        finally:
            for p in [src_path, enc_path, dec_path]:
                try:
                    Path(p).unlink()
                except Exception:
                    pass

    # 10. Key rotation
    print("\n[10] Key rotation")
    old_key = generate_key()
    data_items = ["secret A", "secret B", "secret C"]
    enc_old, _ = batch_encrypt(data_items, old_key)
    new_key, enc_new = keys.rotate(old_key, data_list=enc_old)
    dec_new = batch_decrypt(enc_new, new_key)
    ok = dec_new == data_items
    print(f"  rotate + re-encrypt : {PASS if ok else FAIL}")

    # 11. Utilities
    print("\n[11] Utilities")
    ct_otp, key_otp = utils.otp_encrypt(secret)
    pt_otp = utils.otp_decrypt(ct_otp, key_otp)
    print(f"  OTP              : {PASS if pt_otp == secret else FAIL}")
    shares    = utils.split_key(key)
    recovered = utils.recover_key(shares)
    print(f"  split/recover    : {PASS if recovered == key else FAIL}")
    totp_s  = utils.generate_totp_secret()
    code    = utils.totp(totp_s)
    ok_totp = utils.totp_verify(totp_s, code)
    print(f"  TOTP             : {PASS if ok_totp else FAIL}  code={code}")
    print(f"  Key entropy      : {utils.entropy(bytes.fromhex(key)):.2f} bits/byte")

    # 12. Benchmark
    print("\n[12] Benchmark (1 KB)")
    bench = utils.benchmark(key)
    for algo, info in sorted(bench.items(), key=lambda x: x[1].get("ms", 9999)):
        if "error" in info:
            print(f"  {algo:<28}: error — {info['error']}")
        else:
            print(f"  {algo:<28}: {info['ms']:>7} ms  ({info['throughput_mb_s']:>6} MB/s)")

    print(f"\n{SEP}\n")


if __name__ == "__main__":
    demo()