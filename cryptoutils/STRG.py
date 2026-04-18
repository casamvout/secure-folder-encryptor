"""
strg.py — Secure True Random Generator  v3 (WRITTEN BY AI)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Surpasses secrets in several aspects:

  1. Forward secrecy — the pool is updated via an "extract-then-expand"
     scheme (HKDF-like): the old pool is destroyed after each block.
  2. Entropy pool 128 bytes (SHA3-512 × 2) — does not collapse to 32 bytes.
  3. Fork-safe — child processes automatically re-seed on os.fork().
  4. Bias-free randint — correct rejection sampling for any range.
  5. Entropy accumulator — accepts additional sources (CPU-jitter,
     call counter) without trusting them.
  6. Zeroization — sensitive buffers are zeroed with ctypes.memset.
     Works for both bytearray and bytes (via ob_val offset).
  7. Context manager — guaranteed pool cleanup via `with`.
  8. API-compatible with old STRG + several new methods.

Usage:
    from strg import STRG

    # Recommended — context manager guarantees zeroize()
    with STRG(fulcrum="my-session-id") as rng:
        rng.token_hex(32)           # '3f9a...' (64 chars)
        rng.token_bytes(16)         # b'\\x3f...'
        rng.randint(1, 100)         # 42
        rng.randbelow(100)          # 0..99
        rng.randfloat()             # 0.7312...
        rng.choice([1, 2, 3])       # 2
        rng.shuffle([1,2,3,4,5])    # [3,1,5,2,4]
        rng.sample([1,2,3,4,5], 3)  # [5,2,1]
        rng.password(16)            # 'xK9#mP2@...'
        rng.uuid4()                 # RFC-4122 v4
        rng.compare_digest(a, b)    # constant-time comparison
        rng.reseed()                # manually inject fresh entropy
        rng.bytes_for_bits(128)     # minimum bytes for n bits
        rng.randfloat(0.0, 1.0)     # [a, b) without float-overflow
"""

import ctypes
import hashlib
import hmac
import os
import struct
import threading
import time
import warnings
from typing import Optional, Sequence, TypeVar, Union

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Character set for passwords
# ---------------------------------------------------------------------------
_DEFAULT_PASSWORD_CHARSET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!@#$%^&*-_=+"
)

# ---------------------------------------------------------------------------
# Helper: securely zero bytes/bytearray in memory
# ---------------------------------------------------------------------------

# Offset to data in the bytes/bytearray object in CPython.
# Computed once at module load — not hardcoded.
def _find_bytes_data_offset() -> int:
    """
    Determines the offset from id(b) to the start of actual data in a bytes object.
    Searches for pattern b'\\xAA' * 8 via ctypes.string_at — more reliable than hardcoding.
    """
    marker = b"\xAA" * 8
    base   = id(marker)
    # CPython: bytes object contains data somewhere in the first ~64 bytes of the header
    raw    = ctypes.string_at(base, 128)
    offset = raw.find(marker)
    return offset if offset != -1 else -1

_BYTES_DATA_OFFSET: int = _find_bytes_data_offset()


def _zero(buf: Union[bytes, bytearray]) -> None:
    """
    Overwrites buffer contents with zeros via ctypes.

    - bytearray: from_buffer works directly (mutable).
    - bytes: uses the offset to ob_val found at module load.
      This is CPython-specific; on other implementations (PyPy, Jython) — no-op.
    """
    n = len(buf)
    if n == 0:
        return
    if isinstance(buf, bytearray):
        # bytearray is mutable — from_buffer works directly
        try:
            arr = (ctypes.c_char * n).from_buffer(buf)
            ctypes.memset(arr, 0, n)
        except (TypeError, ValueError):
            pass
    elif isinstance(buf, bytes) and _BYTES_DATA_OFFSET != -1:
        # bytes is immutable — write directly to the data address
        try:
            ctypes.memset(id(buf) + _BYTES_DATA_OFFSET, 0, n)
        except (TypeError, ValueError, OSError):
            pass
    # On non-CPython implementations — silently skip (safer than crashing)


# ---------------------------------------------------------------------------
# CSPRNG core: "extract-then-expand" without pool collapse
# ---------------------------------------------------------------------------
class _EntropyPool:
    """
    128-byte pool with forward secrecy.

    After each extract() call:
        new_pool  = SHA3-512( pool || counter || time_ns )
        new_pool2 = SHA3-512( pool || counter || b"\\x01" )
        pool = new_pool || new_pool2          # 128 bytes
        output = SHA3-512( new_pool XOR new_pool2 || request_counter )

    The chain guarantees:
      - knowing past output does not allow pool recovery (forward secrecy)
      - knowing the current pool does not allow recovering past outputs
    """

    _POOL_SIZE = 128

    def __init__(self, seed: bytes) -> None:
        assert len(seed) >= 64, "seed is too short"
        # Initialize pool via HKDF-Extract (SHA3-512, salt=os.urandom)
        salt = os.urandom(64)
        prk  = hmac.new(salt, seed, hashlib.sha3_512).digest()       # 64 bytes
        prk2 = hmac.new(salt, seed + b"\x01", hashlib.sha3_512).digest()
        self._pool: bytearray = bytearray(prk + prk2)                # 128 bytes
        self._counter: int = 0
        self._pid: int = os.getpid()

    def _check_fork(self) -> None:
        """If we are in a child process — re-seed immediately."""
        pid = os.getpid()
        if pid != self._pid:
            self._pid = pid
            fresh = os.urandom(64) + struct.pack(">Q", time.time_ns())
            self._mix(fresh)

    def _mix(self, extra: bytes) -> None:
        """Inject additional entropy without shrinking the pool."""
        h = hashlib.sha3_512(bytes(self._pool) + extra).digest()
        self._pool[:64]  = h
        # Second half — independent hash with a flag
        h2 = hashlib.sha3_512(bytes(self._pool[64:]) + extra + b"\xff").digest()
        self._pool[64:] = h2

    def extract(self, n: int) -> bytes:
        """Return n random bytes, updating the pool (thread-unsafe — call under lock)."""
        self._check_fork()
        result = bytearray()
        while len(result) < n:
            self._counter += 1
            cnt_bytes = struct.pack(">Q", self._counter)
            # expand: XOR of two pool halves + counter + time (jitter)
            jitter = struct.pack(">Q", time.monotonic_ns() if hasattr(time, "monotonic_ns") else time.time_ns())
            left  = bytes(self._pool[:64])
            right = bytes(self._pool[64:])
            xored = bytes(a ^ b for a, b in zip(left, right))
            output = hashlib.sha3_512(xored + cnt_bytes + jitter).digest()

            # update pool: forward secrecy — old pool is destroyed
            new_left  = hashlib.sha3_512(left  + cnt_bytes + b"\x00").digest()
            new_right = hashlib.sha3_512(right + cnt_bytes + b"\x01").digest()
            self._pool[:64]  = new_left
            self._pool[64:]  = new_right

            need = n - len(result)
            result.extend(output[:need])

        return bytes(result)

    def zeroize(self) -> None:
        """Zero the pool — call when done."""
        for i in range(len(self._pool)):
            self._pool[i] = 0


# ---------------------------------------------------------------------------
# Public STRG class
# ---------------------------------------------------------------------------
class STRG:
    """
    Parameters
    ----------
    fulcrum : int | str
        User-provided seed. Should be unique per session/user.
        More entropy is better (UUID, session token, etc.).
    pepper : str | None
        Static application-level secret. Strengthens the pool but does not
        replace a high-quality fulcrum.

    Recommended usage as a context manager:

        with STRG(fulcrum="...") as rng:
            secret = rng.token_hex(32)
        # pool is guaranteed to be zeroed here
    """

    def __init__(
        self,
        fulcrum: Union[int, str],
        pepper: Optional[str] = None,
        # algo kept as keyword-only for backwards compatibility,
        # but now deprecated — internally always uses SHA3-512
        **kwargs: object,
    ) -> None:
        if "algo" in kwargs:
            warnings.warn(
                "The 'algo' parameter is deprecated and ignored. "
                "STRG v3 always uses SHA3-512 + forward secrecy.",
                DeprecationWarning,
                stacklevel=2,
            )

        fulcrum_str = str(fulcrum)

        # Warning about low-entropy fulcrum
        if len(fulcrum_str) > 3 and len(set(fulcrum_str)) / len(fulcrum_str) < 0.15:
            warnings.warn(
                "fulcrum has low entropy: too many repeated characters. "
                "Use a UUID or session token.",
                UserWarning,
                stacklevel=2,
            )

        self._lock = threading.Lock()

        # Build initial seed: os.urandom × 2 + fulcrum + pepper + time
        pepper_b = pepper.encode("utf-8") if pepper else b""
        seed = b"".join([
            os.urandom(64),
            os.urandom(64),                                    # two independent calls
            fulcrum_str.encode("utf-8"),
            pepper_b,
            struct.pack(">QQ",
                time.time_ns(),
                int(time.monotonic() * 1_000_000_000),
            ),
        ])

        self._pool = _EntropyPool(seed)

        # Zero the seed immediately after initialization
        _zero(seed)
        _zero(pepper_b)

    # ------------------------------------------------------------------
    # Internal byte generator
    # ------------------------------------------------------------------

    def _raw(self, n: int) -> bytes:
        """n random bytes. Thread-safe, fork-safe."""
        if n < 1:
            raise ValueError("n must be >= 1")
        with self._lock:
            return self._pool.extract(n)

    def reseed(self, extra: Optional[bytes] = None) -> None:
        """
        Manually inject fresh entropy into the pool.
        Useful for long-running processes, after os.fork(), or
        when an additional source of randomness is available.
        """
        with self._lock:
            fresh = os.urandom(64) + struct.pack(">Q", time.time_ns())
            if extra:
                fresh += extra
            self._pool._mix(fresh)

    def zeroize(self) -> None:
        """
        Zero the internal entropy pool.
        Call when done working with sensitive data,
        or use STRG as a context manager (recommended).
        """
        with self._lock:
            self._pool.zeroize()

    def __enter__(self) -> "STRG":
        """Support `with STRG(...) as rng:`"""
        return self

    def __exit__(self, *_: object) -> None:
        """Guaranteed zeroize on exit from with block, including on exception."""
        self.zeroize()

    # ------------------------------------------------------------------
    # Base methods (analogous to secrets)
    # ------------------------------------------------------------------

    def token_bytes(self, n: int = 32) -> bytes:
        """n random bytes. Analogous to secrets.token_bytes()."""
        return self._raw(n)

    def token_hex(self, n: int = 32) -> str:
        """Hex string from n random bytes (length = 2*n). Analogous to secrets.token_hex()."""
        return self._raw(n).hex()

    def token_urlsafe(self, n: int = 32) -> str:
        """URL-safe base64 from n bytes. Analogous to secrets.token_urlsafe()."""
        import base64
        return base64.urlsafe_b64encode(self._raw(n)).rstrip(b"=").decode("ascii")

    # ------------------------------------------------------------------
    # Numbers
    # ------------------------------------------------------------------

    @staticmethod
    def bytes_for_bits(bits: int) -> int:
        """Minimum number of bytes needed to store the given number of bits."""
        return (bits + 7) // 8

    def randint(self, a: int, b: int) -> int:
        """
        Random integer in [a, b] inclusive.
        Bias-free rejection sampling: does not use simple % span.
        """
        if a > b:
            raise ValueError(f"a={a} must be <= b={b}")
        if a == b:
            return a
        span    = b - a + 1
        # Number of bytes: enough to represent span-1
        n_bytes = max(1, (span - 1).bit_length() + 7) // 8
        # Rejection threshold: largest multiple of span not exceeding 2^(n_bytes*8)
        max_val = 1 << (n_bytes * 8)
        limit   = max_val - (max_val % span)   # ≡ (max_val // span) * span, no overflow
        while True:
            val = int.from_bytes(self._raw(n_bytes), "big")
            if val < limit:
                return a + (val % span)

    def randbelow(self, n: int) -> int:
        """Random integer in [0, n)."""
        if n < 1:
            raise ValueError("n must be >= 1")
        return self.randint(0, n - 1)

    def randfloat(self, a: float = 0.0, b: float = 1.0) -> float:
        """
        Random float in [a, b) with uniform distribution.
        Uses 53-bit IEEE-754 mantissa — no precision loss.
        """
        if a >= b:
            raise ValueError(f"a={a} must be < b={b}")
        # 53 bits — double precision
        val = int.from_bytes(self._raw(7), "big") >> 3   # 53 significant bits
        fraction = val / (1 << 53)                        # [0.0, 1.0)
        result = a + fraction * (b - a)
        # Paranoia: float arithmetic may yield exactly b at extreme values
        if result >= b:
            result = b - 2**-53 * (b - a)
        return result

    # ------------------------------------------------------------------
    # Sequences
    # ------------------------------------------------------------------

    def choice(self, seq: Sequence[T]) -> T:
        """Random element from a sequence."""
        if not seq:
            raise IndexError("Sequence is empty")
        return seq[self.randint(0, len(seq) - 1)]

    def shuffle(self, seq: "list[T]") -> "list[T]":
        """
        Fisher-Yates shuffle. Returns a new list, original is unchanged.
        Every permutation is equally likely.
        """
        result = list(seq)
        for i in range(len(result) - 1, 0, -1):
            j = self.randint(0, i)
            result[i], result[j] = result[j], result[i]
        return result

    def sample(self, seq: Sequence[T], k: int) -> "list[T]":
        """k unique random elements from a sequence."""
        n = len(seq)
        if not (0 <= k <= n):
            raise ValueError(f"k={k} must be in [0, {n}]")
        if k == 0:
            return []
        # For small k use partial Fisher-Yates (O(k) memory)
        if k <= n // 2:
            pool = list(seq)
            result = []
            for i in range(k):
                j = self.randint(i, n - 1)
                pool[i], pool[j] = pool[j], pool[i]
                result.append(pool[i])
            return result
        return self.shuffle(list(seq))[:k]

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def password(
        self,
        length: int = 16,
        charset: str = _DEFAULT_PASSWORD_CHARSET,
        *,
        require_all_classes: bool = False,
    ) -> str:
        """
        Random password from charset characters.

        Parameters
        ----------
        require_all_classes : bool
            If True and charset == default — guarantees at least one character
            from each class (lowercase, uppercase, digit, special).
            Useful for sites with annoying password requirements.
        """
        if length < 1:
            raise ValueError("length must be >= 1")
        if not charset:
            raise ValueError("charset cannot be empty")

        # Deduplicate charset for fair distribution
        seen: "dict[str, None]" = {}
        for ch in charset:
            seen[ch] = None
        charset = "".join(seen)

        n        = len(charset)
        n_bytes  = max(1, (n - 1).bit_length() + 7) // 8
        max_val  = 1 << (n_bytes * 8)
        limit    = max_val - (max_val % n)

        def _gen(length: int) -> "list[str]":
            result: "list[str]" = []
            while len(result) < length:
                raw = self._raw(length * n_bytes * 2)
                for i in range(0, len(raw) - n_bytes + 1, n_bytes):
                    val = int.from_bytes(raw[i:i + n_bytes], "big")
                    if val < limit:
                        result.append(charset[val % n])
                    if len(result) == length:
                        break
            return result

        if require_all_classes and charset == _DEFAULT_PASSWORD_CHARSET and length >= 4:
            classes = [
                "abcdefghijklmnopqrstuvwxyz",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "0123456789",
                "!@#$%^&*-_=+",
            ]
            while True:
                chars = _gen(length)
                if all(any(c in cls for c in chars) for cls in classes):
                    return "".join(self.shuffle(chars))
        return "".join(_gen(length))

    def compare_digest(self, a: Union[str, bytes], b: Union[str, bytes]) -> bool:
        """Constant-time comparison — protection against timing attacks."""
        return hmac.compare_digest(a, b)

    def uuid4(self) -> str:
        """UUID version 4 (RFC 4122), cryptographically random."""
        b = bytearray(self._raw(16))
        b[6] = (b[6] & 0x0F) | 0x40    # version = 4
        b[8] = (b[8] & 0x3F) | 0x80    # variant = RFC 4122
        h = b.hex()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"

    def __repr__(self) -> str:
        return "STRG(algo='sha3_512+forward_secrecy', fulcrum=<hidden>)"

    def __del__(self) -> None:
        """Zero the pool on garbage collection."""
        try:
            self._pool.zeroize()
        except Exception:
            pass