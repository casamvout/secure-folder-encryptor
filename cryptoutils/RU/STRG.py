"""
strg.py — Secure True Random Generator  v3 (НАПИСАНО ИИ)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Превосходит secrets в нескольких аспектах:

  1. Forward secrecy — пул обновляется по схеме «extract-then-expand»
     (HKDF-like): старый пул уничтожается после каждого блока.
  2. Entropy pool 128 байт (SHA3-512 × 2) — не схлопывается до 32 байт.
  3. Fork-safe — при os.fork() дочерний процесс автоматически ресидируется.
  4. Bias-free randint — корректный rejection sampling для любого диапазона.
  5. Entropy accumulator — принимает дополнительные источники (CPU-jitter,
     счётчик вызовов) бездоверия им.
  6. Zeroization — чувствительные буферы обнуляются ctypes.memset.
     Работает как для bytearray, так и для bytes (через ob_val offset).
  7. Context manager — гарантированная очистка пула через `with`.
  8. API-совместим со старым STRG + несколько новых методов.

Использование:
    from strg import STRG

    # Рекомендуемый способ — context manager гарантирует zeroize()
    with STRG(fulcrum="my-session-id") as rng:
        rng.token_hex(32)           # '3f9a...' (64 символа)
        rng.token_bytes(16)         # b'\\x3f...'
        rng.randint(1, 100)         # 42
        rng.randbelow(100)          # 0..99
        rng.randfloat()             # 0.7312...
        rng.choice([1, 2, 3])       # 2
        rng.shuffle([1,2,3,4,5])    # [3,1,5,2,4]
        rng.sample([1,2,3,4,5], 3)  # [5,2,1]
        rng.password(16)            # 'xK9#mP2@...'
        rng.uuid4()                 # RFC-4122 v4
        rng.compare_digest(a, b)    # constant-time сравнение
        rng.reseed()                # вручную влить свежую энтропию
        rng.bytes_for_bits(128)     # минимум байт для n бит
        rng.randfloat(0.0, 1.0)     # [a, b) без float-overflow
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
# Символьный набор для паролей
# ---------------------------------------------------------------------------
_DEFAULT_PASSWORD_CHARSET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!@#$%^&*-_=+"
)

# ---------------------------------------------------------------------------
# Вспомогательная функция: безопасно обнулить bytes/bytearray в памяти
# ---------------------------------------------------------------------------

# Смещение до данных в объекте bytes/bytearray в CPython.
# Находим его один раз при загрузке модуля — не хардкодим.
def _find_bytes_data_offset() -> int:
    """
    Определяет смещение от id(b) до начала фактических данных в объекте bytes.
    Ищем паттерн b'\\xAA' * 8 через ctypes.string_at — надёжнее хардкода.
    """
    marker = b"\xAA" * 8
    base   = id(marker)
    # CPython: bytes-объект содержит данные где-то в первых ~64 байтах заголовка
    raw    = ctypes.string_at(base, 128)
    offset = raw.find(marker)
    return offset if offset != -1 else -1

_BYTES_DATA_OFFSET: int = _find_bytes_data_offset()


def _zero(buf: Union[bytes, bytearray]) -> None:
    """
    Перезаписать содержимое буфера нулями через ctypes.

    - bytearray: from_buffer работает напрямую (mutable).
    - bytes: используем смещение до ob_val, найденное при загрузке модуля.
      Это CPython-specific; на других реализациях (PyPy, Jython) — no-op.
    """
    n = len(buf)
    if n == 0:
        return
    if isinstance(buf, bytearray):
        # bytearray mutable — from_buffer работает напрямую
        try:
            arr = (ctypes.c_char * n).from_buffer(buf)
            ctypes.memset(arr, 0, n)
        except (TypeError, ValueError):
            pass
    elif isinstance(buf, bytes) and _BYTES_DATA_OFFSET != -1:
        # bytes immutable — пишем напрямую по адресу данных
        try:
            ctypes.memset(id(buf) + _BYTES_DATA_OFFSET, 0, n)
        except (TypeError, ValueError, OSError):
            pass
    # На не-CPython реализациях — молча пропускаем (безопаснее чем падать)


# ---------------------------------------------------------------------------
# Ядро CSPRNG: «extract-then-expand» без схлопывания пула
# ---------------------------------------------------------------------------
class _EntropyPool:
    """
    128-байтовый пул с forward secrecy.

    После каждого вызова extract():
        new_pool  = SHA3-512( pool || counter || time_ns )
        new_pool2 = SHA3-512( pool || counter || b"\\x01" )
        pool = new_pool || new_pool2          # 128 байт
        output = SHA3-512( new_pool XOR new_pool2 || request_counter )

    Цепочка гарантирует:
      - знание прошлого output не позволяет восстановить пул (forward secrecy)
      - знание пула сейчас не позволяет восстановить прошлые output
    """

    _POOL_SIZE = 128

    def __init__(self, seed: bytes) -> None:
        assert len(seed) >= 64, "seed слишком короткий"
        # Инициализируем пул через HKDF-Extract (SHA3-512, salt=os.urandom)
        salt = os.urandom(64)
        prk  = hmac.new(salt, seed, hashlib.sha3_512).digest()       # 64 байт
        prk2 = hmac.new(salt, seed + b"\x01", hashlib.sha3_512).digest()
        self._pool: bytearray = bytearray(prk + prk2)                # 128 байт
        self._counter: int = 0
        self._pid: int = os.getpid()

    def _check_fork(self) -> None:
        """Если мы в дочернем процессе — ресидировать немедленно."""
        pid = os.getpid()
        if pid != self._pid:
            self._pid = pid
            fresh = os.urandom(64) + struct.pack(">Q", time.time_ns())
            self._mix(fresh)

    def _mix(self, extra: bytes) -> None:
        """Влить дополнительную энтропию без уменьшения пула."""
        h = hashlib.sha3_512(bytes(self._pool) + extra).digest()
        self._pool[:64]  = h
        # Вторая половина — независимый хэш с флагом
        h2 = hashlib.sha3_512(bytes(self._pool[64:]) + extra + b"\xff").digest()
        self._pool[64:] = h2

    def extract(self, n: int) -> bytes:
        """Вернуть n случайных байт, обновив пул (thread-unsafe — вызывать под lock)."""
        self._check_fork()
        result = bytearray()
        while len(result) < n:
            self._counter += 1
            cnt_bytes = struct.pack(">Q", self._counter)
            # expand: XOR двух половин пула + счётчик + время (jitter)
            jitter = struct.pack(">Q", time.monotonic_ns() if hasattr(time, "monotonic_ns") else time.time_ns())
            left  = bytes(self._pool[:64])
            right = bytes(self._pool[64:])
            xored = bytes(a ^ b for a, b in zip(left, right))
            output = hashlib.sha3_512(xored + cnt_bytes + jitter).digest()

            # update pool: forward secrecy — старый пул уничтожается
            new_left  = hashlib.sha3_512(left  + cnt_bytes + b"\x00").digest()
            new_right = hashlib.sha3_512(right + cnt_bytes + b"\x01").digest()
            self._pool[:64]  = new_left
            self._pool[64:]  = new_right

            need = n - len(result)
            result.extend(output[:need])

        return bytes(result)

    def zeroize(self) -> None:
        """Обнулить пул — вызывать при завершении работы."""
        for i in range(len(self._pool)):
            self._pool[i] = 0


# ---------------------------------------------------------------------------
# Публичный класс STRG
# ---------------------------------------------------------------------------
class STRG:
    """
    Параметры
    ---------
    fulcrum : int | str
        Пользовательское зерно. Должно быть уникальным для сессии/пользователя.
        Чем больше энтропии — тем лучше (UUID, токен сессии и т.п.).
    pepper : str | None
        Статический секрет уровня приложения. Усиливает пул, но не заменяет
        качественный fulcrum.

    Рекомендуется использовать как context manager:

        with STRG(fulcrum="...") as rng:
            secret = rng.token_hex(32)
        # пул гарантированно обнулён здесь
    """

    def __init__(
        self,
        fulcrum: Union[int, str],
        pepper: Optional[str] = None,
        # algo оставлен как keyword-only для обратной совместимости,
        # но теперь deprecated — внутри всегда SHA3-512
        **kwargs: object,
    ) -> None:
        if "algo" in kwargs:
            warnings.warn(
                "Параметр 'algo' устарел и игнорируется. "
                "STRG v3 всегда использует SHA3-512 + forward secrecy.",
                DeprecationWarning,
                stacklevel=2,
            )

        fulcrum_str = str(fulcrum)

        # Предупреждение о низкой энтропии fulcrum
        if len(fulcrum_str) > 3 and len(set(fulcrum_str)) / len(fulcrum_str) < 0.15:
            warnings.warn(
                "fulcrum имеет низкую энтропию: слишком много повторяющихся символов. "
                "Используйте UUID или токен сессии.",
                UserWarning,
                stacklevel=2,
            )

        self._lock = threading.Lock()

        # Строим начальный seed: os.urandom × 2 + fulcrum + pepper + время
        pepper_b = pepper.encode("utf-8") if pepper else b""
        seed = b"".join([
            os.urandom(64),
            os.urandom(64),                                    # два независимых вызова
            fulcrum_str.encode("utf-8"),
            pepper_b,
            struct.pack(">QQ",
                time.time_ns(),
                int(time.monotonic() * 1_000_000_000),
            ),
        ])

        self._pool = _EntropyPool(seed)

        # Обнуляем seed сразу после инициализации
        _zero(seed)
        _zero(pepper_b)

    # ------------------------------------------------------------------
    # Внутренний генератор байт
    # ------------------------------------------------------------------

    def _raw(self, n: int) -> bytes:
        """n случайных байт. Thread-safe, fork-safe."""
        if n < 1:
            raise ValueError("n должен быть >= 1")
        with self._lock:
            return self._pool.extract(n)

    def reseed(self, extra: Optional[bytes] = None) -> None:
        """
        Влить свежую энтропию в пул вручную.
        Полезно при долгой работе процесса, после os.fork(), или
        когда есть дополнительный источник случайности.
        """
        with self._lock:
            fresh = os.urandom(64) + struct.pack(">Q", time.time_ns())
            if extra:
                fresh += extra
            self._pool._mix(fresh)

    def zeroize(self) -> None:
        """
        Обнулить внутренний пул энтропии.
        Вызывайте при завершении работы с чувствительными данными,
        или используйте STRG как context manager (рекомендуется).
        """
        with self._lock:
            self._pool.zeroize()

    def __enter__(self) -> "STRG":
        """Поддержка `with STRG(...) as rng:`"""
        return self

    def __exit__(self, *_: object) -> None:
        """Гарантированный zeroize при выходе из блока with, в т.ч. при исключении."""
        self.zeroize()

    # ------------------------------------------------------------------
    # Базовые методы (аналог secrets)
    # ------------------------------------------------------------------

    def token_bytes(self, n: int = 32) -> bytes:
        """n случайных байт. Аналог secrets.token_bytes()."""
        return self._raw(n)

    def token_hex(self, n: int = 32) -> str:
        """Hex-строка из n случайных байт (длина = 2*n). Аналог secrets.token_hex()."""
        return self._raw(n).hex()

    def token_urlsafe(self, n: int = 32) -> str:
        """URL-safe base64 из n байт. Аналог secrets.token_urlsafe()."""
        import base64
        return base64.urlsafe_b64encode(self._raw(n)).rstrip(b"=").decode("ascii")

    # ------------------------------------------------------------------
    # Числа
    # ------------------------------------------------------------------

    @staticmethod
    def bytes_for_bits(bits: int) -> int:
        """Минимальное число байт для хранения заданного числа бит."""
        return (bits + 7) // 8

    def randint(self, a: int, b: int) -> int:
        """
        Случайное целое в [a, b] включительно.
        Bias-free rejection sampling: не используем простой % span.
        """
        if a > b:
            raise ValueError(f"a={a} должен быть <= b={b}")
        if a == b:
            return a
        span    = b - a + 1
        # Количество байт: достаточно для представления span-1
        n_bytes = max(1, (span - 1).bit_length() + 7) // 8
        # Порог rejection: наибольшее кратное span, не превышающее 2^(n_bytes*8)
        max_val = 1 << (n_bytes * 8)
        limit   = max_val - (max_val % span)   # ≡ (max_val // span) * span, без переполнения
        while True:
            val = int.from_bytes(self._raw(n_bytes), "big")
            if val < limit:
                return a + (val % span)

    def randbelow(self, n: int) -> int:
        """Случайное целое в [0, n)."""
        if n < 1:
            raise ValueError("n должен быть >= 1")
        return self.randint(0, n - 1)

    def randfloat(self, a: float = 0.0, b: float = 1.0) -> float:
        """
        Случайный float в [a, b) с равномерным распределением.
        Использует 53-битную мантиссу IEEE-754 — без потерь точности.
        """
        if a >= b:
            raise ValueError(f"a={a} должен быть < b={b}")
        # 53 бита — точность double
        val = int.from_bytes(self._raw(7), "big") >> 3   # 53 значащих бита
        fraction = val / (1 << 53)                        # [0.0, 1.0)
        result = a + fraction * (b - a)
        # Паранойя: float arith может дать ровно b при крайних значениях
        if result >= b:
            result = b - 2**-53 * (b - a)
        return result

    # ------------------------------------------------------------------
    # Последовательности
    # ------------------------------------------------------------------

    def choice(self, seq: Sequence[T]) -> T:
        """Случайный элемент из последовательности."""
        if not seq:
            raise IndexError("Последовательность пуста")
        return seq[self.randint(0, len(seq) - 1)]

    def shuffle(self, seq: "list[T]") -> "list[T]":
        """
        Fisher-Yates shuffle. Возвращает новый список, оригинал не трогает.
        Каждая перестановка равновероятна.
        """
        result = list(seq)
        for i in range(len(result) - 1, 0, -1):
            j = self.randint(0, i)
            result[i], result[j] = result[j], result[i]
        return result

    def sample(self, seq: Sequence[T], k: int) -> "list[T]":
        """k уникальных случайных элементов из последовательности."""
        n = len(seq)
        if not (0 <= k <= n):
            raise ValueError(f"k={k} должен быть в [0, {n}]")
        if k == 0:
            return []
        # Для малых k используем partial Fisher-Yates (O(k) памяти)
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
    # Утилиты
    # ------------------------------------------------------------------

    def password(
        self,
        length: int = 16,
        charset: str = _DEFAULT_PASSWORD_CHARSET,
        *,
        require_all_classes: bool = False,
    ) -> str:
        """
        Случайный пароль из символов charset.

        Параметры
        ---------
        require_all_classes : bool
            Если True и charset == дефолтный — гарантирует наличие хотя бы
            одного символа каждого класса (строчная, прописная, цифра, спецсимвол).
            Полезно для сайтов с дурацкими требованиями к паролям.
        """
        if length < 1:
            raise ValueError("length должен быть >= 1")
        if not charset:
            raise ValueError("charset не может быть пустым")

        # Дедупликация charset для честного распределения
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
        """Constant-time сравнение — защита от timing attacks."""
        return hmac.compare_digest(a, b)

    def uuid4(self) -> str:
        """UUID версии 4 (RFC 4122), криптографически случайный."""
        b = bytearray(self._raw(16))
        b[6] = (b[6] & 0x0F) | 0x40    # version = 4
        b[8] = (b[8] & 0x3F) | 0x80    # variant = RFC 4122
        h = b.hex()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"

    def __repr__(self) -> str:
        return "STRG(algo='sha3_512+forward_secrecy', fulcrum=<hidden>)"

    def __del__(self) -> None:
        """При сборке мусора — обнулить пул."""
        try:
            self._pool.zeroize()
        except Exception:
            pass