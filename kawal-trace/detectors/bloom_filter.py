"""Bloom filter for the malware-hash fast path.

A Bloom filter never gives a false negative: if `hash in filter` is False the hash
is definitely not in the signature set. A positive answer may be a false positive
and must be confirmed against SQLite (see signature_matcher). The serialized form
carries a checksum and the number of items so a stale or damaged file is detected
and rebuilt instead of being trusted (a stale filter would create false negatives).
"""
from __future__ import annotations

import hashlib
import math
import os
import struct
import tempfile
from pathlib import Path

_MAGIC = b"KTBF1\x00"
_HEADER = struct.Struct(">6sIIQ32s")  # magic, m_bits, k, count, sha256(bit array)
MAX_BITS = 8 * 256 * 1024 * 1024  # 256 MiB ceiling


class BloomFilterError(ValueError):
    pass


class BloomFilter:
    def __init__(self, capacity: int = 100_000, error_rate: float = 0.001, *,
                 m_bits: int | None = None, k: int | None = None) -> None:
        if m_bits is None or k is None:
            if capacity < 1:
                raise BloomFilterError("capacity harus >= 1")
            if not 0.0 < error_rate < 1.0:
                raise BloomFilterError("error_rate harus di antara 0 dan 1")
            m_bits = max(64, int(math.ceil(-capacity * math.log(error_rate) / (math.log(2) ** 2))))
            k = max(1, int(round(m_bits / capacity * math.log(2))))
        if not 64 <= m_bits <= MAX_BITS or not 1 <= k <= 32:
            raise BloomFilterError("Parameter Bloom filter di luar batas aman")
        self.m_bits = int(m_bits)
        self.k = int(k)
        self.count = 0
        self._bits = bytearray((self.m_bits + 7) // 8)

    def _positions(self, item: str):
        digest = hashlib.blake2b(item.encode("utf-8"), digest_size=16).digest()
        h1 = int.from_bytes(digest[:8], "big")
        h2 = int.from_bytes(digest[8:], "big") | 1  # odd step -> good double hashing
        for i in range(self.k):
            yield (h1 + i * h2) % self.m_bits

    def add(self, item: str) -> None:
        for pos in self._positions(item):
            self._bits[pos >> 3] |= 1 << (pos & 7)
        self.count += 1

    def __contains__(self, item: str) -> bool:
        return all(self._bits[pos >> 3] & (1 << (pos & 7)) for pos in self._positions(item))

    def estimated_false_positive_rate(self) -> float:
        if self.count == 0:
            return 0.0
        return (1.0 - math.exp(-self.k * self.count / self.m_bits)) ** self.k

    @property
    def size_bytes(self) -> int:
        return len(self._bits)

    # ---- persistence -------------------------------------------------------------
    def to_bytes(self) -> bytes:
        digest = hashlib.sha256(bytes(self._bits)).digest()
        return _HEADER.pack(_MAGIC, self.m_bits, self.k, self.count, digest) + bytes(self._bits)

    @classmethod
    def from_bytes(cls, blob: bytes) -> "BloomFilter":
        if len(blob) < _HEADER.size:
            raise BloomFilterError("File Bloom filter terlalu pendek.")
        magic, m_bits, k, count, digest = _HEADER.unpack(blob[:_HEADER.size])
        if magic != _MAGIC:
            raise BloomFilterError("Format Bloom filter tidak dikenal.")
        bits = blob[_HEADER.size:]
        if len(bits) != (m_bits + 7) // 8:
            raise BloomFilterError("Ukuran Bloom filter tidak konsisten.")
        if hashlib.sha256(bits).digest() != digest:
            raise BloomFilterError("Checksum Bloom filter tidak cocok (file rusak/diubah).")
        instance = cls(m_bits=m_bits, k=k)
        instance._bits = bytearray(bits)
        instance.count = count
        return instance

    def save(self, path: str | os.PathLike[str]) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".bloom-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(self.to_bytes())
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, target)  # atomic: never leave a half-written filter
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "BloomFilter":
        try:
            return cls.from_bytes(Path(path).read_bytes())
        except OSError as exc:
            raise BloomFilterError(f"Bloom filter tidak dapat dibaca ({type(exc).__name__}).") from exc
