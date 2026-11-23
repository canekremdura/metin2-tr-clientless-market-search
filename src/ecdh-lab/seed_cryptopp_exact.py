# -*- coding: utf-8 -*-
"""SEED — Crypto++ (seed.cpp) birebir portu.

Tablolar `cryptopp_src/seed.cpp`'den ayristirilir (s_s0, s_s1, s_kc).
Blok 16 bayt, anahtar 16 bayt, tur 16.
Blok I/O BIG_ENDIAN (BlockGetAndPut<word32, BigEndian>).

DOGRULAMA: RFC 4269 vektoru
    anahtar = 00000000...  (16x00)
    blok    = 000102030405060708090a0b0c0d0e0f
    beklenen= 5EBAC6E0054E166819AFF1CC6D1D3401
"""
import os
import re

_M = 0xFFFFFFFF


def _rotl32(x, n):
    n %= 32
    return ((x << n) | (x >> (32 - n))) & _M if n else x


def _rotr32(x, n):
    n %= 32
    return ((x >> n) | (x << (32 - n))) & _M if n else x


_M64 = 0xFFFFFFFFFFFFFFFF


def _rotl64(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _M64 if n else x


def _rotr64(x, n):
    n %= 64
    return ((x >> n) | (x << (64 - n))) & _M64 if n else x


def _load_tables():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cryptopp_src", "seed.cpp")
    src = open(path, encoding="utf-8", errors="replace").read()

    def grab(name):
        m = re.search(name + r"\[\d+\]\s*=\s*\{(.*?)\};", src, re.S)
        nums = re.findall(r"0x([0-9A-Fa-f]+)", m.group(1))
        return [int(x, 16) for x in nums]

    s0 = grab(r"const byte s_s0")
    s1 = grab(r"static const byte s_s1")
    kc = grab(r"const word32 s_kc")
    assert len(s0) == 256 and len(s1) == 256, (len(s0), len(s1))
    assert len(kc) == 16, len(kc)
    return s0, s1, kc


_s0, _s1, _kc = _load_tables()

_M8 = 0xFF


def _byte(x, i):
    return (x >> (8 * i)) & _M8


def _G(x):
    """G(x) = SS0(byte0) ^ SS1(byte1) ^ SS2(byte2) ^ SS3(byte3)."""
    v0 = ((_s0[_byte(x, 0)] * 0x01010101) & 0x3FCFF3FC)
    v1 = ((_s1[_byte(x, 1)] * 0x01010101) & 0xFC3FCFF3)
    v2 = ((_s0[_byte(x, 2)] * 0x01010101) & 0xF3FC3FCF)
    v3 = ((_s1[_byte(x, 3)] * 0x01010101) & 0xCFF3FC3F)
    return (v0 ^ v1 ^ v2 ^ v3) & _M


class SEEDKey:
    __slots__ = ("k",)

    def __init__(self, user_key: bytes, forward: bool = True):
        if len(user_key) != 16:
            raise ValueError("SEED anahtari 16 bayt olmali (%d)" % len(user_key))
        key01 = int.from_bytes(user_key[0:8], "big")
        key23 = int.from_bytes(user_key[8:16], "big")

        k = [0] * 32
        idx = 0
        inc = 2
        if not forward:
            idx = 30
            inc = -2

        for i in range(16):
            hi01 = (key01 >> 32) & _M
            hi23 = (key23 >> 32) & _M
            t0 = (hi01 + hi23 - _kc[i]) & _M
            t1 = ((key01 & _M) - (key23 & _M) + _kc[i]) & _M
            k[idx] = _G(t0)
            k[idx + 1] = _G(t1)
            idx += inc
            if i & 1:
                key23 = _rotl64(key23, 8)
            else:
                key01 = _rotr64(key01, 8)
        self.k = k


def encrypt_block(block16: bytes, kp: SEEDKey) -> bytes:
    a0, a1, b0, b1 = (int.from_bytes(block16[i:i + 4], "big") for i in (0, 4, 8, 12))
    k = kp.k
    for i in range(0, 16, 2):
        t0 = b0 ^ k[2 * i + 0]
        t1 = b1 ^ k[2 * i + 1] ^ t0
        t1 = _G(t1); t0 = (t0 + t1) & _M; t0 = _G(t0)
        t1 = (t1 + t0) & _M; t1 = _G(t1)
        a0 ^= (t0 + t1) & _M
        a1 ^= t1

        t0 = a0 ^ k[2 * i + 2]
        t1 = a1 ^ k[2 * i + 3] ^ t0
        t1 = _G(t1); t0 = (t0 + t1) & _M; t0 = _G(t0)
        t1 = (t1 + t0) & _M; t1 = _G(t1)
        b0 ^= (t0 + t1) & _M
        b1 ^= t1
    return b"".join(x.to_bytes(4, "big") for x in (b0, b1, a0, a1))


def decrypt_block(block16: bytes, kp: SEEDKey) -> bytes:
    """Ters yon: Crypto++ Dec ayni turu ters anahtar programiyla kullanir."""
    raise NotImplementedError(
        "SEED decrypt: Crypto++ Dec, UncheckedSetKey'de forward=False ile ters "
        "program kurar. set_key(key, forward=False) + encrypt_block kullanin.")


def set_key(user_key: bytes, forward: bool = True) -> SEEDKey:
    return SEEDKey(user_key, forward)


def crypt_block(block16: bytes, user_key: bytes, decrypt: bool = False) -> bytes:
    """Tek blok, yonu secilebilir (Crypto++ Enc/Dec esdegeri)."""
    return encrypt_block(block16, SEEDKey(user_key, forward=not decrypt))


def _load_vectors():
    """cryptopp_src/test_seed.txt icindeki TUM vektorler (RFC 4269)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "cryptopp_src", "test_seed.txt")
    txt = open(path, encoding="utf-8", errors="replace").read()
    out = []
    for m in re.finditer(
            r"Key:\s+([0-9A-Fa-f ]+)\s*\n\s*Plaintext:\s+([0-9A-Fa-f ]+)\s*\n"
            r"\s*Ciphertext:\s+([0-9A-Fa-f ]+)", txt):
        out.append(tuple(bytes.fromhex(g.replace(" ", "")) for g in m.groups()))
    return out


def self_test(verbose: bool = True) -> bool:
    vec = _load_vectors()
    ok = True
    good_n = 0
    for k, p, c in vec:
        got = crypt_block(p, k)
        if got == c:
            good_n += 1
        elif verbose:
            print("  FARK k=%s\n   bekl=%s\n   alin=%s"
                  % (k.hex().upper(), c.hex().upper(), got.hex().upper()))
    good = good_n == len(vec) and bool(vec)
    ok &= good
    if verbose:
        print("[%s] SEED RFC 4269: %d/%d" % ("OK " if good else "FAIL", good_n, len(vec)))

    # tur geri-donusumu (forward/ters program)
    k = bytes(range(16))
    blk = bytes(range(16))
    ct = crypt_block(blk, k)
    back = crypt_block(ct, k, decrypt=True)
    good = back == blk
    ok &= good
    if verbose:
        print("[%s] SEED tur geri-donusumu" % ("OK " if good else "FAIL"))
    return bool(ok)


if __name__ == "__main__":
    import sys
    sys.exit(0 if self_test() else 1)
