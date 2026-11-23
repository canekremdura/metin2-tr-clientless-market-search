# -*- coding: utf-8 -*-
"""MARS - Crypto++ birebir portu (mars.cpp + marss.cpp).
Dogrulama: Crypto++ TestVectors/mars.txt KAT vektorleri.
Blok: 16 bayt, anahtar: 16-40 bayt. Blok I/O LITTLE_ENDIAN (BlockGetAndPut<word32, LittleEndian>)."""
import re
import struct
from pathlib import Path

_M = 0xFFFFFFFF


def _rotl(x, n):
    n %= 32
    return ((x << n) | (x >> (32 - n))) & _M if n else x


def _rotr(x, n):
    n %= 32
    return ((x >> n) | (x << (32 - n))) & _M if n else x


def _load_sbox():
    src = (Path(__file__).resolve().parent/'cryptopp_src/marss.cpp').read_text()
    nums = re.findall(r'0x[0-9A-Fa-f]{8}', src)
    assert len(nums) == 512, len(nums)
    return [int(x, 16) for x in nums]


Sbox = _load_sbox()


def unchecked_set_key(user_key):
    """MARS::Base::UncheckedSetKey -> 40 kelime m_k[]."""
    length = len(user_key)
    # GetUserKey(LITTLE_ENDIAN_ORDER, T, 15, userKey, length)
    T = [0] * 15
    nw = length // 4
    for i in range(nw):
        T[i] = struct.unpack_from('<I', user_key, 4 * i)[0]
    # T[length/4] = length/4
    if nw < 15:
        T[nw] = nw
    k = [0] * 40
    for j in range(4):
        # dogrusal donusum
        for i in range(15):
            T[i] = (T[i] ^ _rotl(T[(i + 8) % 15] ^ T[(i + 13) % 15], 3) ^ (4 * i + j)) & _M
        # 4 tur karistirma
        for _ in range(4):
            for i in range(15):
                T[i] = _rotl((T[i] + Sbox[T[(i + 14) % 15] % 512]) & _M, 9)
        # sonraki 10 anahtar kelimesi
        for i in range(10):
            k[10 * j + i] = T[(4 * i) % 15]
    # carpim anahtar kelimesi duzeltmesi
    for i in range(5, 37, 2):
        w = k[i] | 3
        m = (~w ^ (w << 1)) & (~w ^ (w >> 1)) & 0x7FFFFFFE & _M
        m &= (m >> 1) & _M
        m &= (m >> 2) & _M
        m &= (m >> 4) & _M
        m |= (m << 1) & _M
        m |= (m << 2) & _M
        m |= (m << 4) & _M
        m &= 0x7FFFFFFC
        w ^= _rotl(Sbox[265 + (k[i] & 3)], k[i - 1]) & m
        k[i] = w & _M
    return k


def _S(a):
    return Sbox[a & 0x1FF]


def _S0(a):
    return Sbox[a & 0xFF]


def _S1(a):
    return Sbox[(a & 0xFF) + 256]


def encrypt_block(block16, k):
    """MARS::Enc::ProcessAndXorBlock (xorBlock yok)."""
    a, b, c, d = struct.unpack('<4I', block16)
    a = (a + k[0]) & _M
    b = (b + k[1]) & _M
    c = (c + k[2]) & _M
    d = (d + k[3]) & _M
    # ileri karistirma (8 tur)
    for i in range(8):
        b = ((b ^ _S0(a)) + _S1(a >> 8)) & _M
        c = (c + _S0(a >> 16)) & _M
        a = _rotr(a, 24)
        d ^= _S1(a)
        if i % 4 == 0:
            a = (a + d) & _M
        if i % 4 == 1:
            a = (a + b) & _M
        t = a; a = b; b = c; c = d; d = t
    # cekirdek (16 tur)
    for i in range(16):
        t = _rotl(a, 13)
        r = _rotl((t * k[2 * i + 5]) & _M, 10)
        m = (a + k[2 * i + 4]) & _M
        l = _rotl((_S(m) ^ _rotr(r, 5) ^ r) & _M, r)
        c = (c + _rotl(m, _rotr(r, 5))) & _M
        if i < 8:
            b = (b + l) & _M
            d ^= r
        else:
            d = (d + l) & _M
            b ^= r
        a = b; b = c; c = d; d = t
    # geri karistirma (8 tur)
    for i in range(8):
        if i % 4 == 2:
            a = (a - d) & _M
        if i % 4 == 3:
            a = (a - b) & _M
        b ^= _S1(a)
        c = (c - _S0(a >> 24)) & _M
        t = _rotl(a, 24)
        d = ((d - _S1(a >> 16)) & _M) ^ _S0(t)
        a = b; b = c; c = d; d = t
    a = (a - k[36]) & _M
    b = (b - k[37]) & _M
    c = (c - k[38]) & _M
    d = (d - k[39]) & _M
    return struct.pack('<4I', a, b, c, d)


def decrypt_block(block16, k):
    """MARS::Dec::ProcessAndXorBlock."""
    d, c, b, a = struct.unpack('<4I', block16)
    d = (d + k[36]) & _M
    c = (c + k[37]) & _M
    b = (b + k[38]) & _M
    a = (a + k[39]) & _M
    for i in range(8):
        b = ((b ^ _S0(a)) + _S1(a >> 8)) & _M
        c = (c + _S0(a >> 16)) & _M
        a = _rotr(a, 24)
        d ^= _S1(a)
        if i % 4 == 0:
            a = (a + d) & _M
        if i % 4 == 1:
            a = (a + b) & _M
        t = a; a = b; b = c; c = d; d = t
    for i in range(16):
        t = _rotr(a, 13)
        r = _rotl((a * k[35 - 2 * i]) & _M, 10)
        m = (t + k[34 - 2 * i]) & _M
        l = _rotl((_S(m) ^ _rotr(r, 5) ^ r) & _M, r)
        c = (c - _rotl(m, _rotr(r, 5))) & _M
        if i < 8:
            b = (b - l) & _M
            d ^= r
        else:
            d = (d - l) & _M
            b ^= r
        a = b; b = c; c = d; d = t
    for i in range(8):
        if i % 4 == 2:
            a = (a - d) & _M
        if i % 4 == 3:
            a = (a - b) & _M
        b ^= _S1(a)
        c = (c - _S0(a >> 24)) & _M
        t = _rotl(a, 24)
        d = ((d - _S1(a >> 16)) & _M) ^ _S0(t)
        a = b; b = c; c = d; d = t
    d = (d - k[0]) & _M
    c = (c - k[1]) & _M
    b = (b - k[2]) & _M
    a = (a - k[3]) & _M
    return struct.pack('<4I', d, c, b, a)


def self_test():
    """Crypto++ TestVectors/mars.txt KAT vektorleri."""
    import os
    path = Path(__file__).resolve().parent/'cryptopp_src/mars_test.txt'
    tests = []
    key = pt = ct = None
    for line in open(path):
        line = line.strip()
        if line.startswith('Key:'):
            key = bytes.fromhex(line[4:].strip())
        elif line.startswith('Plaintext:'):
            pt = bytes.fromhex(line[10:].strip())
        elif line.startswith('Ciphertext:'):
            ct = bytes.fromhex(line[11:].strip())
        elif line == 'Test: Encrypt' and key and pt and ct and len(pt) == 16:
            tests.append((key, pt, ct))
            key = pt = ct = None
    print('KAT test sayisi: %d' % len(tests))
    ok = 0
    for i, (key, pt, ct) in enumerate(tests):
        k = unchecked_set_key(key)
        e = encrypt_block(pt, k)
        if e == ct:
            ok += 1
        else:
            print('  HATA #%d: key=%s pt=%s beklenen=%s hesaplanan=%s' % (i, key.hex(), pt.hex(), ct.hex(), e.hex()))
    print('Encrypt KAT: %d/%d' % (ok, len(tests)))
    # geri donus testi
    rd = 0
    for key, pt, ct in tests[:5]:
        k = unchecked_set_key(key)
        if decrypt_block(ct, k) == pt:
            rd += 1
    print('Decrypt geri donus: %d/5' % rd)
    return ok == len(tests)


if __name__ == '__main__':
    self_test()
