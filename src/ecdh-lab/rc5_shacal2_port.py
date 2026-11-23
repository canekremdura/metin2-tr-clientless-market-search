# -*- coding: utf-8 -*-
"""RC5 + SHACAL2 - Crypto++ birebir portlari.
RC5: RFC 2040 vektorleriyle (R=8/12/16) dogrulanir; oyun varsayani R=16.
SHACAL2: Crypto++ TestVectors/shacal2.txt (NESSIE) vektorleriyle dogrulanir.
"""
import struct

_M = 0xFFFFFFFF


def _rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & _M if n else x


def _rotr(x, n):
    n &= 31
    return ((x >> n) | (x << (32 - n))) & _M if n else x


# ================================================================ RC5
def rc5_set_key(key: bytes, rounds: int = 16):
    """Crypto++ RC5::Base::UncheckedSetKey (varsayilan R=16)."""
    U = 4
    keylen = len(key)
    c = max((keylen + U - 1) // U, 1)
    L = [0] * c
    for i in range(keylen):
        L[i // 4] |= key[i] << (8 * (i % 4))  # LITTLE_ENDIAN
    s_len = 2 * (rounds + 1)
    S = [0] * s_len
    S[0] = 0xB7E15163
    for j in range(1, s_len):
        S[j] = (S[j - 1] + 0x9E3779B9) & _M
    a = b = 0
    n = 3 * max(s_len, c)
    for h in range(n):
        a = S[h % s_len] = _rotl((S[h % s_len] + a + b) & _M, 3)
        b = L[h % c] = _rotl((L[h % c] + a + b) & _M, (a + b))
    return S, rounds


def rc5_encrypt_block(block8: bytes, S, r) -> bytes:
    a, b = struct.unpack('<2I', block8)
    a = (a + S[0]) & _M
    b = (b + S[1]) & _M
    for i in range(r):
        a = (_rotl(a ^ b, b) + S[2 + 2 * i]) & _M
        b = (_rotl(a ^ b, a) + S[3 + 2 * i]) & _M
    return struct.pack('<2I', a, b)


def rc5_decrypt_block(block8: bytes, S, r) -> bytes:
    a, b = struct.unpack('<2I', block8)
    for i in range(r - 1, -1, -1):
        b = _rotr((b - S[3 + 2 * i]) & _M, a) ^ a
        a = _rotr((a - S[2 + 2 * i]) & _M, b) ^ b
    b = (b - S[1]) & _M
    a = (a - S[0]) & _M
    return struct.pack('<2I', a, b)


# ================================================================ SHACAL2
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def _s0(x):
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _s1(x):
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _ss0(x):
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)


def _ss1(x):
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


def shacal2_set_key(key: bytes):
    """Crypto++ SHACAL2::Base::UncheckedSetKey (64 kelime program)."""
    rk = [0] * 64
    # GetUserKey(BIG_ENDIAN_ORDER, rk, 64, key, keylen)
    for i in range(len(key)):
        rk[i // 4] |= key[i] << (24 - 8 * (i % 4))
    for i in range(48):
        rk[i + 16] = (rk[i] + _ss0(rk[i + 1]) + rk[i + 9] + _ss1(rk[i + 14])) & _M
        rk[i] = (rk[i] + _K[i]) & _M
    for i in range(48, 64):
        rk[i] = (rk[i] + _K[i]) & _M
    return rk


def shacal2_encrypt_block(block32: bytes, rk) -> bytes:
    a, b, c, d, e, f, g, h = struct.unpack('>8I', block32)

    def R(a, b, c, d, e, f, g, h, k):
        h = (h + _s1(e) + ((e & f) ^ (~e & g)) + k) & _M
        d = (d + h) & _M
        h = (h + _s0(a) + ((a & b) | (c & (a | b)))) & _M
        return a, b, c, d, e, f, g, h

    for j in range(0, 64, 8):
        a, b, c, d, e, f, g, h = R(a, b, c, d, e, f, g, h, rk[j])
        h, a, b, c, d, e, f, g = R(h, a, b, c, d, e, f, g, rk[j + 1])
        g, h, a, b, c, d, e, f = R(g, h, a, b, c, d, e, f, rk[j + 2])
        f, g, h, a, b, c, d, e = R(f, g, h, a, b, c, d, e, rk[j + 3])
        e, f, g, h, a, b, c, d = R(e, f, g, h, a, b, c, d, rk[j + 4])
        d, e, f, g, h, a, b, c = R(d, e, f, g, h, a, b, c, rk[j + 5])
        c, d, e, f, g, h, a, b = R(c, d, e, f, g, h, a, b, rk[j + 6])
        b, c, d, e, f, g, h, a = R(b, c, d, e, f, g, h, a, rk[j + 7])
    return struct.pack('>8I', a, b, c, d, e, f, g, h)


# ================================================================ TESTLER
def self_test():
    ok = True
    # ---- RC5: RFC 2040 (CBC vektorleri: ct = E(pt XOR IV))
    # (rounds, key, IV, pt, ct)
    vectors = [
        (8, '00', '0000000000000000', '0000000000000000', 'dcfe098577eca5ff'),
        (8, '00', '0102030405060708', '1020304050607080', '9646fb77638f9ca8'),
        (12, '00', '0102030405060708', '1020304050607080', 'b2b3209db6594da4'),
        (16, '00', '0102030405060708', '1020304050607080', '545f7f32a5fc3836'),
        (8, '01020304', '0000000000000000', 'ffffffffffffffff', '8285e7c1b5bc7402'),
        (12, '01020304', '0000000000000000', 'ffffffffffffffff', 'fc586f92f7080934'),
        (16, '01020304', '0000000000000000', 'ffffffffffffffff', 'cf270ef9717ff7c4'),
        (8, '0102030405060708', '0102030405060708', '1020304050607080', '5c4c041e0f217ac3'),
        (12, '0102030405060708', '0102030405060708', '1020304050607080', '921f12485373b4f7'),
        (16, '0102030405060708', '0102030405060708', '1020304050607080', '5ba0ca6bbe7f5fad'),
        (16, '01020304050607081020304050607080', '0102030405060708', '1020304050607080', 'dad6bda9dfe8f7e8'),
        (12, '01020304050607081020304050607080', '0102030405060708', '1020304050607080', '294ddb46b3278d60'),
        (8, '01020304050607081020304050607080', '0102030405060708', '1020304050607080', 'c533771cd0110e63'),
    ]
    print('== RC5 (RFC 2040, CBC=ECB(pt XOR IV)) ==')
    for r, keyh, ivh, pth, cth in vectors:
        key = bytes.fromhex(keyh)
        iv = bytes.fromhex(ivh)
        pt = bytes.fromhex(pth)
        ct = bytes.fromhex(cth)
        ptx = bytes(a ^ b for a, b in zip(pt, iv))
        S, rr = rc5_set_key(key, r)
        e = rc5_encrypt_block(ptx, S, rr)
        d = rc5_decrypt_block(e, S, rr)
        rt = d == ptx
        good = e == ct and rt
        if not good:
            ok = False
            print('  HATA R=%d key=%s -> %s (beklenen %s, rt=%s)' % (r, keyh, e.hex(), cth, rt))
        else:
            print('  OK  R=%-2d key=%-34s -> %s' % (r, keyh[:34], e.hex()))
    # ---- SHACAL2: NESSIE set 1 vektor 0-2 + set 3 son
    print('== SHACAL2 (NESSIE) ==')
    sh_vectors = [
        (bytes.fromhex('80' + '00' * 63), bytes.fromhex('00' * 32), '361ab6322fa9e7a7bb23818d839e01bddafdf47305426edd297aedb9f6202bae'),
        (bytes.fromhex('40' + '00' * 63), bytes.fromhex('00' * 32), 'f3baf53e5301e08813f8be6f651bb19e9722151ff15063ba42a6fef7cf3bf3d7'),
        (bytes.fromhex('ff' * 64), bytes.fromhex('ff' * 32), '0598127baf11706f77402000d730c54a0b84c868a98c6ca4d7f3c0fa06a78b7a'),
    ]
    for key, pt, ct in sh_vectors:
        rk = shacal2_set_key(key)
        e = shacal2_encrypt_block(pt, rk)
        good = e.hex() == ct
        if not good:
            ok = False
            print('  HATA key=%s... -> %s (beklenen %s)' % (key.hex()[:16], e.hex(), ct))
        else:
            print('  OK  key=%s... -> %s' % (key.hex()[:16], e.hex()[:32]))
    print()
    print('SONUC:', 'TUMU GECTI' if ok else 'HATALAR VAR')
    return ok


if __name__ == '__main__':
    self_test()
