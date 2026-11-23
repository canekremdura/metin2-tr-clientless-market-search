# -*- coding: utf-8 -*-
"""Serpent portu (Crypto++ birebir: serpent.cpp + serpentp.h).
serpent_set_key(user_key) -> m_key[132]
serpent_encrypt_block(block16, k) -> 16 bayt
Program enjeksiyonu: nesneden okunan m_key dogrudan kullanilabilir.
"""
import struct

M32 = 0xFFFFFFFF


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def _s0(r0, r1, r2, r3, r4):
    r3 ^= r0; r4 = r1; r1 &= r3; r4 ^= r2; r1 ^= r0
    r0 |= r3; r0 ^= r4; r4 ^= r3; r3 ^= r2; r2 |= r1
    r2 ^= r4; r4 = (~r4) & M32; r4 |= r1; r1 ^= r3
    r1 ^= r4; r3 |= r0; r1 ^= r3; r4 ^= r3
    return r0 & M32, r1 & M32, r2 & M32, r3 & M32, r4 & M32


def _s1(r0, r1, r2, r3, r4):
    r0 = (~r0) & M32; r2 = (~r2) & M32; r4 = r0; r0 &= r1
    r2 ^= r0; r0 |= r3; r3 ^= r2; r1 ^= r0; r0 ^= r4
    r4 |= r1; r1 ^= r3; r2 |= r0; r2 &= r4; r0 ^= r1
    r1 &= r2; r1 ^= r0; r0 &= r2; r0 ^= r4
    return r0 & M32, r1 & M32, r2 & M32, r3 & M32, r4 & M32


def _s2(r0, r1, r2, r3, r4):
    r4 = r0; r0 &= r2; r0 ^= r3; r2 ^= r1; r2 ^= r0
    r3 |= r4; r3 ^= r1; r4 ^= r2; r1 = r3; r3 |= r4
    r3 ^= r0; r0 &= r1; r4 ^= r0; r1 ^= r3; r1 ^= r4
    r4 = (~r4) & M32
    return r0 & M32, r1 & M32, r2 & M32, r3 & M32, r4 & M32


def _s3(r0, r1, r2, r3, r4):
    r4 = r0; r0 |= r3; r3 ^= r1; r1 &= r4; r4 ^= r2
    r2 ^= r3; r3 &= r0; r4 |= r1; r3 ^= r4; r0 ^= r1
    r4 &= r0; r1 ^= r3; r4 ^= r2; r1 |= r0; r1 ^= r2
    r0 ^= r3; r2 = r1; r1 |= r3; r1 ^= r0
    return r0 & M32, r1 & M32, r2 & M32, r3 & M32, r4 & M32


def _s4(r0, r1, r2, r3, r4):
    r1 ^= r3; r3 = (~r3) & M32; r2 ^= r3; r3 ^= r0; r4 = r1
    r1 &= r3; r1 ^= r2; r4 ^= r3; r0 ^= r4; r2 &= r4
    r2 ^= r0; r0 &= r1; r3 ^= r0; r4 |= r1; r4 ^= r0
    r0 |= r3; r0 ^= r2; r2 &= r3; r0 = (~r0) & M32; r4 ^= r2
    return r0 & M32, r1 & M32, r2 & M32, r3 & M32, r4 & M32


def _s5(r0, r1, r2, r3, r4):
    r0 ^= r1; r1 ^= r3; r3 = (~r3) & M32; r4 = r1; r1 &= r0
    r2 ^= r3; r1 ^= r2; r2 |= r4; r4 ^= r3; r3 &= r1
    r3 ^= r0; r4 ^= r1; r4 ^= r2; r2 ^= r0; r0 &= r3
    r2 = (~r2) & M32; r0 ^= r4; r4 |= r3; r2 ^= r4
    return r0 & M32, r1 & M32, r2 & M32, r3 & M32, r4 & M32


def _s6(r0, r1, r2, r3, r4):
    r2 = (~r2) & M32; r4 = r3; r3 &= r0; r0 ^= r4
    r3 ^= r2; r2 |= r4; r1 ^= r3; r2 ^= r0; r0 |= r1
    r2 ^= r1; r4 ^= r0; r0 |= r3; r0 ^= r2; r4 ^= r3
    r4 ^= r0; r3 = (~r3) & M32; r2 &= r4; r2 ^= r3
    return r0 & M32, r1 & M32, r2 & M32, r3 & M32, r4 & M32


def _s7(r0, r1, r2, r3, r4):
    r4 = r2; r2 &= r1; r2 ^= r3; r3 &= r1; r4 ^= r2
    r2 ^= r1; r1 ^= r0; r0 |= r4; r0 ^= r2; r3 ^= r1
    r2 ^= r3; r3 &= r0; r3 ^= r4; r4 ^= r2; r2 &= r0
    r4 = (~r4) & M32; r2 ^= r4; r4 &= r0; r1 ^= r3; r4 ^= r1
    return r0 & M32, r1 & M32, r2 & M32, r3 & M32, r4 & M32


_ORDERS = {
    'beforeS0': ('a', 'b', 'c', 'd', 'e'),
    'afterS0': ('b', 'e', 'c', 'a', 'd'),
    'afterS1': ('c', 'b', 'a', 'e', 'd'),
    'afterS2': ('a', 'e', 'b', 'd', 'c'),
    'afterS3': ('e', 'b', 'd', 'c', 'a'),
    'afterS4': ('b', 'a', 'e', 'c', 'd'),
    'afterS5': ('a', 'c', 'b', 'e', 'd'),
    'afterS6': ('a', 'c', 'd', 'b', 'e'),
    'afterS7': ('d', 'e', 'b', 'a', 'c'),
}
_STAGE = {'beforeS0': 0, 'afterS0': 1, 'afterS1': 2, 'afterS2': 3,
          'afterS3': 4, 'afterS4': 5, 'afterS5': 6, 'afterS6': 7, 'afterS7': 8}


def _lt(v, order):
    a, b, c, d = v[order[0]], v[order[1]], v[order[2]], v[order[3]]
    a = _rotl(a, 13)
    c = _rotl(c, 3)
    d = _rotl(d ^ c ^ ((a << 3) & M32), 7)
    b = _rotl(b ^ a ^ c, 1)
    a = _rotl(a ^ b ^ d, 5)
    c = _rotl(c ^ d ^ ((b << 7) & M32), 22)
    v[order[0]], v[order[1]], v[order[2]], v[order[3]] = a, b, c, d


def _kx(v, order, r, k, koff):
    v[order[0]] ^= k[koff + 4 * r + 0]
    v[order[1]] ^= k[koff + 4 * r + 1]
    v[order[2]] ^= k[koff + 4 * r + 2]
    v[order[3]] ^= k[koff + 4 * r + 3]


def _sbox(v, order, fn):
    r = fn(v[order[0]], v[order[1]], v[order[2]], v[order[3]], v[order[4]])
    v[order[0]], v[order[1]], v[order[2]], v[order[3]], v[order[4]] = r


def serpent_encrypt_block(block16, k):
    v = {'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0}
    v['a'], v['b'], v['c'], v['d'] = struct.unpack('<IIII', block16)
    koff = 0
    i = 1
    while True:
        _kx(v, _ORDERS['beforeS0'], 0, k, koff)
        _sbox(v, _ORDERS['beforeS0'], _s0)
        _lt(v, _ORDERS['afterS0'])
        _kx(v, _ORDERS['afterS0'], 1, k, koff)
        _sbox(v, _ORDERS['afterS0'], _s1)
        _lt(v, _ORDERS['afterS1'])
        _kx(v, _ORDERS['afterS1'], 2, k, koff)
        _sbox(v, _ORDERS['afterS1'], _s2)
        _lt(v, _ORDERS['afterS2'])
        _kx(v, _ORDERS['afterS2'], 3, k, koff)
        _sbox(v, _ORDERS['afterS2'], _s3)
        _lt(v, _ORDERS['afterS3'])
        _kx(v, _ORDERS['afterS3'], 4, k, koff)
        _sbox(v, _ORDERS['afterS3'], _s4)
        _lt(v, _ORDERS['afterS4'])
        _kx(v, _ORDERS['afterS4'], 5, k, koff)
        _sbox(v, _ORDERS['afterS4'], _s5)
        _lt(v, _ORDERS['afterS5'])
        _kx(v, _ORDERS['afterS5'], 6, k, koff)
        _sbox(v, _ORDERS['afterS5'], _s6)
        _lt(v, _ORDERS['afterS6'])
        _kx(v, _ORDERS['afterS6'], 7, k, koff)
        _sbox(v, _ORDERS['afterS6'], _s7)
        if i == 4:
            break
        i += 1
        v['c'] = v['b']
        v['b'] = v['e']
        v['e'] = v['d']
        v['d'] = v['a']
        v['a'] = v['e']
        koff += 32
        _lt(v, _ORDERS['beforeS0'])
    _kx(v, _ORDERS['afterS7'], 8, k, koff)
    return struct.pack('<IIII', v['d'], v['e'], v['b'], v['a'])


def _lk(k, koff, oname, v):
    r = _STAGE[oname]
    p = koff + (8 - r) * 4
    v[_ORDERS[oname][0]] = k[p]
    v[_ORDERS[oname][1]] = k[p + 1]
    v[_ORDERS[oname][2]] = k[p + 2]
    v[_ORDERS[oname][3]] = k[p + 3]


def _sk(k, koff, oname, v):
    r = _STAGE[oname]
    p = koff + (8 - r) * 4 + 4
    k[p] = v[_ORDERS[oname][0]]
    k[p + 1] = v[_ORDERS[oname][1]]
    k[p + 2] = v[_ORDERS[oname][2]]
    k[p + 3] = v[_ORDERS[oname][3]]


def _prestep(k, koff, lk_name, sbox, sk_name):
    v = {'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0}
    _lk(k, koff, lk_name, v)
    _sbox(v, _ORDERS[lk_name], sbox)
    _sk(k, koff, sk_name, v)


def serpent_set_key(user_key):
    k0 = [0] * 8
    for i in range(len(user_key)):
        k0[i // 4] |= user_key[i] << (8 * (i % 4))
    if len(user_key) < 32:
        k0[len(user_key) // 4] |= 1 << ((len(user_key) % 4) * 8)
    k = [0] * 132
    t = k0[7]
    for i in range(8):
        t = _rotl(k0[i] ^ k0[(i + 3) % 8] ^ k0[(i + 5) % 8] ^ t ^ 0x9e3779b9 ^ i, 11)
        k[i] = k0[i] = t
    for i in range(8, 132):
        t = _rotl(k[i - 8] ^ k[i - 5] ^ k[i - 3] ^ t ^ 0x9e3779b9 ^ i, 11)
        k[i] = t
    koff = -20
    for _ in range(4):
        _prestep(k, koff, 'afterS2', _s3, 'afterS3')
        _prestep(k, koff, 'afterS1', _s2, 'afterS2')
        _prestep(k, koff, 'afterS0', _s1, 'afterS1')
        _prestep(k, koff, 'beforeS0', _s0, 'afterS0')
        koff += 32
        _prestep(k, koff, 'afterS6', _s7, 'afterS7')
        _prestep(k, koff, 'afterS5', _s6, 'afterS6')
        _prestep(k, koff, 'afterS4', _s5, 'afterS5')
        _prestep(k, koff, 'afterS3', _s4, 'afterS4')
    _prestep(k, koff, 'afterS2', _s3, 'afterS3')
    return k
