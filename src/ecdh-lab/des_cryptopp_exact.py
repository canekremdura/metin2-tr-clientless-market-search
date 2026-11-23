# -*- coding: utf-8 -*-
"""Crypto++ DES / DES_EDE2 birebir portu (des.cpp + dessp.cpp'den).
- IPERM/FPERM: Wei Dai rotasyon versiyonlari
- RawProcessBlock: 8 iterasyon x 4 alt-tur, Spbox tablolari
- EDE2: Get(l,r) -> IPERM -> des1(l,r) -> des2(r,l) -> des1(l,r) -> FPERM -> Put(r,l)
- Dogrulama: pycryptodome TripleDES (k1||k2||k1) ile
"""
import re
import os
import struct

MASK = 0xFFFFFFFF


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def _load_spbox():
    src = open(os.path.join(os.path.dirname(__file__), "cryptopp_src", "dessp.cpp")).read()
    m = re.search(r"Spbox\[8\]\[64\]\s*=\s*\{(.*?)\};", src, re.S)
    body = m.group(1)
    nums = re.findall(r"0x[0-9A-Fa-f]{8}", body)
    assert len(nums) == 512, len(nums)
    return [[int(x, 16) for x in nums[i * 64:(i + 1) * 64]] for i in range(8)]


SPBOX = _load_spbox()


def iperm(l, r):
    right = rotl(r, 4)
    work = (l ^ right) & 0xF0F0F0F0
    l ^= work
    right = rotr(right ^ work, 20)
    work = (l ^ right) & 0xFFFF0000
    l ^= work
    right = rotr(right ^ work, 18)
    work = (l ^ right) & 0x33333333
    l ^= work
    right = rotr(right ^ work, 6)
    work = (l ^ right) & 0x00FF00FF
    l ^= work
    right = rotl(right ^ work, 9)
    work = (l ^ right) & 0xAAAAAAAA
    l = rotl(l ^ work, 1)
    r = right ^ work
    return l, r


def fperm(l, r):
    right = rotr(r, 1)
    work = (l ^ right) & 0xAAAAAAAA
    right ^= work
    l = rotr(l ^ work, 9)
    work = (l ^ right) & 0x00FF00FF
    right ^= work
    l = rotl(l ^ work, 6)
    work = (l ^ right) & 0x33333333
    right ^= work
    l = rotl(l ^ work, 18)
    work = (l ^ right) & 0xFFFF0000
    right ^= work
    l = rotl(l ^ work, 20)
    work = (l ^ right) & 0xF0F0F0F0
    right ^= work
    l = rotr(l ^ work, 4)
    return l, right


def raw_process_block(l, r, k):
    """k = 32 dword program ( Crypto++ FixedSizeSecBlock<word32,32> )."""
    s0, s1, s2, s3 = SPBOX[0], SPBOX[1], SPBOX[2], SPBOX[3]
    s4, s5, s6, s7 = SPBOX[4], SPBOX[5], SPBOX[6], SPBOX[7]
    for i in range(8):
        work = rotr(r, 4) ^ k[4 * i + 0]
        l ^= s6[work & 0x3F] ^ s4[(work >> 8) & 0x3F] ^ s2[(work >> 16) & 0x3F] ^ s0[(work >> 24) & 0x3F]
        work = r ^ k[4 * i + 1]
        l ^= s7[work & 0x3F] ^ s5[(work >> 8) & 0x3F] ^ s3[(work >> 16) & 0x3F] ^ s1[(work >> 24) & 0x3F]
        work = rotr(l, 4) ^ k[4 * i + 2]
        r ^= s6[work & 0x3F] ^ s4[(work >> 8) & 0x3F] ^ s2[(work >> 16) & 0x3F] ^ s0[(work >> 24) & 0x3F]
        work = l ^ k[4 * i + 3]
        r ^= s7[work & 0x3F] ^ s5[(work >> 8) & 0x3F] ^ s3[(work >> 16) & 0x3F] ^ s1[(work >> 24) & 0x3F]
    return l, r


def des_ede2_block(block8, k1, k2):
    """DES_EDE2::ProcessAndXorBlock — yon: sifreleme (CTR).
    k1 = ileri program (32 dword), k2 = TERS sirada saklanmis program (32 dword).
    """
    l, r = struct.unpack(">II", block8)
    l, r = iperm(l, r)
    l, r = raw_process_block(l, r, k1)
    r, l = raw_process_block(r, l, k2)  # des2(r, l) — arguman takasli
    l, r = raw_process_block(l, r, k1)
    l, r = fperm(l, r)
    return struct.pack(">II", r, l)  # Put(r)(l) — cikti takasli


# ---- anahtar programi olusturma (RawSetKey) — dogrulama icin ----
PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]
TOTROT = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28]
PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
BYTEBIT = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]


def raw_set_key(key8, decryption=False):
    """Crypto++ RawSetKey — 32 dword k[] dondurur."""
    pc1m = [0] * 56
    for j in range(56):
        l = PC1[j] - 1
        m = l & 7
        pc1m[j] = 1 if (key8[l >> 3] & BYTEBIT[m]) else 0
    k = [0] * 32
    for i in range(16):
        ks = [0] * 8
        pcr = [0] * 56
        for j in range(56):
            l = j + TOTROT[i]
            pcr[j] = pc1m[l if l < (28 if j < 28 else 56) else l - 28]
        for j in range(48):
            if pcr[PC2[j] - 1]:
                l = j % 6
                ks[j // 6] |= BYTEBIT[l] >> 2
        k[2 * i] = (ks[0] << 24) | (ks[2] << 16) | (ks[4] << 8) | ks[6]
        k[2 * i + 1] = (ks[1] << 24) | (ks[3] << 16) | (ks[5] << 8) | ks[7]
    if decryption:
        for i in range(0, 16, 2):
            k[i], k[32 - 2 - i] = k[32 - 2 - i], k[i]
            k[i + 1], k[32 - 1 - i] = k[32 - 1 - i], k[i + 1]
    return k


def self_test():
    """pycryptodome TripleDES (k1||k2||k1) ile karsilastir."""
    try:
        from Crypto.Cipher import DES3
    except ImportError:
        print("pycryptodome yok — self-test atladi")
        return True
    import random
    random.seed(1234)
    ok = 0
    for trial in range(20):
        k1b = bytes(random.randrange(256) for _ in range(8))
        k2b = bytes(random.randrange(256) for _ in range(8))
        block = bytes(random.randrange(256) for _ in range(8))
        # Crypto++ EDE2 sifreleme yonu: m_des1 ileri, m_des2 TERS
        k1 = raw_set_key(k1b, decryption=False)
        k2 = raw_set_key(k2b, decryption=True)
        mine = des_ede2_block(block, k1, k2)
        ref = DES3.new(k1b + k2b + k1b, DES3.MODE_ECB).encrypt(block)
        if mine == ref:
            ok += 1
        else:
            print("FARK trial=%d\n  benim: %s\n  referans: %s" % (trial, mine.hex(), ref.hex()))
    print("self-test: %d/20 basarili" % ok)
    return ok == 20


if __name__ == "__main__":
    self_test()
