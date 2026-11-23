# -*- coding: utf-8 -*-
"""Crypto++ CAST256 birebir portu (cast.cpp — Leonard Janke katkisi).
- f1/f2/f3 tur fonksiyonlari (S[0..3], U8a=MSB)
- Omega anahtar plani (t_m/t_r tablolari, kappa[8])
- 6 ileri (Q) + 6 geri (QBar) quad tur — 16 bayt blok, big-endian
- Dogrulama: RFC 2612 resmi test vektorleri (128/192/256-bit anahtar)
Not: CTR modu icin IsForwardTransformation=true -> anahtar takasi YOK.
"""
import os
import re
import struct

MASK = 0xFFFFFFFF


def _rotl(x, n):
    n &= 31
    if n == 0:
        return x & MASK
    return ((x << n) | (x >> (32 - n))) & MASK


def _load_sboxes():
    src = open(os.path.join(os.path.dirname(__file__), "cryptopp_src", "casts.cpp")).read()
    m = re.search(r"CAST::S\[8\]\[256\]\s*=\s*\{(.*?)\};", src, re.S)
    nums = re.findall(r"0x([0-9A-Fa-f]{8})UL", m.group(1))
    assert len(nums) == 2048, len(nums)
    return [[int(x, 16) for x in nums[i * 256:(i + 1) * 256]] for i in range(8)]


S = _load_sboxes()

T_M = [
    [0x5A827999, 0xD151D6A1, 0x482133A9, 0xBEF090B1, 0x35BFEDB9, 0xAC8F4AC1,
     0x235EA7C9, 0x9A2E04D1, 0x10FD61D9, 0x87CCBEE1, 0xFE9C1BE9, 0x756B78F1,
     0xEC3AD5F9, 0x630A3301, 0xD9D99009, 0x50A8ED11, 0xC7784A19, 0x3E47A721,
     0xB5170429, 0x2BE66131, 0xA2B5BE39, 0x19851B41, 0x90547849, 0x0723D551],
    [0xC95C653A, 0x402BC242, 0xB6FB1F4A, 0x2DCA7C52, 0xA499D95A, 0x1B693662,
     0x9238936A, 0x0907F072, 0x7FD74D7A, 0xF6A6AA82, 0x6D76078A, 0xE4456492,
     0x5B14C19A, 0xD1E41EA2, 0x48B37BAA, 0xBF82D8B2, 0x365235BA, 0xAD2192C2,
     0x23F0EFCA, 0x9AC04CD2, 0x118FA9DA, 0x885F06E2, 0xFF2E63EA, 0x75FDC0F2],
    [0x383650DB, 0xAF05ADE3, 0x25D50AEB, 0x9CA467F3, 0x1373C4FB, 0x8A432203,
     0x01127F0B, 0x77E1DC13, 0xEEB1391B, 0x65809623, 0xDC4FF32B, 0x531F5033,
     0xC9EEAD3B, 0x40BE0A43, 0xB78D674B, 0x2E5CC453, 0xA52C215B, 0x1BFB7E63,
     0x92CADB6B, 0x099A3873, 0x8069957B, 0xF738F283, 0x6E084F8B, 0xE4D7AC93],
    [0xA7103C7C, 0x1DDF9984, 0x94AEF68C, 0x0B7E5394, 0x824DB09C, 0xF91D0DA4,
     0x6FEC6AAC, 0xE6BBC7B4, 0x5D8B24BC, 0xD45A81C4, 0x4B29DECC, 0xC1F93BD4,
     0x38C898DC, 0xAF97F5E4, 0x266752EC, 0x9D36AFF4, 0x14060CFC, 0x8AD56A04,
     0x01A4C70C, 0x78742414, 0xEF43811C, 0x6612DE24, 0xDCE23B2C, 0x53B19834],
    [0x15EA281D, 0x8CB98525, 0x0388E22D, 0x7A583F35, 0xF1279C3D, 0x67F6F945,
     0xDEC6564D, 0x5595B355, 0xCC65105D, 0x43346D65, 0xBA03CA6D, 0x30D32775,
     0xA7A2847D, 0x1E71E185, 0x95413E8D, 0x0C109B95, 0x82DFF89D, 0xF9AF55A5,
     0x707EB2AD, 0xE74E0FB5, 0x5E1D6CBD, 0xD4ECC9C5, 0x4BBC26CD, 0xC28B83D5],
    [0x84C413BE, 0xFB9370C6, 0x7262CDCE, 0xE9322AD6, 0x600187DE, 0xD6D0E4E6,
     0x4DA041EE, 0xC46F9EF6, 0x3B3EFBFE, 0xB20E5906, 0x28DDB60E, 0x9FAD1316,
     0x167C701E, 0x8D4BCD26, 0x041B2A2E, 0x7AEA8736, 0xF1B9E43E, 0x68894146,
     0xDF589E4E, 0x5627FB56, 0xCCF7585E, 0x43C6B566, 0xBA96126E, 0x31656F76],
    [0xF39DFF5F, 0x6A6D5C67, 0xE13CB96F, 0x580C1677, 0xCEDB737F, 0x45AAD087,
     0xBC7A2D8F, 0x33498A97, 0xAA18E79F, 0x20E844A7, 0x97B7A1AF, 0x0E86FEB7,
     0x85565BBF, 0xFC25B8C7, 0x72F515CF, 0xE9C472D7, 0x6093CFDF, 0xD7632CE7,
     0x4E3289EF, 0xC501E6F7, 0x3BD143FF, 0xB2A0A107, 0x296FFE0F, 0xA03F5B17],
    [0x6277EB00, 0xD9474808, 0x5016A510, 0xC6E60218, 0x3DB55F20, 0xB484BC28,
     0x2B541930, 0xA2237638, 0x18F2D340, 0x8FC23048, 0x06918D50, 0x7D60EA58,
     0xF4304760, 0x6AFFA468, 0xE1CF0170, 0x589E5E78, 0xCF6DBB80, 0x463D1888,
     0xBD0C7590, 0x33DBD298, 0xAAAB2FA0, 0x217A8CA8, 0x9849E9B0, 0x0F1946B8],
]

T_R = [
    [19, 27, 3, 11, 19, 27, 3, 11, 19, 27, 3, 11, 19, 27, 3, 11, 19, 27, 3, 11, 19, 27, 3, 11],
    [4, 12, 20, 28, 4, 12, 20, 28, 4, 12, 20, 28, 4, 12, 20, 28, 4, 12, 20, 28, 4, 12, 20, 28],
    [21, 29, 5, 13, 21, 29, 5, 13, 21, 29, 5, 13, 21, 29, 5, 13, 21, 29, 5, 13, 21, 29, 5, 13],
    [6, 14, 22, 30, 6, 14, 22, 30, 6, 14, 22, 30, 6, 14, 22, 30, 6, 14, 22, 30, 6, 14, 22, 30],
    [23, 31, 7, 15, 23, 31, 7, 15, 23, 31, 7, 15, 23, 31, 7, 15, 23, 31, 7, 15, 23, 31, 7, 15],
    [8, 16, 24, 0, 8, 16, 24, 0, 8, 16, 24, 0, 8, 16, 24, 0, 8, 16, 24, 0, 8, 16, 24, 0],
    [25, 1, 9, 17, 25, 1, 9, 17, 25, 1, 9, 17, 25, 1, 9, 17, 25, 1, 9, 17, 25, 1, 9, 17],
    [10, 18, 26, 2, 10, 18, 26, 2, 10, 18, 26, 2, 10, 18, 26, 2, 10, 18, 26, 2, 10, 18, 26, 2],
]

S0, S1, S2, S3 = S[0], S[1], S[2], S[3]


def _f1(l, r, km, kr):
    t = _rotl((km + r) & MASK, kr)
    l ^= ((S0[t >> 24] ^ S1[(t >> 16) & 0xFF]) - S2[(t >> 8) & 0xFF]) + S3[t & 0xFF]
    return l & MASK, t


def _f2(l, r, km, kr):
    t = _rotl(km ^ r, kr)
    l ^= ((S0[t >> 24] - S1[(t >> 16) & 0xFF]) + S2[(t >> 8) & 0xFF]) ^ S3[t & 0xFF]
    return l & MASK, t


def _f3(l, r, km, kr):
    t = _rotl((km - r) & MASK, kr)
    l ^= ((S0[t >> 24] + S1[(t >> 16) & 0xFF]) ^ S2[(t >> 8) & 0xFF]) - S3[t & 0xFF]
    return l & MASK, t


def cast256_set_key(key, forward=True):
    """CAST256::Base::UncheckedSetKey — K[96] dondurur (rotasyonlar + masklar).
    forward=True (CTR icin) -> anahtar takasi yok."""
    kappa = [0] * 8
    # GetUserKey(BIG_ENDIAN_ORDER, kappa, 8, userKey, keylength) — sifir dolgulu
    for i in range(len(key)):
        kappa[i // 4] |= key[i] << (24 - 8 * (i % 4))
    K = [0] * 96
    for i in range(12):
        kappa = _omega(2 * i, kappa)
        kappa = _omega(2 * i + 1, kappa)
        K[8 * i + 0] = kappa[0] & 31
        K[8 * i + 1] = kappa[2] & 31
        K[8 * i + 2] = kappa[4] & 31
        K[8 * i + 3] = kappa[6] & 31
        K[8 * i + 4] = kappa[7]
        K[8 * i + 5] = kappa[5]
        K[8 * i + 6] = kappa[3]
        K[8 * i + 7] = kappa[1]
    if not forward:
        for j in range(6):
            for i in range(4):
                i1 = 8 * j + i
                i2 = 8 * (11 - j) + i
                K[i1], K[i2] = K[i2], K[i1]
                K[i1 + 4], K[i2 + 4] = K[i2 + 4], K[i1 + 4]
    return K


def _omega(i, kappa):
    k = kappa[:]
    k[6], _ = _f1(k[6], k[7], T_M[0][i], T_R[0][i])
    k[5], _ = _f2(k[5], k[6], T_M[1][i], T_R[1][i])
    k[4], _ = _f3(k[4], k[5], T_M[2][i], T_R[2][i])
    k[3], _ = _f1(k[3], k[4], T_M[3][i], T_R[3][i])
    k[2], _ = _f2(k[2], k[3], T_M[4][i], T_R[4][i])
    k[1], _ = _f3(k[1], k[2], T_M[5][i], T_R[5][i])
    k[0], _ = _f1(k[0], k[1], T_M[6][i], T_R[6][i])
    k[7], _ = _f2(k[7], k[0], T_M[7][i], T_R[7][i])
    return k


def cast256_block(block16, K):
    """CAST256::Base::ProcessAndXorBlock (sifreleme yonu).
    block16: 16 bayt -> 16 bayt."""
    b0, b1, b2, b3 = struct.unpack(">IIII", block16)
    block = [b0, b1, b2, b3]

    def q(i):
        block[2], _ = _f1(block[2], block[3], K[8 * i + 4], K[8 * i + 0])
        block[1], _ = _f2(block[1], block[2], K[8 * i + 5], K[8 * i + 1])
        block[0], _ = _f3(block[0], block[1], K[8 * i + 6], K[8 * i + 2])
        block[3], _ = _f1(block[3], block[0], K[8 * i + 7], K[8 * i + 3])

    def qbar(i):
        block[3], _ = _f1(block[3], block[0], K[8 * i + 7], K[8 * i + 3])
        block[0], _ = _f3(block[0], block[1], K[8 * i + 6], K[8 * i + 2])
        block[1], _ = _f2(block[1], block[2], K[8 * i + 5], K[8 * i + 1])
        block[2], _ = _f1(block[2], block[3], K[8 * i + 4], K[8 * i + 0])

    for i in range(6):
        q(i)
    for i in range(6, 12):
        qbar(i)
    return struct.pack(">IIII", block[0], block[1], block[2], block[3])


def self_test():
    """RFC 2612 resmi test vektorleri."""
    vectors = [
        ("2342bb9efa38542c0af75647f29f615d",
         "00000000000000000000000000000000",
         "c842a08972b43d20836c91d1b7530f6b"),
        ("2342bb9efa38542cbed0ac83940ac298bac77a7717942863",
         "00000000000000000000000000000000",
         "1b386c0210dcadcbdd0e41aa08a7a7e8"),
        ("2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604",
         "00000000000000000000000000000000",
         "4f6a2038286897b9c9870136553317fa"),
    ]
    ok = 0
    for key_hex, pt_hex, ct_hex in vectors:
        key = bytes.fromhex(key_hex)
        pt = bytes.fromhex(pt_hex)
        ct_exp = bytes.fromhex(ct_hex)
        K = cast256_set_key(key, forward=True)
        ct = cast256_block(pt, K)
        status = "OK" if ct == ct_exp else "FARKLI (beklenen %s, bizim %s)" % (ct_exp.hex(), ct.hex())
        if ct == ct_exp:
            ok += 1
        print("anahtar %dB: %s" % (len(key), status))
    print("RFC 2612 test: %d/3" % ok)
    return ok == 3


if __name__ == "__main__":
    self_test()
