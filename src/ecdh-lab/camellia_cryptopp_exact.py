# -*- coding: utf-8 -*-
"""Camellia — Crypto++ (camellia.cpp) birebir portu.

Kaynak tablolar `cryptopp_src/camellia.cpp`'den ayristirilir:
  - `Camellia::Base::SP[4][256]` (1024 word32) — tur fonksiyonu
  - `Camellia::Base::s1[256]` (byte)            — anahtar programi (SLOW_ROUND)
Blok 16 bayt, anahtar 16/24/32, blok I/O BIG_ENDIAN.

ONEMLI (EFI): Crypto++ `#define EFI(i) (1-(i))` YALNIZCA CRYPTOPP_LITTLE_ENDIAN
altinda tanimli. x86'da `ks` dizisi ters sirada saklanir. Bu port ayni
davranisi uygular; aksi hâlde anahtar programi sessizce yanlis olur.

DOGRULAMA: `cryptopp_src/test_camellia.txt` (NESSIE, 128-bit anahtarlar).
"""
import os
import re

_M = 0xFFFFFFFF


def _rotl(x, n):
    n %= 32
    return ((x << n) | (x >> (32 - n))) & _M if n else x


def _rotr(x, n):
    n %= 32
    return ((x >> n) | (x << (32 - n))) & _M if n else x


def _load_tables():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "cryptopp_src", "camellia.cpp")
    src = open(path, encoding="utf-8", errors="replace").read()

    i = src.index("SP[4][256]")
    sp_nums = re.findall(r"0x([0-9A-Fa-f]{8})", src[i:])
    assert len(sp_nums) == 1024, len(sp_nums)
    sp = [[int(sp_nums[r * 256 + k], 16) for k in range(256)] for r in range(4)]

    j = src.index("s1[256]")
    tail = src[j:]
    m = re.search(r"\{(\s*(?:\d+\s*,\s*){255,256}\d+\s*)\}", tail)
    s1 = [int(x) for x in re.findall(r"\d+", m.group(1))]
    assert len(s1) == 256, len(s1)
    return sp, s1


SP, S1 = _load_tables()

# x86 = little endian -> Crypto++'in EFI(..) tanimi aktif olur
EFI = lambda i: 1 - i  # noqa: E731


def _rotl8(x, n):
    """8-bit rotasyon. Crypto++ `rotlConstant<R>(T x)` tipi ARGUMANDAN cikarir;
    `s1[...]` bir `byte` oldugu icin donus de `byte` olur (genislik 8 bit)."""
    n %= 8
    return ((x << n) | (x >> (8 - n))) & 0xFF if n else x & 0xFF


def _rotr8(x, n):
    n %= 8
    return ((x >> n) | (x << (8 - n))) & 0xFF if n else x & 0xFF


def _byte(x, i):
    return (x >> (8 * i)) & 0xFF


def _slow_round(lh, ll, rh, rl, kh, kl):
    """Crypto++ SLOW_ROUND — s1 tablosuyla (anahtar programinda kullanilir).

    NOT: buradaki TUM `rotlConstant<1>` / `rotrConstant<1>` cagrilari `byte`
    tiplidir -> 8-bit rotasyon. `rotlConstant<8>`/`<16>` ise word32 uzerinde
    calisir -> 32-bit rotasyon."""
    zr = ll ^ kl
    zl = lh ^ kh
    zr = (_rotl8(S1[_byte(zr, 3)], 1)
          | (_rotr8(S1[_byte(zr, 2)], 1) << 24)
          | (S1[_rotl8(_byte(zr, 1), 1)] << 16)
          | (S1[_byte(zr, 0)] << 8)) & _M
    zl = ((S1[_byte(zl, 3)] << 24)
          | (_rotl8(S1[_byte(zl, 2)], 1) << 16)
          | (_rotr8(S1[_byte(zl, 1)], 1) << 8)
          | S1[_rotl8(_byte(zl, 0), 1)]) & _M
    zl ^= zr
    zr = (zl ^ (_rotl(zr, 8) & _M)) & _M
    zl = (zr ^ (_rotr(zl, 8) & _M)) & _M
    rh ^= _rotl(zr, 16)
    rh ^= zl
    rl ^= _rotl(zl, 8)
    return lh & _M, ll & _M, rh & _M, rl & _M


def _round(lh, ll, rh, rl, kh, kl):
    """Crypto++ ROUND — SP tablolariyla (hizli tur)."""
    th = lh ^ kh
    tl = ll ^ kl
    d = SP[0][_byte(tl, 0)] ^ SP[1][_byte(tl, 3)] ^ SP[2][_byte(tl, 2)] ^ SP[3][_byte(tl, 1)]
    u = SP[0][_byte(th, 3)] ^ SP[1][_byte(th, 2)] ^ SP[2][_byte(th, 1)] ^ SP[3][_byte(th, 0)]
    d ^= u
    rh ^= d
    rl ^= d
    rl ^= _rotr(u, 8) & _M
    return lh & _M, ll & _M, rh & _M, rl & _M


def _double_round(lh, ll, rh, rl, k0, k1, k2, k3):
    """C++ DOUBLE_ROUND birebir — YERINDE semantik.

    C'de makro `(lh,ll,rh,rl)` degiskenlerini yerinde gunceller: birinci
    ROUND rh/rl'yi, ikinci ROUND lh/ll'yi degistirir. `_round` ise sonucu
    HER ZAMAN (A,B,C,D) sirasiyla dondurdugu icin, ikinci cagrinin ciktisi
    (rh, rl, lh', ll') olur; yerinde semantigi elde etmek icin basa ve sona
    takas edilmis hâlde geri donulmelidir."""
    a, b, c, d = _round(lh, ll, rh, rl, k0, k1)   # (lh, ll, rh', rl')
    a, b, c, d = _round(c, d, a, b, k2, k3)        # (rh', rl', lh'', ll'')
    return c, d, a, b                              # (lh'', ll'', rh', rl')


_C1 = (0xA09E667F, 0x3BCC908B, 0xB67AE858, 0x4CAA73B2)
_C2 = (0xC6EF372F, 0xE94F82BE, 0x54FF53A5, 0xF1D36F1C)
_C3 = (0x10E527FA, 0xDE682D1D, 0xB05688C2, 0xB3E6C1FD)


class CamelliaKey:
    """Anahtar programi — Crypto++ m_key ile ayni duzen (32 word, 8 tur)."""

    __slots__ = ("ks", "rounds")

    def __init__(self, key: bytes, forward: bool = True):
        if len(key) not in (16, 24, 32):
            raise ValueError("Camellia anahtari 16/24/32 bayt olmali (%d)" % len(key))
        rounds = 4 if len(key) >= 24 else 3
        kslen = 8 * rounds + 2
        ks = [0] * (kslen * 2)

        m = 0
        a = 0
        if not forward:
            m = -1
            a = kslen - 1

        kl0, kl1, kl2, kl3 = (int.from_bytes(key[i:i + 4], "big") for i in (0, 4, 8, 12))

        def calc(i, j):
            """CALC_ADDR2 bayt ofseti -> word32 indeksi.

            C: (byte*)base + 8*i + 4*j + ((-16*i) & m)
            m=0     -> 8i+4j           -> word: 2i + j
            m=-1    -> 8i+4j-16i       -> word: j - 2i
            (base zaten ks32 += 2*a ile word cinsinden ilerletilmis)"""
            return (2 * i + j) if m == 0 else (j - 2 * i)

        base = 2 * a

        def put64(idx, val):
            """*(word64*)CALC_ADDR(ks32, idx) = val.

            kucuk-endian bellekte dusuk word once yazilir."""
            p = base + calc(idx, 0)
            if p < 0 or p + 1 >= len(ks):
                raise IndexError("Camellia ks indeksi %d (len=%d)" % (p, len(ks)))
            ks[p] = val & _M
            ks[p + 1] = (val >> 32) & _M

        k0, k1, k2, k3 = kl0, kl1, kl2, kl3

        self.ks = ks

        def prepare(k0, k1, k2, k3):
            return ((k0 << 32) | k1) & 0xFFFFFFFFFFFFFFFF, ((k2 << 32) | k3) & 0xFFFFFFFFFFFFFFFF

        def ks_round(i, r, which, kwl, kwr):
            """Crypto++ KS_ROUND birebir.

            KRITIK: makroda IKI `if` de ayri ayri degerlendirilir ve ikisi de
            atesleyebilir. `int(r<64)` ve `int(r>64)` ifadeleri biri 1 iken
            digeri 0 oldugundan, `which=3` icin bir kosul bit1'i digeri bit0'i
            test eder -- yani AYNI cagri IKI ayri alt anahtar yazar:

              r<64 : bit(1<<1)=2 -> adres i+EFI(1)=i   , deger (kwr<<r)|(kwl>>(64-r))
                     bit(1<<0)   -> adres i+EFI(0)=i+1 , deger (kwl<<r)|(kwr>>(64-r))
              r>64 : bit(1<<0)   -> adres i+EFI(0)=i+1 , deger (kwr<<r)|(kwl>>(64-r))
                     bit(1<<1)   -> adres i+EFI(1)=i   , deger (kwl<<r)|(kwr>>(64-r))

            Tek dal uygulamak alt anahtarlarin yarisini bos/yanlis birakir --
            tur fonksiyonu dogru olsa bile blok ciktisi tamamen bozulur."""
            rr = r % 64
            lt = 1 if r < 64 else 0
            gt = 1 if r > 64 else 0
            if which & (1 << lt):
                put64(i + (1 - lt), ((kwr << rr) | (kwl >> (64 - rr))) & 0xFFFFFFFFFFFFFFFF)
            if which & (1 << gt):
                put64(i + (1 - gt), ((kwl << rr) | (kwr >> (64 - rr))) & 0xFFFFFFFFFFFFFFFF)

        if len(key) == 16:
            kwl, kwr = prepare(k0, k1, k2, k3)
            put64(0 + EFI(0), kwl)
            put64(0 + EFI(1), kwr)
            ks_round(4, 15, 3, kwl, kwr)
            ks_round(10, 45, 3, kwl, kwr)
            ks_round(12, 60, 2, kwl, kwr)
            ks_round(16, 77, 3, kwl, kwr)
            ks_round(18, 94, 3, kwl, kwr)
            ks_round(22, 111, 3, kwl, kwr)

            k0, k1, k2, k3 = kl0, kl1, kl2, kl3
            k0, k1, k2, k3 = _double_round(k0, k1, k2, k3, *_C1)
            k0 ^= kl0; k1 ^= kl1; k2 ^= kl2; k3 ^= kl3
            k0, k1, k2, k3 = _double_round(k0, k1, k2, k3, *_C2)

            kwl, kwr = prepare(k0, k1, k2, k3)
            put64(2 + EFI(0), kwl)
            put64(2 + EFI(1), kwr)
            ks_round(6, 15, 3, kwl, kwr)
            ks_round(8, 30, 3, kwl, kwr)
            ks_round(12, 45, 1, kwl, kwr)
            ks_round(14, 60, 3, kwl, kwr)
            ks_round(20, 94, 3, kwl, kwr)
            ks_round(24, 47, 3, kwl, kwr)
        else:
            kwl, kwr = prepare(k0, k1, k2, k3)
            put64(0 + EFI(0), kwl)
            put64(0 + EFI(1), kwr)
            ks_round(12, 45, 3, kwl, kwr)
            ks_round(16, 60, 3, kwl, kwr)
            ks_round(22, 77, 3, kwl, kwr)
            ks_round(30, 111, 3, kwl, kwr)

            kr0, kr1 = (int.from_bytes(key[i:i + 4], "big") for i in (16, 20))
            if len(key) == 24:
                kr2, kr3 = (~kr0) & _M, (~kr1) & _M
            else:
                kr2, kr3 = (int.from_bytes(key[i:i + 4], "big") for i in (24, 28))
            k0, k1, k2, k3 = kr0, kr1, kr2, kr3

            kwl, kwr = prepare(k0, k1, k2, k3)
            ks_round(4, 15, 3, kwl, kwr)
            ks_round(8, 30, 3, kwl, kwr)
            ks_round(18, 60, 3, kwl, kwr)
            ks_round(26, 94, 3, kwl, kwr)

            k0 ^= kl0; k1 ^= kl1; k2 ^= kl2; k3 ^= kl3
            k0, k1, k2, k3 = _double_round(k0, k1, k2, k3, *_C1)
            k0 ^= kl0; k1 ^= kl1; k2 ^= kl2; k3 ^= kl3
            k0, k1, k2, k3 = _double_round(k0, k1, k2, k3, *_C2)

            kwl, kwr = prepare(k0, k1, k2, k3)
            ks_round(6, 15, 3, kwl, kwr)
            ks_round(14, 45, 3, kwl, kwr)
            ks_round(24, 77, 3, kwl, kwr)
            ks_round(28, 94, 3, kwl, kwr)

            k0 ^= kr0; k1 ^= kr1; k2 ^= kr2; k3 ^= kr3
            k0, k1, k2, k3 = _double_round(k0, k1, k2, k3, *_C3)

            kwl, kwr = prepare(k0, k1, k2, k3)
            put64(2 + EFI(0), kwl)
            put64(2 + EFI(1), kwr)
            ks_round(10, 30, 3, kwl, kwr)
            ks_round(20, 60, 3, kwl, kwr)
            ks_round(32, 47, 3, kwl, kwr)

        self.rounds = rounds


def encrypt_block(block16: bytes, kp: CamelliaKey) -> bytes:
    lh, ll, rh, rl = (int.from_bytes(block16[i:i + 4], "big") for i in (0, 4, 8, 12))
    ks = kp.ks
    rounds = kp.rounds

    def KS(i, j):
        return ks[i * 4 + EFI(j // 2) * 2 + EFI(j % 2)]

    lh ^= KS(0, 0); ll ^= KS(0, 1); rh ^= KS(0, 2); rl ^= KS(0, 3)

    a, b, c, d = _slow_round(lh, ll, rh, rl, KS(1, 0), KS(1, 1))
    lh, ll, rh, rl = a, b, c, d
    a, b, c, d = _slow_round(rh, rl, lh, ll, KS(1, 2), KS(1, 3))
    lh, ll, rh, rl = c, d, a, b

    for _ in range(rounds - 1):
        lh, ll, rh, rl = _double_round(lh, ll, rh, rl, KS(2, 0), KS(2, 1), KS(2, 2), KS(2, 3))
        lh, ll, rh, rl = _double_round(lh, ll, rh, rl, KS(3, 0), KS(3, 1), KS(3, 2), KS(3, 3))
        # FL / FLINV
        ll ^= _rotl(lh & KS(4, 0), 1) & _M
        lh ^= (ll | KS(4, 1)) & _M
        rh ^= (rl | KS(4, 3)) & _M
        rl ^= _rotl(rh & KS(4, 2), 1) & _M
        lh, ll, rh, rl = _double_round(lh, ll, rh, rl, KS(5, 0), KS(5, 1), KS(5, 2), KS(5, 3))
        # kaynaktaki `ks += 16` word32 -> 4 tur ilerleme
        ks = ks[16:]

    lh, ll, rh, rl = _double_round(lh, ll, rh, rl, KS(2, 0), KS(2, 1), KS(2, 2), KS(2, 3))
    a, b, c, d = _round(lh, ll, rh, rl, KS(3, 0), KS(3, 1))
    lh, ll, rh, rl = a, b, c, d
    a, b, c, d = _slow_round(rh, rl, lh, ll, KS(3, 2), KS(3, 3))
    lh, ll, rh, rl = c, d, a, b

    lh ^= KS(4, 0); ll ^= KS(4, 1); rh ^= KS(4, 2); rl ^= KS(4, 3)
    return b"".join(x.to_bytes(4, "big") for x in (rh, rl, lh, ll))


def crypt_block(block16: bytes, key: bytes, decrypt: bool = False) -> bytes:
    return encrypt_block(block16, CamelliaKey(key, forward=not decrypt))


def set_key(key: bytes, forward: bool = True) -> CamelliaKey:
    return CamelliaKey(key, forward)


def _load_vectors():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "cryptopp_src", "test_camellia.txt")
    txt = open(path, encoding="utf-8", errors="replace").read()
    out = []
    for m in re.finditer(
            r"Key:\s+([0-9A-Fa-f ]+)\s*\n\s*Plaintext:\s+([0-9A-Fa-f ]+)\s*\n\s*Ciphertext:\s+([0-9A-Fa-f ]+)",
            txt):
        out.append(tuple(bytes.fromhex(g.replace(" ", "")) for g in m.groups()))
    return out


def self_test(verbose: bool = True) -> bool:
    vec = _load_vectors()
    if not vec:
        if verbose:
            print("[FAIL] Camellia: test vektoru okunamadi")
        return False
    ok = 0
    for k, p, c in vec:
        if crypt_block(p, k).hex().upper() == c.hex().upper():
            ok += 1
        elif verbose:
            print("  FARK k=%s\n   bekl=%s\n   alin=%s"
                  % (k.hex().upper(), c.hex().upper(), crypt_block(p, k).hex().upper()))
    good = ok == len(vec)
    if verbose:
        print("[%s] Camellia NESSIE: %d/%d" % ("OK " if good else "FAIL", ok, len(vec)))

    k = bytes(range(16))
    blk = bytes(range(16))
    rt = crypt_block(crypt_block(blk, k), k, decrypt=True) == blk
    if verbose:
        print("[%s] Camellia tur geri-donusumu" % ("OK " if rt else "FAIL"))
    return bool(good and rt)


if __name__ == "__main__":
    import sys
    sys.exit(0 if self_test() else 1)
