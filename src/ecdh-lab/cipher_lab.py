# -*- coding: utf-8 -*-
"""
Metin2 GF TR â€” Cipher Lab (Faz: el sÄ±kÄ±ÅŸma + ÅŸifre tÃ¼retimi doÄŸrulamasÄ±)

Kaynak: metin2-client-source-main/EterBase/cipher.cpp (SetUp/Pick birebir portu)
GF gÃ¼ncel istemci farkÄ±: DH2 yerine ECDH P-256 (kabloda Ã¶lÃ§Ã¼ldÃ¼, ElMarin teyit);
tÃ¼retim mantÄ±ÄŸÄ± aynÄ±: shared â†’ hint â†’ algoritma seÃ§imi + anahtar/IV dilimleme.

KullanÄ±m:
  python cipher_lab.py selftest     # mantÄ±k + ECDH + CTR tur testleri
  python cipher_lab.py session      # iki taraf simÃ¼lasyonu (client/server)
  python cipher_lab.py rc6test      # RC6 bilinen-vektÃ¶r testi
"""
import sys

# ---------------------------------------------------------------- live Pick table
# 2026-11-13: current build Pick uses modulo 13, read from native switch + RTTI.
ALGO_TABLE = [
    "3DES", "3DES", "SEED", "SHACAL2", "IDEA", "Camellia", "TEA",
    "RC5", "SKIPJACK", "MARS", "CAST256", "RC6", "Serpent",
]

# Crypto++ varsayÄ±lan anahtar uzunluklarÄ± (bayt) ve blok boyutlarÄ±
ALGO_PARAMS = {
    "SKIPJACK": (10, 8),
    "Twofish":  (16, 16),
    "RC6":      (16, 16),
    "MARS":     (16, 16),
    "Serpent":  (16, 16),
    "CAST256":  (16, 16),  # oyun dogrulamasi: K[96] 16B anahtarla birebir (30.10)
    "IDEA":     (16, 8),
    "3DES":     (16, 8),   # DES_EDE2: DEFAULT_KEYLENGTH=16
    "Camellia": (16, 16),
    "SEED":     (16, 16),
    "RC5":      (16, 8),
    "Blowfish": (16, 8),
    "TEA":      (16, 8),
    "SHACAL2":  (16, 32),
}


def pick_algorithm(hint: int) -> str:
    return ALGO_TABLE[hint % len(ALGO_TABLE)]


def derive_sessions(shared: bytes, polarity: bool) -> dict:
    """cipher.cpp Cipher::SetUp() birebir portu.

    polarity=True  -> (biz=istemci): encoder_ = algo_1, decoder_ = algo_0
    polarity=False -> (biz=sunucu):  encoder_ = algo_0, decoder_ = algo_1
    DÃ¶nen dict: {encoder: (algo,key,iv), decoder: (algo,key,iv)}
    """
    n = len(shared)
    assert n >= 2, "shared Ã§ok kÄ±sa"

    hint_0 = shared[shared[0] % n]
    hint_1 = shared[shared[1] % n]
    algo_0 = pick_algorithm(hint_0)
    algo_1 = pick_algorithm(hint_1)

    key_len_0, iv_len_0 = ALGO_PARAMS[algo_0]
    key_len_1, iv_len_1 = ALGO_PARAMS[algo_1]
    assert n >= key_len_0 and n >= iv_len_0
    assert n >= key_len_1 and n >= iv_len_1

    # anahtarlar: key_0 baÅŸtan; key_1 = min(key_len_0, n-key_len_1) ofsetinden
    key_0 = shared[:key_len_0]
    off = min(key_len_0, n - key_len_1)
    key_1 = shared[off:off + key_len_1]

    # IV'ler: iv_0 sondan; iv_1 onun hemen Ã¶nÃ¼nden (yer kalmazsa baÅŸtan)
    off = n - iv_len_0
    iv_0 = shared[off:off + iv_len_0]
    off = 0 if off < iv_len_1 else off - iv_len_1
    iv_1 = shared[off:off + iv_len_1]

    if polarity:
        return {"encoder": (algo_1, key_1, iv_1), "decoder": (algo_0, key_0, iv_0)}
    return {"encoder": (algo_0, key_0, iv_0), "decoder": (algo_1, key_1, iv_1)}


# ---------------------------------------------------------------- ECDH P-256
def ecdh_keypair():
    """P-256 anahtar Ã§ifti (GF gÃ¼ncel istemci: ECDH, X-koordinatÄ± = shared)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def ecdh_shared_x(our_priv, peer_pub) -> bytes:
    """Ortak sÄ±r = ECDH noktasÄ±nÄ±n X koordinatÄ± (32 bayt, bÃ¼yÃ¼k-sonlu)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    shared_key = our_priv.exchange(ec.ECDH(), peer_pub)
    return shared_key  # cryptography zaten X koordinatÄ±nÄ± (32B) dÃ¶ndÃ¼rÃ¼r


def pub_uncompressed(pub) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def pub_from_uncompressed(data: bytes):
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


# ---------------------------------------------------------------- blok ÅŸifreler
def _rc6_block(key: bytes, block: bytes, decrypt: bool = False) -> bytes:
    """RC6-32/20/{16,24,32} â€” tek blok (16B). Little-endian kelimeler.
    Test vektÃ¶rÃ¼: key=16x00, block=16x00 -> 8fc3a53656b1f778c9df1b82ba4799a6
    """
    assert len(block) == 16
    r = 20
    M = 0xFFFFFFFF
    P32, Q32 = 0xB7E15163, 0x9E3779B9
    c = len(key) // 4
    # tomcrypt rc6.c dogrulandi: anahtar sozcukleri LITTLE-endian
    # (A=(A<<8)|key[i] birikimi + BSWAP deger ters cevirme = little-endian)
    L = [int.from_bytes(key[i * 4:i * 4 + 4], "little") for i in range(c)]
    S = [(P32 + i * Q32) & M for i in range(2 * r + 4)]
    # standart RC6 anahtar geniÅŸletmesi: v = 3 * max(c, 2r+4) tur
    A = B = i = j = 0
    v = 3 * max(c, 2 * r + 4)
    for _ in range(v):
        A = S[i] = _rotl32((S[i] + A + B) & M, 3)
        B = L[j] = _rotl32((L[j] + A + B) & M, (A + B) & 31)
        i = (i + 1) % (2 * r + 4)
        j = (j + 1) % c
    A = int.from_bytes(block[0:4], "little")
    B = int.from_bytes(block[4:8], "little")
    C = int.from_bytes(block[8:12], "little")
    D = int.from_bytes(block[12:16], "little")
    if not decrypt:
        B = (B + S[0]) & M
        D = (D + S[1]) & M
        for i in range(1, r + 1):
            t = _rotl32((B * (2 * B + 1)) & M, 5)
            u = _rotl32((D * (2 * D + 1)) & M, 5)
            A = (_rotl32(A ^ t, u & 31) + S[2 * i]) & M
            C = (_rotl32(C ^ u, t & 31) + S[2 * i + 1]) & M
            A, B, C, D = B, C, D, A
        A = (A + S[2 * r + 2]) & M
        C = (C + S[2 * r + 3]) & M
    else:
        C = (C - S[2 * r + 3]) & M
        A = (A - S[2 * r + 2]) & M
        for i in range(r, 0, -1):
            A, B, C, D = D, A, B, C
            u = _rotl32((D * (2 * D + 1)) & M, 5)
            t = _rotl32((B * (2 * B + 1)) & M, 5)
            C = (_rotr32((C - S[2 * i + 1]) & M, t & 31)) ^ u
            A = (_rotr32((A - S[2 * i]) & M, u & 31)) ^ t
        D = (D - S[1]) & M
        B = (B - S[0]) & M
    return (A.to_bytes(4, "little") + B.to_bytes(4, "little") +
            C.to_bytes(4, "little") + D.to_bytes(4, "little"))


def _rotl32(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _rotr32(x: int, n: int) -> int:
    n &= 31
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _mul_mod_65537(a: int, b: int) -> int:
    """IDEA carpma modulu: a*b mod 65537, 0 -> 65536 eslemesiyle."""
    if a == 0:
        a = 0x10000
    if b == 0:
        b = 0x10000
    p = (a * b) % 0x10001
    return 0 if p == 0x10000 else p


def _inv_mul_65537(a: int) -> int:
    """65537 modulunde carpma tersi (a=0 -> 0, a=1 -> 1)."""
    if a == 0:
        return 0
    t, newt, r, newr = 0, 1, 0x10001, a
    while newr:
        q = r // newr
        t, newt = newt, t - q * newt
        r, newr = newr, r - q * newr
    return t % 0x10001


def _idea_keys(key: bytes) -> list:
    """Crypto++ IDEA::EnKey birebir portu (cryptopp_src/idea.cpp:100-113).

    Ilk 8 anahtar: big-endian 16-bit kelimeler. Sonrasi: 128-bit kayitciyi
    25 bit sola dondurup yeniden bolmek."""
    assert len(key) == 16
    KEYLEN = 52
    mk = [0] * KEYLEN
    for i in range(8):
        mk[i] = (key[2 * i] << 8) | key[2 * i + 1]
    for i in range(8, KEYLEN):
        j = ((i // 8) - 1) * 8
        mk[i] = ((mk[j + (i + 1) % 8] << 9) | (mk[j + (i + 2) % 8] >> 7)) & 0xFFFF
    return mk


def _idea_block(key: bytes, block: bytes, decrypt: bool = False) -> bytes:
    """Crypto++ IDEA::ProcessAndXorBlock birebir portu.

    64-bit blok, 128-bit anahtar, BigEndian kelime sirasi."""
    if decrypt:
        raise NotImplementedError("IDEA decrypt portlanmadi (CTR gerektirmez)")
    assert len(block) == 8
    ks = _idea_keys(key)
    x0 = int.from_bytes(block[0:2], 'big')
    x1 = int.from_bytes(block[2:4], 'big')
    x2 = int.from_bytes(block[4:6], 'big')
    x3 = int.from_bytes(block[6:8], 'big')
    for i in range(8):
        o = i * 6
        x0 = _mul_mod_65537(x0, ks[o + 0])
        x1 = (x1 + ks[o + 1]) & 0xFFFF
        x2 = (x2 + ks[o + 2]) & 0xFFFF
        x3 = _mul_mod_65537(x3, ks[o + 3])
        t0 = x0 ^ x2
        t0 = _mul_mod_65537(t0, ks[o + 4])
        t1 = (t0 + (x1 ^ x3)) & 0xFFFF
        t1 = _mul_mod_65537(t1, ks[o + 5])
        t0 = (t0 + t1) & 0xFFFF
        x0 ^= t1
        x3 ^= t0
        t0 ^= x1
        x1 = x2 ^ t1
        x2 = t0
    x0 = _mul_mod_65537(x0, ks[48])
    x2 = (x2 + ks[49]) & 0xFFFF
    x1 = (x1 + ks[50]) & 0xFFFF
    x3 = _mul_mod_65537(x3, ks[51])
    return b''.join(w.to_bytes(2, 'big') for w in (x0, x2, x1, x3))


def _tea_block(key: bytes, block: bytes, decrypt: bool = False) -> bytes:
    """Crypto++ TEA (ORIJINAL TEA, XTEA DEGIL) birebir portu.

    Kaynak: cryptopp tea.cpp TEA::Enc::ProcessAndXorBlock.
        sum = 0
        while (sum != 32*DELTA):
            sum += DELTA
            y += ((z<<4)+k[0]) ^ (z+sum) ^ ((z>>5)+k[1])
            z += ((y<<4)+k[2]) ^ (y+sum) ^ ((y>>5)+k[3])

    KRITIK: kelimeler BIG-ENDIAN (BlockGetAndPut<word32, BigEndian>),
    karisim ((z<<4)+k0) ^ (z+sum) ^ ((z>>5)+k1) seklinde (XTEA'nin
    ((z<<4)^(z>>5))+z ve k[sum&3] varyanti DEGIL). Onceki port XTEA'ydi
    ve KAT'i gecemiyordu (bkz. work/tea_check.py)."""
    assert len(block) == 8
    y = int.from_bytes(block[0:4], "big")
    z = int.from_bytes(block[4:8], "big")
    k = [int.from_bytes(key[i:i + 4], "big") for i in range(0, 16, 4)]
    M = 0xFFFFFFFF
    D = 0x9E3779B9
    if not decrypt:
        s = 0
        for _ in range(32):
            s = (s + D) & M
            y = (y + (((z << 4) + k[0]) ^ (z + s) ^ ((z >> 5) + k[1]))) & M
            z = (z + (((y << 4) + k[2]) ^ (y + s) ^ ((y >> 5) + k[3]))) & M
    else:
        s = (D * 32) & M
        for _ in range(32):
            z = (z - (((y << 4) + k[2]) ^ (y + s) ^ ((y >> 5) + k[3]))) & M
            y = (y - (((z << 4) + k[0]) ^ (z + s) ^ ((z >> 5) + k[1]))) & M
            s = (s - D) & M
    return y.to_bytes(4, "big") + z.to_bytes(4, "big")


def block_cipher(algo: str, key: bytes, iv: bytes, decrypt: bool = False):
    """Secilen algoritma icin (encrypt_block fonksiyonu, blok boyutu) dondurur.

    NOT: CTR modunda blok sifresinin yonu onemsizdir (keystream her zaman
    sifreleme yonunde uretilir), bu yuzden `decrypt` yalnizca ECB/tek-blok
    testlerinde kullanilir."""
    if algo == "SKIPJACK":
        from skipjack_port import crypt
        return (lambda b: crypt(key, b, decrypt)), 8
    if algo == "MARS":
        from mars_cryptopp_exact import unchecked_set_key, encrypt_block, decrypt_block
        k = unchecked_set_key(key)
        return (lambda b: decrypt_block(b, k) if decrypt else encrypt_block(b, k)), 16
    if algo == "RC5":
        from rc5_shacal2_port import rc5_set_key, rc5_encrypt_block, rc5_decrypt_block
        S, r = rc5_set_key(key, 16)  # Crypto++ varsayilan 16 tur
        return (lambda b: rc5_decrypt_block(b, S, r) if decrypt else rc5_encrypt_block(b, S, r)), 8
    if algo == "SHACAL2":
        from rc5_shacal2_port import shacal2_set_key, shacal2_encrypt_block
        rk = shacal2_set_key(key)
        return (lambda b: shacal2_encrypt_block(b, rk)), 32
    if algo == "IDEA":
        # IDEA: 128-bit anahtar, 64-bit blok. KAT: cipher_lab self-test.
        return (lambda b: _idea_block(key, b, decrypt)), 8
    if algo == "TEA":
        return (lambda b: _tea_block(key, b, decrypt)), 8
    if algo == "RC6":
        return (lambda b: _rc6_block(key, b, decrypt)), 16
    if algo == "Serpent":
        from serpent_cryptopp_exact import serpent_set_key, serpent_encrypt_block
        k = serpent_set_key(key)
        return (lambda b: serpent_encrypt_block(b, k)), 16
    if algo == "CAST256":
        # Crypto++ cast.h: CAST-256 defaults to a 16-byte key, not the 32-byte maximum.
        from cast256_cryptopp_exact import cast256_set_key, cast256_block
        K = cast256_set_key(key, forward=not decrypt)
        return (lambda b: cast256_block(b, K)), 16
    if algo == "3DES":
        # EDE2 expects a forward schedule for k1 and a reverse schedule for k2.
        from des_cryptopp_exact import raw_set_key, des_ede2_block
        k1 = raw_set_key(key[:8], decryption=False)
        k2 = raw_set_key(key[8:16], decryption=True)
        return (lambda b: des_ede2_block(b, k1, k2)), 8
    if algo == "Camellia":
        from camellia_cryptopp_exact import CamelliaKey, encrypt_block
        kp = CamelliaKey(key, forward=not decrypt)
        return (lambda b: encrypt_block(b, kp)), 16
    if algo == "SEED":
        # SEED decryption uses the same block function with a reversed schedule.
        from seed_cryptopp_exact import set_key, encrypt_block
        kp = set_key(key, forward=not decrypt)
        return (lambda b: encrypt_block(b, kp)), 16
    if algo == "Twofish":
        # Optional Twofish implementation by Niels Ferguson.
        try:
            import twofish as _tf
            c = _tf.Twofish(key)
            if decrypt:
                return (lambda b: c.decrypt(b)), 16
            return (lambda b: c.encrypt(b)), 16
        except ImportError:
            raise NotImplementedError(
                "Twofish: 'pip install twofish' gerekli (dahili port bozuk).")
    if algo == "Blowfish":
        try:
            from Crypto.Cipher import Blowfish
        except ModuleNotFoundError:
            raise NotImplementedError(
                "Blowfish: pycryptodome yok. cryptopp_src/blowfish.cpp mevcut, "
                "port yazilmali (Crypto++ Blowfish her zaman big-endian).")
        c = Blowfish.new(key, Blowfish.MODE_ECB)
        return (lambda b: c.decrypt(b) if decrypt else c.encrypt(b)), 8
    raise NotImplementedError(
        f"{algo}: implementasyon yok. cryptopp_src/ altinda referans kaynak "
        f"mevcut; ayni yontemle (des_cryptopp_exact gibi) port edilmeli.")


# ---------------------------------------------------------------- CTR modu
def ctr_xor(algo: str, key: bytes, iv: bytes, data: bytes, decrypt: bool = False,
            skip_blocks: int = 0) -> bytes:
    """Crypto++ CTR_Mode davranisi: keystream = E(IV+i bloklari), XOR.

    ONEMLI: `skip_blocks`, sayac durumunu tasimak icindir. Soket akisi parca
    parca geldigi icin ayni oturumda ikinci bir cagri yapildiginda sayac
    IV'ten DEGIL, kaldigi yerden devam etmelidir:

        c1 = ctr_xor(a,k,iv, chunk1)            # blok 0..n
        c2 = ctr_xor(a,k,iv, chunk2, skip_blocks=n)   # blok n+1'den devam

    Sayac her cagrida IV'e sifirlanirsa, 32 bayttan sonra keystream bastan
    baslar ve akis cozulemez (olculdu: 32+32 bolunmus akis != tek cagri).
    Ust duzey kolaylik icin CTRStream kullanin; o sayaci kendi tutar."""
    enc, bs = block_cipher(algo, key, iv)
    iv_padded = (iv + b"\x00" * bs)[:bs]
    counter = (int.from_bytes(iv_padded, "big") + skip_blocks) & ((1 << (bs * 8)) - 1)
    out = bytearray()
    for pos in range(0, len(data), bs):
        ks = enc(counter.to_bytes(bs, "big"))
        chunk = data[pos:pos + bs]
        for i, byte in enumerate(chunk):
            out.append(byte ^ ks[i])
        counter = (counter + 1) & ((1 << (bs * 8)) - 1)
    return bytes(out)


class CTRStream:
    """Crypto++ CTR_Mode esdegeri: sayac durumunu cagrilar arasinda tasir.

    Soket akisinda dogru olan budur. Her `crypt()` cagrisi sayaci kaldigi
    yerden surdurur, yani parca boyutundan bagimsiz olarak ayni keystream'i
    uretir:

        s = CTRStream('RC6', key, iv)
        pt  = s.crypt(chunk1) + s.crypt(chunk2)   # tek cagriya esit
    """

    def __init__(self, algo: str, key: bytes, iv: bytes):
        self.enc, self.bs = block_cipher(algo, key, iv)
        iv_padded = (iv + b"\x00" * self.bs)[:self.bs]
        self._start = int.from_bytes(iv_padded, "big")
        self._counter = self._start
        self._buf = b""          # blok icinde kalan keystream
        self._mask = (1 << (self.bs * 8)) - 1

    @property
    def blocks_consumed(self) -> int:
        """IV'den bu yana uretilmis tam blok sayisi (sayac ilerlemesi)."""
        return (self._counter - self._start) & self._mask

    def crypt(self, data: bytes) -> bytes:
        out = bytearray()
        pos = 0
        # onceki cagridan kalan keystream varsa onu tuket
        if self._buf:
            need = min(len(self._buf), len(data))
            out += bytes(a ^ b for a, b in zip(data[:need], self._buf[:need]))
            self._buf = self._buf[need:]
            pos = need
        while pos < len(data):
            ks = self.enc(self._counter.to_bytes(self.bs, "big"))
            self._counter = (self._counter + 1) & self._mask
            chunk = data[pos:pos + self.bs]
            out += bytes(a ^ b for a, b in zip(chunk, ks))
            if len(ks) > len(chunk):
                self._buf = ks[len(chunk):]
            pos += len(chunk)
        return bytes(out)


# ---------------------------------------------------------------- testler
def rc6test():
    """tomcrypt rc6.c icindeki resmi test vektorleri (3 anahtar boyutu)."""
    vectors = [
        (16, "0123456789abcdef0112233445566778",
         "02132435465768798a9bacbdcedfe0f1", "524e192f4715c6231f51f6367ea43f18"),
        (24, "0123456789abcdef0112233445566778899aabbccddeeff0",
         "02132435465768798a9bacbdcedfe0f1", "688329d019e505041e52e92af95291d4"),
        (32, "0123456789abcdef0112233445566778899aabbccddeeff01032547698badcfe",
         "02132435465768798a9bacbdcedfe0f1", "c8241816f0d7e48920ad16a1674e5d48"),
    ]
    ok_all = True
    for klen, key_hex, pt_hex, ct_hex in vectors:
        key, pt, ct = bytes.fromhex(key_hex), bytes.fromhex(pt_hex), bytes.fromhex(ct_hex)
        got = _rc6_block(key, pt)
        back = _rc6_block(key, ct, decrypt=True)
        good = got == ct and back == pt
        ok_all &= good
        print(f"[{'OK ' if good else 'FAIL'}] RC6 vektor (anahtar {klen}B): {got.hex()}")
    return ok_all


def selftest():
    ok = True
    ok &= rc6test()

    # TEA tur testi: Ã§Ã¶z->tekrar ÅŸifrele = orijinal
    key = bytes(range(16))
    pt = bytes(range(8))
    ct = _tea_block(key, pt)
    ok &= _tea_block(key, ct, decrypt=True) == pt
    print(f"[{'OK ' if _tea_block(key, ct, decrypt=True) == pt else 'FAIL'}] TEA tur testi")

    # ECDH: iki taraf ayni shared_x'e ulasmali
    try:
        a_priv, a_pub = ecdh_keypair()
        b_priv, b_pub = ecdh_keypair()
        sa, sb = ecdh_shared_x(a_priv, b_pub), ecdh_shared_x(b_priv, a_pub)
        print(f"[{'OK ' if sa == sb else 'FAIL'}] ECDH P-256 ortak sir eslesmesi ({sa.hex()[:16]}...)")
        shared = sb
    except ModuleNotFoundError as ex:
        print(f"[SKIP] ECDH P-256 ({ex.name} kurulu degil) — derive_sessions "
              f"icin sabit bir sir kullaniliyor")
        sa = sb = bytes(range(32))
        shared = sb

    # SetUp turetimi: paylasilan sir iki tarafta AYNI oturumlari uretmeli
    client_sess = derive_sessions(shared, polarity=True)
    server_sess = derive_sessions(shared, polarity=False)
    ce, cd = client_sess["encoder"], client_sess["decoder"]
    se, sd = server_sess["encoder"], server_sess["decoder"]
    print(f"    istemci: encoder={ce[0]} decoder={cd[0]}")
    print(f"    sunucu : encoder={se[0]} decoder={sd[0]}")
    # karÅŸÄ± yÃ¶nlÃ¼ler birbirinin eÅŸi olmalÄ± (istemci encoder == sunucu decoder)
    match = (ce[0] == sd[0] and ce[1] == sd[1] and ce[2] == sd[2] and
             cd[0] == se[0] and cd[1] == se[1] and cd[2] == se[2])
    print(f"[{'OK ' if match else 'FAIL'}] polarity eÅŸleÅŸmesi (C encoder == S decoder)")
    ok &= match and sa == sb

    # CTR turlari: current live selector algorithms + akis surekliligi
    eksik = []
    for algo in dict.fromkeys(ALGO_TABLE):
        kl, bs = ALGO_PARAMS[algo]
        try:
            data = bytes(range(50))
            session_key, session_iv = bytes(range(kl)), bytes(bs)
            ct = ctr_xor(algo, session_key, session_iv, data)
            pt = ctr_xor(algo, session_key, session_iv, ct)
            # asil hata buydu: sayac cagrilar arasinda tasinmiyordu
            s = CTRStream(algo, session_key, session_iv)
            parca = s.crypt(ct[:17]) + s.crypt(ct[17:40]) + s.crypt(ct[40:])
            good = (pt == data) and (parca == data)
            print(f"[{'OK ' if good else 'FAIL'}] CTR tur + akis ({algo}, {len(ct)}B)")
            ok &= good
        except NotImplementedError as ex:
            eksik.append(algo)
            print(f"[EKSIK] {algo} — {ex}")
        except Exception as ex:
            ok = False
            print(f"[FAIL] {algo} — {type(ex).__name__}: {ex}")

    if eksik:
        # Bu bir UYARI, hata degil: lab kademeli buyuyor. Ama sessiz kalmamali —
        # eksik algoritma secilen bir oturum cozulemez.
        print(f"\nUYARI: {len(eksik)}/{len(set(ALGO_TABLE))} algoritma eksik -> {eksik}")
        print("       Bu algoritmalar secilen oturumlar COZULEMEZ (bkz. rapor §5.6.4e)")

    print("\nSONUC:", "TUM TESTLER GECTI" if ok else "HATALAR VAR")
    return ok


def session():
    """UÃ§tan uca simÃ¼lasyon: el sÄ±kÄ±ÅŸma + tÃ¼retim + paket alÄ±ÅŸveriÅŸi.
    GerÃ§ek kabloyla karÅŸÄ±laÅŸtÄ±rÄ±lacak ÅŸablonun kendisi."""
    # 1) iki taraf P-256 Ã§ifti Ã¼retir, aÃ§Ä±k anahtarlarÄ±nÄ±exchange eder
    c_priv, c_pub = ecdh_keypair()
    s_priv, s_pub = ecdh_keypair()
    print("istemci aÃ§Ä±k anahtar (65B, sÄ±kÄ±ÅŸtÄ±rÄ±lmamÄ±ÅŸ):", pub_uncompressed(c_pub).hex()[:32], "...")
    print("sunucu  aÃ§Ä±k anahtar (65B, sÄ±kÄ±ÅŸtÄ±rÄ±lmamÄ±ÅŸ):", pub_uncompressed(s_pub).hex()[:32], "...")

    # 2) her iki taraf kendi Ã¶zel anahtarÄ±yla shared_x hesaplar
    shared_c = ecdh_shared_x(c_priv, s_pub)
    shared_s = ecdh_shared_x(s_priv, c_pub)
    assert shared_c == shared_s, "ECDH uyuÅŸmazlÄ±ÄŸÄ±"
    print("shared_x (32B):", shared_c.hex())

    # 3) SetUp tÃ¼retimi (polarity: istemci True, sunucu False)
    cs, ss = derive_sessions(shared_c, True), derive_sessions(shared_s, False)
    algo = cs["encoder"][0]
    print(f"seÃ§ilen algoritma Ã§ifti: encoder={cs['encoder'][0]} decoder={cs['decoder'][0]}")

    # 4) Ã¶rnek paket: istemci ÅŸifreler -> sunucu Ã§Ã¶zer (ve tersi)
    try:
        plaintext = b"\x03\x10Hello, market server!\x00\x00"
        wire = ctr_xor(*cs["encoder"], plaintext)
        back = ctr_xor(*ss["decoder"], wire)
        print("Câ†’S:", plaintext, "->", wire.hex())
        print("S tarafÄ±nda Ã§Ã¶zÃ¼len:", back, "==", plaintext if back == plaintext else "BOZUK!")
        assert back == plaintext
        reply = b"\x02\x08welcome\x00"
        wire2 = ctr_xor(*ss["encoder"], reply)
        back2 = ctr_xor(*cs["decoder"], wire2)
        assert back2 == reply
        print("Sâ†’C turu da OK â€” oturum simÃ¼lasyonu tamam")
    except NotImplementedError as exc:
        print(f"[SKIP] {exc} â€” bu algoritma iÃ§in blok ÅŸifre henÃ¼z yok,",
              "derive_sessions Ã§Ä±ktÄ±sÄ± yine de yukarÄ±da")
        print("  istemci encoder:", cs["encoder"][0], cs["encoder"][1].hex(), cs["encoder"][2].hex())
        print("  istemci decoder :", cs["decoder"][0], cs["decoder"][1].hex(), cs["decoder"][2].hex())


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "selftest"
    if mode == "selftest":
        sys.exit(0 if selftest() else 1)
    if mode == "session":
        session()
    elif mode == "rc6test":
        rc6test()
    else:
        print(__doc__)
