"""SKIPJACK block operation matching Crypto++ byte/key order.
Adapted from Crypto++ skipjack.cpp (public-domain implementation lineage).
Source: https://github.com/weidai11/cryptopp/blob/master/skipjack.cpp
The live selector table, not this reference, establishes game protocol use.
"""
import struct
F=bytes.fromhex('a3d70983f848f6f4b321157899b1aff9e72d4d8ace4cca2e5295d91e4e3844280adf02a017f1606812b77ac3e9fa3d5396846bbaf2639a197caee5f5f7166aa239b67b0fc193811beeb41aead0912fb855b9da853f41bfe05a58805f660bd89035d5c0a733066569450094566d989b7697fcb2c2b0fedb20e1ebd6e4dd474a1d42ed9e6e493ccd4327d207d4dec7671889cb301f8dc68faac874dcc95d5c31a47088612c9f0d2b8750825464267d0340344b1c73d1c4fd3bccfb7fabe63e5ba5ad04239c145122f02979717eff8c0ee20cefbc72756f37a1ecd38e628b8610e8087711be924f24c532369dcff3a6bbac5e6ca9135725b5e3bda83a0105592a46')

def crypt(key, block, decrypt=False):
    if len(key)!=10 or len(block)!=8:
        raise ValueError('SKIPJACK needs a 10-byte key and an 8-byte block')
    reverse_key=key[::-1]
    def g(word,round_no,inverse=False):
        for j in (range(3,-1,-1) if inverse else range(4)):
            k=reverse_key[(4*(round_no-1)+j)%10]
            if j%2==0:word ^= F[(word&255)^k]<<8
            else:word ^= F[(word>>8)^k]
        return word
    w=list(struct.unpack('<4H',block))[::-1]
    for round_no in (range(32,0,-1) if decrypt else range(1,33)):
        i=(1-round_no)%4
        rule_a=round_no<=8 or 17<=round_no<=24
        if not decrypt:
            if rule_a:
                w[i]=g(w[i],round_no);w[(i-1)%4]^=w[i]^round_no
            else:
                w[(i+1)%4]^=w[i]^round_no;w[i]=g(w[i],round_no)
        else:
            if rule_a:
                w[(i-1)%4]^=w[i]^round_no;w[i]=g(w[i],round_no,True)
            else:
                w[i]=g(w[i],round_no,True);w[(i+1)%4]^=w[i]^round_no
    return struct.pack('<4H',*w[::-1])
