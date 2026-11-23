
# -*- coding: utf-8 -*-
"""MT2 TR Clientless v2 — tam oturum: 11151 -> 12105 -> 12102."""

import argparse
import json
import os
import random
import socket
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'ecdh-lab'))

from cipher_lab import (
    CTRStream, ALGO_PARAMS, ecdh_keypair, ecdh_shared_x,
    pub_uncompressed, pub_from_uncompressed
)

# Charon auth sunucusu; baska sunucu icin degistirin veya MT2_AUTH_HOST verin.
AUTH_HOST = os.environ.get('MT2_AUTH_HOST', '79.110.92.149')
AUTH_PORT = 11151
LOGIN_PORT = 12105
GAME_PORT = 12102

CAND_ALGOS = [
    'CAST256', 'Serpent', 'RC6', 'MARS', '3DES',
    'Camellia', 'SEED', 'Blowfish', 'RC5', 'TEA', 'SHACAL2'
]

HS_SRV_MAGIC_OFF = 19


def log(msg):
    print('[%s] %s' % (time.strftime('%H:%M:%S'), msg))


class ProtocolError(Exception):
    pass


def recv_exact(sock, n, timeout=10.0):
    buf = b''
    sock.settimeout(timeout)

    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(
                'baglanti kapandi (%d/%d)' % (len(buf), n)
            )
        buf += chunk

    return buf


def recv_some(sock, timeout=10.0):
    sock.settimeout(timeout)
    return sock.recv(65536)


# ----------------------------------------------------------------
# El sikisma
# ----------------------------------------------------------------

try:
    from .fd_bodies import _11151_BODY, _12105_BODY, _12102_BODY
except ImportError:
    from fd_bodies import _11151_BODY, _12105_BODY, _12102_BODY

FD_BODIES = {
    11151: _11151_BODY,
    12105: _12105_BODY,
    12102: _12102_BODY
}


def build_handshake_reply(server_handshake: bytes, port: int) -> bytes:
    """527B sunucu -> 525B istemci yaniti."""

    assert len(server_handshake) == 527, len(server_handshake)
    assert server_handshake[2] == 0xfd, 'fd bekleniyordu'

    nonce = server_handshake[3:10]
    type_byte = server_handshake[10]

    body = bytes([type_byte]) + FD_BODIES[port][1:]
    pkt = b'\xfd' + nonce + body

    assert len(pkt) == 525, len(pkt)
    return pkt


def do_handshake(sock, port):
    hs = recv_exact(sock, 527)

    if hs[:2] != b'\xff\x01':
        raise ProtocolError(
            'el sikisma bekleniyordu: %s' % hs[:4].hex()
        )

    sock.sendall(build_handshake_reply(hs, port))
    return hs


# ----------------------------------------------------------------
# Anahtar anlasmasi
# ----------------------------------------------------------------

def build_ka_reply(our_pub) -> bytes:
    pub = pub_uncompressed(our_pub)

    pkt = (
        b'\xfb'
        + struct.pack('<H', 32)
        + struct.pack('<H', 65)
        + pub
        + b'\x00' * 191
    )

    assert len(pkt) == 261
    return pkt


def do_key_agreement(sock, timeout=10.0):
    """Sunucunun FB paketini bekler, ECDH yanitini gonderir."""

    deadline = time.time() + timeout
    buf = b''

    def _have_ka(data):
        i = data.find(b'\xfb')
        return i >= 0 and len(data) >= i + 261

    # FB + 261 baytlik paket gelene kadar oku.
    while not _have_ka(buf):

        if time.time() > deadline:
            print('\n[KA TIMEOUT DEBUG]')
            print('Buffered length:', len(buf))
            print('Buffered first 64:', buf[:64].hex(' '))
            print('FB position:', buf.find(b'\xfb'))

            raise ProtocolError(
                'ka zaman asimi: %s' % buf[:24].hex()
            )

        try:
            chunk = recv_some(
                sock,
                timeout=max(0.5, deadline - time.time())
            )
        except socket.timeout:
            continue

        if not chunk:
            raise ConnectionError('ka beklenirken koptu')

        print('\n[KA RAW RX]')
        print('Chunk length:', len(chunk))
        print('Chunk first 64:', chunk[:64].hex(' '))

        buf += chunk

        print('Total buffered:', len(buf))
        print('FB position:', buf.find(b'\xfb'))

    # Gelen verinin tanilamasi.
    print('\n[PRE-KA BUFFER]')
    print('Length:', len(buf))
    print('HEX:', buf[:600].hex(' '))

    print('\n[MARKER POSITIONS]')

    for marker in [b'\xfd', b'\xfa', b'\xfb', b'\x9f\x77']:
        positions = []
        pos = 0

        while True:
            pos = buf.find(marker, pos)

            if pos < 0:
                break

            positions.append(pos)
            pos += 1

        print(marker.hex(), positions)

    # KA paketini ayikla.
    ka_off = buf.find(b'\xfb')

    if ka_off < 0 or len(buf) < ka_off + 261:
        raise ProtocolError(
            'ka bulunamadi: %s' % buf[:16].hex()
        )

    ka_srv = buf[ka_off:ka_off + 261]
    srv_pub_point = ka_srv[5:70]

    if srv_pub_point[0] != 4:
        raise ProtocolError(
            'kamu noktasi 04 ile baslamiyor: %02x'
            % srv_pub_point[0]
        )

    # Kendi ECDH anahtarimizi uret ve yaniti gonder.
    our_priv, our_pub = ecdh_keypair()
    sock.sendall(build_ka_reply(our_pub))

    # KA sonrasindaki veriyi koru.
    rest = buf[ka_off + 261:]

    # FA cercevesini bekle.
    while len(rest) < 4:
        chunk = recv_some(sock)

        if not chunk:
            raise ConnectionError('fa beklenirken koptu')

        rest += chunk

    if rest[0] != 0xfa:
        raise ProtocolError(
            'fa bekleniyordu: %s' % rest[:6].hex()
        )

    fa_len = 4
    rest = rest[fa_len:]

    # Ilk sifreli paketin iki baytini bekle.
    while len(rest) < 2:
        chunk = recv_some(sock)

        if not chunk:
            raise ConnectionError(
                'ilk sifreli paket beklenirken koptu'
            )

        rest += chunk

    shared = ecdh_shared_x(
        our_priv,
        pub_from_uncompressed(srv_pub_point)
    )

    return shared, rest


# ----------------------------------------------------------------
# Sifreleme
# ----------------------------------------------------------------

def stream_from_triple(triple):
    """(algo, key, iv) -> CTRStream. derive_sessions cikisini dogrudan kullanir."""
    algo, key, iv = triple
    return CTRStream(algo, key, iv)


def make_streams(algo, shared):
    """ESKI YOL — SADECE iki yon de ayni algoritma oldugunda dogru.

    key_1 ofseti cipher.cpp'de key_length_0'a gore hesaplanir; burada
    ALGO_PARAMS[algo] kullanildigi icin algo_0 != algo_1 ise (ornek
    3DES decoder + CAST256 encoder) YANLIS dilim alinir.
    Yeni kod `stream_from_triple(derive_sessions(...)[...])` kullanmali.
    """
    klen, ivlen = ALGO_PARAMS[algo]
    n = len(shared)

    key_0 = shared[:klen]

    off = min(klen, n - klen)
    key_1 = shared[off:off + klen]

    off = n - ivlen
    iv_0 = shared[off:off + ivlen]

    off = 0 if off < ivlen else off - ivlen
    iv_1 = shared[off:off + ivlen]

    return (
        CTRStream(algo, key_0, iv_0),
        CTRStream(algo, key_1, iv_1)
    )


def make_encoder(shared, enc_algo=None):
    """encoder akisi — cipher.cpp SetUp() cikisindan birebir.

    cipher.cpp (polarity=True): algo_0 = decoder, algo_1 = encoder.
        key_1 = shared[min(key_len_0, n - key_len_1)]  (+key_len_1)
        iv_0  = shared[n - iv_len_0 : ]
        iv_1  = shared[0 if (n-iv_len_0) < iv_len_1 else n-iv_len_0-iv_len_1 : ]

    `make_streams` iki yonun key/IV uzunlugunu AYNI varsayar; decoder=3DES
    (iv 8) + encoder=CAST256 (iv 16) gibi durumda yanlis dilim alir.

    enc_algo=None -> turetilen encoder. Verilirse (aday denemesi) ayni
    ofsetlerle o aday icin kurulur.
    """
    from cipher_lab import derive_sessions, ALGO_PARAMS as _AP

    der = derive_sessions(shared, True)
    algo_1, key_1, iv_1 = der['encoder']
    if enc_algo is not None and enc_algo != algo_1:
        algo_0 = der['decoder'][0]
        klen_1, ivlen_1 = _AP[enc_algo]
        klen_0, ivlen_0 = _AP[algo_0]
        n = len(shared)
        key_1 = shared[min(klen_0, n - klen_1):][:klen_1]
        off = n - ivlen_0
        off = 0 if off < ivlen_1 else off - ivlen_1
        iv_1 = shared[off:off + ivlen_1]
        algo_1 = enc_algo
    return CTRStream(algo_1, key_1, iv_1)


def derive_streams(shared, polarity=True):
    from cipher_lab import derive_sessions

    der = derive_sessions(shared, polarity=polarity)

    dec_algo, dec_key, dec_iv = der['decoder']
    enc_algo, enc_key, enc_iv = der['encoder']

    dec = CTRStream(dec_algo, dec_key, dec_iv)
    enc = CTRStream(enc_algo, enc_key, enc_iv)

    return dec_algo, dec, enc_algo, enc


def detect_decoder(shared, first_enc_bytes):
    dec_algo, dec, _, _ = derive_streams(
        shared,
        polarity=True
    )
    return dec_algo, dec


# ----------------------------------------------------------------
# 1051B login
# ----------------------------------------------------------------

JSON_OFF_1051 = 789
TOTAL_1051 = 1051


def build_login_1051(ticket_json: bytes, client_key: bytes = b'',
                     prefix=None, tail=None) -> bytes:
    room = TOTAL_1051 - JSON_OFF_1051

    if len(ticket_json) > room:
        raise ValueError(
            'JSON 1051B alanini asti: %d > %d'
            % (len(ticket_json), room)
        )

    if prefix is None:
        pre = b'\x00' * JSON_OFF_1051
    else:
        pre = bytes(prefix)
        if len(pre) != JSON_OFF_1051:
            raise ValueError('onek 789B olmali: %d' % len(pre))

    need = room - len(ticket_json)
    if tail is None:
        t = b''
    else:
        t = bytes(tail)[:need]
    t = t + b'\x00' * (need - len(t))

    pkt = pre + ticket_json + t

    assert len(pkt) == TOTAL_1051
    return pkt



def build_login_1051_native(ticket_json: bytes, opaque_tail: bytes, variant=1) -> bytes:
    if len(opaque_tail) != 21:
        raise ValueError('native login requires the complete opaque 21-byte tail')
    if variant != 1:
        raise ValueError('only variant 1 was measured')
    obj = json.loads(ticket_json.decode('ascii'))
    if not isinstance(obj, dict):
        raise ValueError('ticket JSON must be an object')
    auth_text = ticket_json.hex().encode('ascii').hex().encode('ascii')
    if len(auth_text) > 1024:
        raise ValueError('double-hex ticket exceeds the native 1024-character field capacity')
    return b'\x61' + struct.pack('<I', variant) + auth_text.ljust(1025, b'\x00') + bytes(opaque_tail)



def build_login_1051_fields(ticket_json: bytes, client_key: bytes,
                            language=b'tr', client_setting=1, sequence=0xaf) -> bytes:
    if len(client_key) != 16:
        raise ValueError('client_key must be 16 bytes')
    if len(language) != 2 or any(c < 32 or c > 126 for c in language):
        raise ValueError('language must be two printable ASCII bytes')
    if not 0 <= client_setting <= 255 or not 0 <= sequence <= 255:
        raise ValueError('setting and sequence must fit one byte')
    tail = bytes(language) + b'\x00' + bytes(client_key) + bytes([client_setting, sequence])
    return build_login_1051_native(ticket_json, tail)

def parse_login_1051_native(packet: bytes):
    """Decode the native constructor layout; the setting byte semantic name is unknown."""
    if len(packet) != 1051 or packet[0] != 0x61:
        raise ValueError('expected a 1051-byte native 0x61 input')
    variant = struct.unpack_from('<I', packet, 1)[0]
    field = packet[5:1030]
    end = field.find(b'\x00')
    if end < 0 or any(field[end:]):
        raise ValueError('auth field must be NUL terminated and zero padded')
    raw = field[:end]
    if not raw or any(c not in b'0123456789abcdefABCDEF' for c in raw):
        raise ValueError('auth field must contain hexadecimal text')
    first = bytes.fromhex(raw.decode('ascii'))
    if any(c not in b'0123456789abcdefABCDEF' for c in first):
        raise ValueError('auth field must be double hexadecimal text')
    ticket_json = bytes.fromhex(first.decode('ascii'))
    if not isinstance(json.loads(ticket_json.decode('ascii')), dict):
        raise ValueError('decoded ticket must be a JSON object')
    return {'variant': variant, 'ticket_json': ticket_json, 'opaque_tail': packet[1030:],
            'language': packet[1030:1032], 'client_key': packet[1033:1049],
            'client_setting': packet[1049], 'sequence': packet[1050]}

def build_login55(name: bytes, login_key: bytes, client_key: bytes) -> bytes:
    assert len(name) <= 31

    pkt = b'\x44' + name + b'\x00' * (31 - len(name))
    pkt += login_key[:4] + client_key[:16] + b'\x00\x00\xaf'

    assert len(pkt) == 55
    return pkt


# ----------------------------------------------------------------
# 11151 baglanti
# ----------------------------------------------------------------

def try_auth_connection(ticket_json, enc_candidates=None):
    sock = socket.create_connection(
        (AUTH_HOST, AUTH_PORT),
        timeout=15
    )

    log('11151 baglandi')

    try:
        do_handshake(sock, AUTH_PORT)

        shared, rest = do_key_agreement(sock)

        log('shared: %s' % shared.hex())

        first_enc = rest[:2]
        dec_algo, dec = detect_decoder(shared, first_enc)

        log('decoder tespit edildi: %s' % dec_algo)

        rest = rest[2:]

        client_key = os.urandom(16)
        login_pt = build_login_1051(ticket_json, client_key)

        for enc_algo in (enc_candidates or CAND_ALGOS):

            try:
                enc = make_encoder(shared, enc_algo)
            except NotImplementedError:
                continue

            sock.sendall(enc.crypt(login_pt))
            log('1051B gonderildi (encoder=%s)' % enc_algo)

            try:
                buf = rest
                deadline = time.time() + 8

                while time.time() < deadline:
                    try:
                        chunk = recv_some(
                            sock,
                            timeout=max(0.5, deadline - time.time())
                        )
                    except socket.timeout:
                        continue

                    if not chunk:
                        raise ConnectionError(
                            'sunucu koptu (encoder yanlis?)'
                        )

                    buf += chunk

                    if len(buf) >= 37:
                        resp = dec.crypt(buf[:37])

                        log(
                            '37B yanit (cozulmus): %s'
                            % resp.hex()
                        )

                        return sock, dec, enc, resp, client_key

                log(
                    'encoder=%s: yanit yok — sonraki aday'
                    % enc_algo
                )

            except (ConnectionError, OSError) as e:
                log(
                    'encoder=%s: %s — yeniden baglanilacak'
                    % (enc_algo, e)
                )
                return None

        return None

    except (ConnectionError, OSError, ProtocolError) as e:
        log('11151 hata: %s' % e)

        try:
            sock.close()
        except OSError:
            pass

        return None


def auth_flow(ticket_json, max_attempts=14):
    for attempt in range(1, max_attempts + 1):
        log('=== giris denemesi %d/%d ===' % (
            attempt, max_attempts
        ))

        res = try_auth_connection(ticket_json)

        if res:
            sock, dec, enc, resp, client_key = res

            return {
                'sock': sock,
                'decoder': dec,
                'encoder': enc,
                'resp': resp,
                'client_key': client_key
            }

        time.sleep(1.0 + random.random())

    return None


# ----------------------------------------------------------------
# 12105 / 12102
# ----------------------------------------------------------------

def try_game_connection(port, name, login_key, client_key, label):
    sock = socket.create_connection(
        (AUTH_HOST, port),
        timeout=15
    )

    log('%s baglandi' % label)

    try:
        do_handshake(sock, port)

        shared, rest = do_key_agreement(sock)

        while len(rest) < 2:
            chunk = recv_some(sock)

            if not chunk:
                raise ConnectionError(
                    'ilk sifreli paket beklenirken koptu'
                )

            rest += chunk

        first_enc = rest[:2]
        dec_algo, dec = detect_decoder(shared, first_enc)

        log('%s decoder: %s' % (label, dec_algo))

        rest = rest[2:]

        login55 = build_login55(
            name,
            login_key,
            client_key
        )

        for enc_algo in CAND_ALGOS:
            try:
                enc = make_encoder(shared, enc_algo)
            except NotImplementedError:
                continue

            sock.sendall(enc.crypt(login55))

            log(
                '%s login55 gonderildi (encoder=%s)'
                % (label, enc_algo)
            )

            try:
                buf = rest
                deadline = time.time() + 8

                while time.time() < deadline:
                    try:
                        chunk = recv_some(
                            sock,
                            timeout=max(0.5, deadline - time.time())
                        )
                    except socket.timeout:
                        continue

                    if not chunk:
                        raise ConnectionError('sunucu koptu')

                    buf += chunk

                    if len(buf) >= 422:
                        resp = dec.crypt(buf[:422])

                        if name in resp:
                            log(
                                '%s GIRIS BASARILI — karakter listesi alindi (%s)'
                                % (label, name)
                            )
                            return sock, dec, enc, buf[422:]

                        log(
                            '%s 422B geldi ama isim yok — encoder yanlis olabilir'
                            % label
                        )
                        return None

                log('%s encoder=%s: yanit yok' % (
                    label, enc_algo
                ))

            except (ConnectionError, OSError) as e:
                log('%s encoder=%s: %s' % (
                    label, enc_algo, e
                ))
                return None

        return None

    except (ConnectionError, OSError, ProtocolError) as e:
        log('%s hata: %s' % (label, e))

        try:
            sock.close()
        except OSError:
            pass

        return None


def game_flow(port, name, login_key, client_key, label, max_attempts=8):
    for attempt in range(1, max_attempts + 1):
        log('=== %s denemesi %d/%d ===' % (
            label, attempt, max_attempts
        ))

        res = try_game_connection(
            port, name, login_key, client_key, label
        )

        if res:
            return res

        time.sleep(1.0 + random.random())

    return None


# ----------------------------------------------------------------
# Ticket
# ----------------------------------------------------------------

def build_ticket_json(
    token=None,
    display_name=None,
    account_id=None
):
    """Build an ASCII ticket; fill omitted fields from the local ticket file."""
    gt = os.path.join(HERE, '..', 'mt2gf', 'game_token.json')
    d = {}
    if (token is None or display_name is None or account_id is None) and os.path.exists(gt):
        try:
            with open(gt, encoding='utf-8') as f:
                d = json.load(f)
        except Exception:
            d = {}

    if token is None:
        token = d.get('token')
        if not token:
            txt = os.path.join(HERE, '..', 'mt2gf', 'game_token.txt')
            with open(txt, encoding='utf-8') as f:
                token = f.read().strip()

    if display_name is None:
        display_name = d.get('display_name')
        if not display_name:
            raise ValueError('display_name yok: game_token.json okunamadi '
                             've acik deger verilmedi')
    if account_id is None:
        account_id = d.get('numeric_id')
        if not account_id:
            raise ValueError('numeric_id yok: game_token.json okunamadi '
                             've acik deger verilmedi')
    try:
        account_id = int(account_id)
    except (TypeError, ValueError):
        raise ValueError('numeric_id sayisal degil: %r' % (account_id,))

    obj = {
        'account_display_name': display_name,
        'auth_ticket': token,
        'auth_type': 'gf',
        'external_account_id': account_id
    }

    return json.dumps(
        obj,
        separators=(',', ':')
    ).encode('ascii')


def parse_login_key(resp37):
    # Native channel login55 uses exactly response[1:5], confirmed cross-flow.
    if len(resp37) < 37 or resp37[0] != 0x28:
        return []
    return [('auth_success_0x28', resp37[1:5])]


# ----------------------------------------------------------------
# Ana akis
# ----------------------------------------------------------------

def full_flow():
    log('ticket olusturuluyor...')

    ticket = build_ticket_json()

    log('ticket: %s...' % ticket[:80])

    auth = auth_flow(ticket)

    if not auth:
        log('AUTH BASARISIZ — 11151 girilemedi')
        return None

    log('AUTH TAMAM — 37B: %s' % auth['resp'].hex())

    candidates = parse_login_key(auth['resp'])

    for tag, lk in candidates:
        log(
            'login_key adayi (%s): %s'
            % (tag, lk.hex())
        )

    return auth


def main():
    global AUTH_HOST
    ap = argparse.ArgumentParser()

    ap.add_argument('--full', action='store_true')
    ap.add_argument('--probe', action='store_true')
    ap.add_argument('--auth-only', action='store_true')
    ap.add_argument('--auth-host', default=AUTH_HOST,
                    help='auth sunucu IP (veya MT2_AUTH_HOST)')

    args = ap.parse_args()
    AUTH_HOST = args.auth_host
    if not AUTH_HOST:
        print('auth host gerekli: --auth-host veya MT2_AUTH_HOST')
        return 2

    if args.probe:
        sock = socket.create_connection(
            (AUTH_HOST, AUTH_PORT),
            timeout=10
        )

        sock.sendall(b'\x35')

        lst = recv_exact(sock, 84)

        log('sunucu listesi: %s...' % lst[:32].hex())

        sock.close()
        return

    full_flow()


if __name__ == '__main__':
    main()
