# -*- coding: utf-8 -*-
"""world_login.py — UCTAN UCA (bastan sona) TCP ile oyuna giris denemesi + TAM LOG.

Amac: tek komutla auth'tan dunya yuklemesine kadar ilerlemek; her adimda ne
gonderdik / ne geldik / nerede takildik NET gorunsun.

Adimlar:
  S0  ticket hazirla
  S1  11151 TCP baglan
  S2  11151 el sikisma (527 -> 525)
  S3  11151 ECDH/KA + fa
  S4  11151 1051B login gonder
  S5  11151 yanit oku/coz (37B = login_key)          <-- sik tikanan yer
  S6  kanal sunucusu sec
  S7  kanal TCP baglan
  S8  kanal el sikisma + KA
  S9  kanal login55 + surum/komut gonder
  S10 kanal yanit oku/coz (karakter listesi 422B)
  S11 karakter sec + READY/ENTER gonder
  S12 dunya verisi oku/coz (0xcd, ~11855B)
  S13 ozet + KALDIĞIMIZ ADIM

Loglar:
  captures/clientless_world/run_<ts>.log        (insan ozeti)
  captures/clientless_world/run_<ts>_wire.jsonl (HER paket: yon, port, uzunluk,
                                                 tam hex + cozulmus hex; her
                                                 satirda flush -> cokme olsa
                                                 da bulgu kalir)
  captures/clientless_world/run_<ts>/*.bin      (ham + cozulmus paketler)

Kullanim:
  python world_login.py                      # tam uctan uca
  python world_login.py --debug              # konsolda 256B onizleme
  python world_login.py --auth-only          # yalniz 11151
  python world_login.py --login1051-file real_1051_pt.bin   # MCP'den gelen gercek pt
  python world_login.py --channel-host SUNUCU_IP --login-port 12102

UYARI: gercek hesap token'i ile sunucuya dogrudan giris -> ban riski.
       `python -I` KULLANMA (cryptography kaybolur).
"""
import argparse
import atexit
import binascii
import json
import os
import socket
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "ecdh-lab"))

try:
    from auth_client import (  # noqa: E402
        build_handshake_reply, build_ka_reply, build_login55, build_login_1051,
        build_login_1051_native, build_login_1051_fields, parse_login_1051_native,
        make_streams, derive_streams, stream_from_triple, detect_decoder,
        parse_login_key,
        build_ticket_json, CAND_ALGOS, ALGO_PARAMS, ProtocolError,
    )
    from cipher_lab import (  # noqa: E402
        ecdh_keypair, ecdh_shared_x, pub_from_uncompressed, derive_sessions,
    )
except ModuleNotFoundError as e:
    sys.stderr.write("HATA: %s\n`-I` bayragini kullanmayin.\n" % e)
    raise SystemExit(2)

# Charon auth sunucusu; baska sunucu icin degistirin veya --auth-host verin.
AUTH_HOST = os.environ.get("MT2_AUTH_HOST", "79.110.92.149")
AUTH_PORT = 11151


def auth_host_for_server(server_id):
    """server_id -> auth IP. servers_tr.json'dan okur; bulunamazsa None."""
    p = os.path.join(ROOT, "captures", "servers_tr.json")
    try:
        d = json.load(open(p, encoding="utf-8"))
        ent = d["auth_servers"]["0"].get(str(server_id))
        return (ent or {}).get("ip")
    except Exception:
        return None
CHANNEL_PORT = 12105
GAME_PORT = 12102
CLIENT_VERSION = b"Ver. 26,2,10"  # Yerel TR binary: 2026-11-13

ROOT = os.path.dirname(os.path.dirname(HERE))
OUTROOT = os.path.join(ROOT, "captures", "clientless_world")

T0 = time.time()


# ============================================================== LOG
class Logger(object):
    """Iki katmanli log:
      * konsol + run_<ts>.log  -> insan ozeti (adimlar, 48B onizleme)
      * wire_<ts>.jsonl        -> HER paketin TAM hex'i (cozulmus dahil),
                                  her adimda flush; hata olursa bulgu kalir.
    debug=True -> konsol onizlemesi 256B ve cozulmus onizleme her zaman.
    diagnostics=False -> kisa durum mesaji; metin veya paket dosyasi acilmaz.
    """

    def __init__(self, path, debug=False, *, diagnostics=True):
        self.diagnostics = diagnostics
        self.f = open(path, "w", encoding="utf-8") if diagnostics else None
        self.ts = time.strftime("%Y%m%d_%H%M%S")
        self.steps = []  # (id, ad, durum, detay, ms)
        self.debug = bool(debug)
        self.preview = 256 if debug else 48
        wp = path.replace(".log", "_wire.jsonl")
        self.wire = open(wp, "w", encoding="utf-8") if diagnostics else None
        self.wire_path = wp if diagnostics else None
        self.seq = 0

    def _w(self, s):
        if not self.diagnostics:
            return
        try:
            sys.stdout.write(s + "\n")
            sys.stdout.flush()
        except Exception:
            pass
        self.f.write(s + "\n")
        self.f.flush()

    def raw(self, s):
        self._w(s)

    def step_start(self, sid, desc):
        self.t = time.time()
        self._w("")
        self._w("=" * 70)
        self._w("S%s  %s" % (sid, desc))
        self._w("-" * 70)
        self.cur = (sid, desc, None, None)

    def step_ok(self, detay=""):
        sid, desc, _, _ = self.cur
        ms = int((time.time() - self.t) * 1000)
        self.steps.append((sid, desc, "OK", detay, ms))
        if not self.diagnostics:
            status = {5: 'Oyun girisi dogrulandi.', 10: 'Karakter bilgisi alindi.',
                      12: 'Dunyaya girildi.'}.get(sid)
            if status:
                print(status, flush=True)
        self._w("[S%s] OK   %s  (%d ms)" % (sid, detay, ms))

    def step_fail(self, detay=""):
        sid, desc, _, _ = self.cur
        ms = int((time.time() - self.t) * 1000)
        self.steps.append((sid, desc, "FAIL", detay, ms))
        if not self.diagnostics:
            if detay == 'ProtocolError: character selection cancelled; no character entry sent':
                print('Karakter secimi iptal edildi.', flush=True)
            elif detay == 'ProtocolError: slot 0 is empty; no character entry sent':
                print('Bu sunucuda ilk karakter yuvasi bos.', flush=True)
            else:
                print('Islem tamamlanamadi (adim %s: %s).' % (sid, desc), flush=True)
        self._w("[S%s] FAIL %s  (%d ms)" % (sid, detay, ms))

    def info(self, s):
        if not self.diagnostics and s.startswith('TRADE RESULT: '):
            print(s, flush=True)
        self._w("      " + s)

    def pkt(self, direction, port, data, note="", dec=None):
        if not self.diagnostics:
            return
        t = time.time() - T0
        pv = self.preview
        hexs = binascii.hexlify(data[:pv]).decode("ascii")
        if len(data) > pv:
            hexs += "..."
        self._w("      t=%.3f %s:%d %s %4dB  %s  %s"
                % (t, direction, port, "OUT>" if direction == "OUT" else "<IN ", len(data), hexs, note))
        if dec is not None:
            dhex = binascii.hexlify(dec[:pv]).decode("ascii")
            if len(dec) > pv:
                dhex += "..."
            self._w("                               (cozulmus) %4dB  %s" % (len(dec), dhex))
        # TAM kayit — bunun icin debug gerekmez; her zaman yazilir.
        self.seq += 1
        rec = {
            "seq": self.seq,
            "t": round(t, 3),
            "dir": direction,
            "port": port,
            "len": len(data),
            "note": note,
            "hex": binascii.hexlify(data).decode("ascii"),
        }
        if dec is not None:
            rec["dec_len"] = len(dec)
            rec["dec_hex"] = binascii.hexlify(dec).decode("ascii")
        try:
            self.wire.write(json.dumps(rec) + "\n")
            self.wire.flush()
        except Exception as e:
            self._w("      [!] wire kaydi yazilamadi: %r" % (e,))

    def close(self):
        for f in (self.f, self.wire):
            if f is None:
                continue
            try:
                f.close()
            except Exception:
                pass

    def summary(self):
        self._w("")
        self._w("=" * 70)
        self._w("OZET")
        self._w("=" * 70)
        for sid, desc, st, det, ms in self.steps:
            self._w("  S%-2s %-4s %-46s %s (%d ms)" % (sid, st, desc[:46], det[:40], ms))
        failed = [s for s in self.steps if s[2] == "FAIL"]
        if failed:
            sid, desc, st, det, ms = failed[0]
            self._w("")
            self._w("  >>> KALDIĞIMIZ ADIM: S%s — %s" % (sid, desc))
            self._w("      sebep: %s" % det)
        else:
            self._w("")
            self._w("  >>> TAMAMLANDI (tum adimlar OK)")
        self._w("")
        self._w("  Kablolu kayit (her paket, TAM hex): %s" % self.wire_path)
        self._w("")
        return failed[0][0] if failed else None


# ============================================================== IO
# DUZELTME (2026-11-04): EOF ile timeout AYNI gorunuyordu; "sunucu sessizce
# kapatti" teshisi bu yuzden konulamadi. Son okumada karsi taraf FIN
# gonderdiyse LAST_CLOSE=True olur.
LAST_CLOSE = False


def read_until(sock, predicate, deadline, initial=b""):
    global LAST_CLOSE
    LAST_CLOSE = False
    buf = bytes(initial)
    if predicate(buf):
        return buf, True
    sock.settimeout(0.2)
    while time.time() < deadline:
        if buf and predicate(buf):
            return buf, True
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            LAST_CLOSE = True
            return buf, False
        if not chunk:
            LAST_CLOSE = True
            return buf, False
        buf += chunk
    return buf, predicate(buf) if buf else False


def drain(sock, sec):
    out, t0 = b"", time.time()
    sock.settimeout(0.2)
    while time.time() - t0 < sec:
        try:
            c = sock.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            break
        if not c:
            break
        out += c
    return out


# ============================================================== paketler
def pkt_version(version=None):
    return b"\xfa" + (CLIENT_VERSION if version is None else version) + b"\x00" + b"\x00" * 5 + b"\x8a"


def pkt_command():
    return bytes.fromhex("7b0600010003") + b"\x48"


def pkt_status():
    head = bytes.fromhex("720100c8007801") + b"\x01\x01\x01\x01"
    blok = bytes.fromhex("c8007801") + b"\x01\x01\x01\x01"
    body = head + blok * 10
    return body[:94] + b"\xa7"


def pkt_select(opcode, slot):
    return bytes([opcode & 0xFF, slot & 0xFF])


def pkt_ready():
    return b"\x0a"


def pkt_enter(opcode):
    return bytes([opcode & 0xFF])


# ============================================================== oturum
def open_session(log, host, port, tag, sock=None):
    if sock is None:
        sock = socket.create_connection((host, port), timeout=15)
    # el sikisma
    hs = b""
    deadline = time.time() + 10
    while len(hs) < 527 and time.time() < deadline:
        try:
            c = sock.recv(527 - len(hs))
        except socket.timeout:
            continue
        if not c:
            raise ProtocolError("el sikismasi koptu (%d/527)" % len(hs))
        hs += c
    if len(hs) != 527 or hs[:2] != b"\xff\x01":
        raise ProtocolError("el sikismasi beklenmiyor: %s" % hs[:16].hex())
    log.pkt("IN", port, hs, "%s el sikisma 527" % tag)
    sock.sendall(build_handshake_reply(hs, port))
    log.pkt("OUT", port, build_handshake_reply(hs, port), "%s fd yaniti 525" % tag)

    # KA
    buf, _ = read_until(sock, lambda b: b.find(b"\xfb") >= 0 and len(b) >= b.find(b"\xfb") + 261,
                        time.time() + 10)
    off = buf.find(b"\xfb")
    if off < 0 or len(buf) < off + 261:
        raise ProtocolError("KA gelmedi: %s" % buf[:24].hex())
    ka = buf[off:off + 261]
    if ka[5] != 0x04:
        raise ProtocolError("kamu noktasi 04 degil: %02x" % ka[5])
    our_priv, our_pub = ecdh_keypair()
    sock.sendall(build_ka_reply(our_pub))
    log.pkt("OUT", port, build_ka_reply(our_pub), "%s ECDH KA 261" % tag)
    shared = ecdh_shared_x(our_priv, pub_from_uncompressed(ka[5:70]))
    log.info("shared = %s" % shared.hex())
    rest = buf[off + 261:]

    # fa
    buf2, _ = read_until(sock, lambda b: len(b) >= 6, time.time() + 8, initial=rest)
    rest = buf2
    # fa: 4B duz + AYRI 2B sifreli (raw TCP 7/7). Bkz. S3 bolumundeki uzun not.
    if len(rest) < 6 or rest[0] != 0xfa:
        raise ProtocolError("fa yok: %s" % rest[:12].hex())
    log.pkt("IN", port, rest[:4], "%s fa (sifre aktif)" % tag)
    log.pkt("IN", port, rest[4:6], "%s fa-sonrasi 2B sifreli" % tag)
    # Ilk iki sifreli bayt caller tarafinda decoder ile tuketilir.
    rest = rest[4:]
    return sock, shared, rest


# ============================================================== main
def main(argv=None, *, token=None, confirm_selection=None, diagnostics=True):
    ap = argparse.ArgumentParser(description="UCTAN UCA TCP oyuna giris + tam log")
    ap.add_argument("--name", default=None,
                    help="display_name. Verilmezse game_token.json:display_name.")
    ap.add_argument("--account-id", type=int, default=None,
                    help="external_account_id. Verilmezse game_token.json'daki "
                         "numeric_id kullanilir (0 DEGIL).")
    ap.add_argument("--max-token-age", type=float, default=1800.0,
                    help="game_token.json bundan eskiyse DUR (saniye, varsayilan "
                         "1800 = 30 dk). Gameforge Bearer ~1 saat yasar; bayat "
                         "Dosya yasi yalnizca yerel tazelik kontroludur; ret nedenini kanitlamaz.")
    ap.add_argument("--skip-token-age", action="store_true",
                    help="yas denetimini atla (bilerek eski token kullanacaksan)")
    ap.add_argument("--auto-token", action="store_true",
                    help="once src/mt2gf/auto_token.py calistirip tokeni tazele")
    ap.add_argument("--auth-host", default=None,
                    help="Bos birakilirsa game_token.json:server -> "
                         "captures/servers_tr.json auth_servers'tan cozulur")
    ap.add_argument("--auth-port", type=int, default=AUTH_PORT)
    ap.add_argument("--channel-host", default=None,
                    help="Bos ise --auth-host ile ayni (ayni IP, farkli port)")
    ap.add_argument("--login-port", type=int, default=CHANNEL_PORT)
    ap.add_argument("--game-port", type=int, default=GAME_PORT)
    ap.add_argument("--algo", default="CAST256")
    ap.add_argument("--s4-mode", default="enc",
                    choices=["enc", "random", "plain", "none"],
                    help="S4'te 1051B'yi nasil gonderecegi. S5 teshisi icindir: "
                         "enc = turetilen encoder ile sifrele (normal); "
                         "random = 1051 RASTGELE bayt (hic sifrelenmemis cop); "
                         "plain = duz metni oldugu gibi gonder (sifresiz); "
                         "none = HIC GONDERME (kontrol: FIN yoksa baglanti canli, "
                         "ret 1051B'den geliyor demektir). "
                         "Sunucu ucu AYNI sekilde reddediyorsa (ayni FIN, ayni "
                         "gecikme) -> cipher'i cozemiyor, paket sunucu icin "
                         "rastgeleden farksiz. 'enc' farkli tepki veriyorsa -> "
                         "cipher DOGRU cozuluyor, sorun paket iceriginde.")
    ap.add_argument("--auth-only", action="store_true")
    ap.add_argument("--select-opcode", type=lambda s: int(s, 0), default=0x65)
    ap.add_argument("--enter-opcode", type=lambda s: int(s, 0), default=0x0b)
    ap.add_argument("--select-slot", type=int, default=0)
    ap.add_argument("--wait", type=float, default=10.0)
    ap.add_argument("--login1051-file", default=None,
                    help="Hazir 1051B DUZ METIN dosyasi (onek+kuyruk dahil). "
                         "Verilirse --prefix/--tail yok sayilir.")
    ap.add_argument("--prefix", choices=["zero", "real", "file"], default="zero",
                    help="[0:789] onegi: zero=sifir (v_A), real=capture kopyasi (v_B), "
                         "file=--prefix-file")
    ap.add_argument("--prefix-file", default=None,
                    help="789B onek dosyasi (--prefix file ile)")
    ap.add_argument("--tail", choices=["zero", "real", "file"], default="zero",
                    help="JSON sonrasi kuyruk: zero=cok sifir, real=capture kuyrugu, "
                         "file=--tail-file")
    ap.add_argument("--tail-file", default=None)
    ap.add_argument("--real-sample", help="real onek/kuyruk icin yerel 1051B ornek")
    ap.add_argument("--token", default=None)
    ap.add_argument("--ka-sync", default="auto",
                    choices=["auto", "off"],
                    help="ARTIK KULLANILMIYOR (2026-11-07). Eski 'fa-sonrasi "
                         "6B senkron paketi' modeli kayit artefaktiydi: gercek "
                         "duzen 4B fa + AYRI 2B sifreli paket. Geriye uyumluluk "
                         "icin kabul edilir, hicbir sey yapmaz.")
    ap.add_argument("--no-portmap", action="store_true",
                    help="OLCULEN ASAMAYI ATLA: gercek istemci 11151'e once "
                         "1B `0x35` gonderip 84B port listesi aliyor, sonra "
                         "asil oturumu ikinci baglantida kuruyor. Varsayilan "
                         "bu asamayi YAPAR; bu bayrak kapatir (A/B testi).")
    ap.add_argument("--keep-portmap", action="store_true",
                    help="port-map baglantisini ACIK birak. OLCULDU ki gercek "
                         "istemci ~10-17 ms sonra FIN atiyor; bu yalnizca A/B "
                         "denemesi icin (varsayilan: kapat).")
    ap.add_argument("--dry-run", action="store_true",
                    help="AG YOK: S0 ticket + S4 1051B duz metnini kurar, "
                         "ozetler ve cikar. Canli denemeden once dogrulama.")
    ap.add_argument("--debug", action="store_true",
                    help="konsolda paket onizlemesi 48B yerine 256B; cozulmus "
                         "onizleme her pakette. wire_*.jsonl HER ZAMAN tam hex "
                         "yazar (bu bayrak onu degistirmez).")
    ap.add_argument("--client-version", default=CLIENT_VERSION.decode("ascii"),
                    help="Guncel yerel istemciden dogrulanan surum metni; ornek: Ver. 26,2,10")
    ap.add_argument("--world-seconds", type=float, default=30, help="Observe world for N seconds; 0 keeps the connection until STOP/interrupt")
    ap.add_argument("--character-name", default=None, help="Require this character name before native direct entry")
    ap.add_argument("--trade-search-once",action="store_true",help="Send one verified native-recorded trade query after world entry")
    ap.add_argument("--trade-source", help="Local decoded search recording")
    ap.add_argument("--character-list-only", action="store_true", help="Stop after verified character-list packet; no character selected")
    ap.add_argument("--send-extra-controls", action="store_true", help="Explicit legacy experiment: send version/command before character list")
    ap.add_argument("--handshake-only", action="store_true", help="Stop after verified encrypted AUTH phase; no account login sent")
    ap.add_argument("--native-tail-file", help="Diagnostic override: complete 21-byte native tail; normally generated from fields")
    ap.add_argument("--allow-legacy-layout", action="store_true",
                    help="Yalniz eski JSON@789 deneyini acikca tekrar etmek icin")
    ap.add_argument('--language', default='tr', help='Native login: two ASCII language bytes')
    ap.add_argument('--client-setting', type=int, default=1,
                    help='Native constructor setting byte; current observed value 1')
    a = ap.parse_args(argv)
    if 'real' in (a.prefix, a.tail) and not a.real_sample:
        ap.error('--prefix real ve --tail real icin --real-sample gerekli')
    if a.trade_search_once and (not a.trade_source or not os.path.isfile(a.trade_source)):
        ap.error('--trade-search-once requires a local --trade-source file')
    if token is not None:
        if a.token is not None or a.auto_token:
            ap.error('in-memory ticket cannot be combined with --token or --auto-token')
        if not a.auth_host or not a.name or a.account_id is None:
            ap.error('in-memory ticket requires --auth-host, --name and --account-id')
        a.token = token
    try:
        language_bytes = a.language.encode('ascii')
    except UnicodeEncodeError:
        ap.error('--language must be ASCII')
    if a.world_seconds < 0:
        ap.error("--world-seconds must be nonnegative")
    if len(language_bytes) != 2 or not 0 <= a.client_setting <= 255:
        ap.error('--language requires two bytes; --client-setting must be 0..255')
    if a.native_tail_file and a.allow_legacy_layout:
        ap.error('native tail and legacy layout cannot be combined')
    native_tail = None
    if a.native_tail_file:
        if a.login1051_file:
            ap.error("--native-tail-file ve --login1051-file birlikte kullanilamaz")
        try:
            native_tail = open(a.native_tail_file, "rb").read()
        except OSError as e:
            ap.error("native tail okunamadi: %s" % e)
        if len(native_tail) != 21:
            ap.error("--native-tail-file tam 21B olmali")
    try:
        version_bytes = a.client_version.encode("ascii")
    except UnicodeEncodeError:
        ap.error("--client-version ASCII olmali")
    if not version_bytes or b"\x00" in version_bytes:
        ap.error("--client-version bos olamaz ve NUL iceremez")

    ts = time.strftime("%Y%m%d_%H%M%S")
    rundir = os.path.join(OUTROOT, "run_" + ts)
    os.makedirs(rundir)
    log = Logger(os.path.join(OUTROOT, "run_%s.log" % ts), debug=a.debug, diagnostics=diagnostics)
    # Her cikis yolunda (return, exception, KeyboardInterrupt) dosyalar kapansin.
    atexit.register(log.close)

    # auth IP cozumu (mantik: game_token.json:server -> servers_tr.json)
    if not a.auth_host:
        srv = None
        try:
            srv = json.load(open(os.path.join(os.path.dirname(HERE), "mt2gf",
                                              "game_token.json"),
                                 encoding="utf-8")).get("server")
        except Exception:
            pass
        a.auth_host = auth_host_for_server(srv) or AUTH_HOST
        log.raw("[i] auth host: %s (server=%s)" % (a.auth_host, srv))
    if not a.channel_host:
        a.channel_host = a.auth_host

    log.raw("=" * 70)
    log.raw("  world_login — UCTAN UCA  (%s)  hedef=%s:%d" % (ts, a.auth_host, a.auth_port))
    log.raw("=" * 70)

    def save(name, data):
        if not diagnostics:
            return
        try:
            open(os.path.join(rundir, name), "wb").write(data)
        except Exception:
            pass

    # ---------------- S0 ticket
    log.step_start(0, "ticket hazirla")
    # The ticket, display name, and numeric ID must belong to the same account.
    gt_path = os.path.join(os.path.dirname(HERE), 'mt2gf', 'game_token.json')

    # ONCE token tazeligi: bayat Bearer S5'te sessizce reddediliyor ve
    # "yanlis onek/yanlis anahtar" gibi gorunuyor. 7 bos denemenin sebebi buydu.
    if a.auto_token:
        log.info("auto_token.py calistiriliyor (token tazeleme)...")
        import subprocess
        at = os.path.join(os.path.dirname(HERE), 'mt2gf', 'auto_token.py')
        rc = subprocess.call([sys.executable, at], cwd=os.path.dirname(at))
        if rc != 0:
            log.step_fail("auto_token.py rc=%d — token tazelenemedi" % rc)
            log.summary(); return 1
    if token is None and not a.skip_token_age and os.path.exists(gt_path):
        age = time.time() - os.path.getmtime(gt_path)
        log.info("game_token.json yasi: %.0f sn" % age)
        if age > a.max_token_age:
            log.step_fail("token BAYAT (%.0f sn > %.0f sn) — once `python "
                          "src/mt2gf/auto_token.py` calistir, ya da "
                          "--max-token-age artir / --skip-token-age"
                          % (age, a.max_token_age))
            log.summary(); return 1

    gt_data = {}
    if token is None and os.path.exists(gt_path):
        try:
            gt_data = json.load(open(gt_path, encoding='utf-8'))
        except Exception:
            gt_data = {}
    if a.token is None:
        a.token = gt_data.get('token')
    if not isinstance(a.token, str) or not a.token.strip():
        log.step_fail("token yok veya bos; S1 baglantisi acilmadi")
        log.summary(); return 1
    if a.account_id is None:
        acct_id = gt_data.get('numeric_id', 0) or 0
        acct_src = 'game_token.json'
    else:
        acct_id, acct_src = a.account_id, 'CLI'
    # display_name: --name verilmediyse dosyadan; 13 Kasim native girdisinde
    # buyuk/kucuk harf korunuyor, kimlik normalize edilmez.
    disp = a.name if a.name else gt_data.get('display_name')
    if not disp:
        log.step_fail("display_name yok (ne --name ne game_token.json)")
        log.summary(); return 1
    # 13 Nov native input preserves mixed case; do not rewrite account identity.
    disp = str(disp)
    log.info("external_account_id=%s (%s)" % (acct_id, acct_src))
    log.info("display_name=%s" % disp)
    ticket = build_ticket_json(token=a.token, display_name=disp,
                               account_id=int(acct_id))
    # Token ICERIGI loglanmaz — ticket'in yalnizca sekli yazilir.
    log.info("ticket: %dB, anahtarlar=%s"
             % (len(ticket), ",".join(sorted(json.loads(ticket.decode("ascii"))))))
    log.step_ok("%dB" % len(ticket))

    # Native ticket preserves case; the separately observed channel login lowercases it.
    name = disp.lower().encode("ascii")
    client_key = native_tail[3:19] if native_tail is not None else os.urandom(16)

    if a.dry_run:
        # AG YOK — yalnizca kurulacak paketi goster.
        pre = tlr = None
        if a.prefix == "real":
            sample = open(a.real_sample, "rb").read()
            pre = sample[:789]
        elif a.prefix == "file":
            pre = open(a.prefix_file, "rb").read()
        if a.tail == "real":
            sample = open(a.real_sample, "rb").read()
            tlr = sample[789 + len(ticket):]
        elif a.tail == "file":
            tlr = open(a.tail_file, "rb").read()
        if native_tail is not None:
            pt = build_login_1051_native(ticket, native_tail)
        elif a.login1051_file and os.path.exists(a.login1051_file):
            pt = open(a.login1051_file, "rb").read()
        elif not a.allow_legacy_layout:
            pt = build_login_1051_fields(ticket, client_key, language_bytes, a.client_setting)
        else:
            pt = build_login_1051(ticket, prefix=pre, tail=tlr)
        log.info("DRY-RUN — aga CIKILMADI")
        log.info("hedef: %s:%d (server=%s)" % (a.auth_host, a.auth_port,
                                               gt_data.get('server')))
        log.info("1051B uzunluk=%d, JSON@%d, onek sifir-disi=%d/789"
                 % (len(pt), pt.find(b'{"'),
                    sum(1 for b in pt[:789] if b)))
        # Token ICERIGI YAZILMAZ — yalnizca alanlar ve maskeli kuyruk.
        _o = json.loads(ticket.decode('ascii'))
        log.info("JSON alanlari: %s"
                 % {k: (v[:6] + '...' if k == 'auth_ticket' else v)
                    for k, v in sorted(_o.items())})
        log.info("paket duzeni: %s" % ("native 0x61 / cift-hex JSON" if not a.allow_legacy_layout else "eski deneysel"))
        log.step_ok("paket hazir (gondermek icin --dry-run kaldir)")
        log.summary(); return 0

    # ---------------- S1 connect
    # The observed client requests the port map on a separate connection.
    if not a.no_portmap:
        log.step_start(1, "11151 port-map (0x35 -> 84B)")
        try:
            ps = socket.create_connection((a.auth_host, a.auth_port), timeout=15)
            ps.sendall(b"\x35")
            log.pkt("OUT", a.auth_port, b"\x35", "port-map istegi (1B 0x35)")
            ps.settimeout(0.3)
            pm = b""
            chunks = []          # (t, uzunluk) — segment sinirlarini olcmek icin
            d = time.time() + 8
            last = time.time()
            # Do not assume TCP reads align with protocol messages.
            while time.time() < d:
                try:
                    c = ps.recv(65536)
                except socket.timeout:
                    if len(pm) >= 84 and time.time() - last > 1.0:
                        break
                    continue
                except OSError:
                    break
                if not c:
                    break
                pm += c
                chunks.append((round(time.time() - (d - 8), 3), len(c)))
                last = time.time()
                if len(pm) >= 629:
                    break
            if a.keep_portmap:
                log.info("port-map baglantisi ACIK birakildi (--keep-portmap, "
                         "gercek davranis DEGIL)")
            else:
                try:
                    ps.close()
                except OSError:
                    pass
            if diagnostics:
                try:
                    with open(os.path.join(ROOT, "captures", "clientless_world",
                                           "portmap_%s.bin" % log.ts), "wb") as f:
                        f.write(pm)
                except Exception:
                    pass
            log.info("port-map ham: %dB, %d segment -> %s"
                     % (len(pm), len(chunks), chunks))

            def cut(lo, hi):
                return pm[lo:hi] if len(pm) >= hi else b""

            # Find the port list by signature; the preceding handshake may be absent.
            lst = b""
            lst_off = -1
            for _o in range(0, max(1, len(pm) - 84 + 1)):
                w = pm[_o:_o + 84]
                if len(w) == 84 and w[0] == 0x53 and w[1] == 0x1A:
                    lst, lst_off = w, _o
                    break
            hi = lst_off if lst_off >= 0 else 0
            hidx = pm.find(b"\xff\x01\xfd", 0, hi if hi else len(pm))
            hello = pm[:hidx] if hidx > 0 else b""
            hs527 = pm[hidx:hidx + 527] if hidx >= 0 else b""
            if hello and len(hello) <= 16 and hello != b"\x00" * len(hello):
                log.pkt("IN", a.auth_port, hello, "6B merhaba (527 oncesi)")
            elif hi >= 6:
                log.info("527 oncesi %dB: %s" % (len(pm[:hidx]), pm[:hidx].hex()))
            if hs527 and len(hs527) == 527:
                log.pkt("IN", a.auth_port, hs527,
                        "527 (port-map el sikismasi) @%d" % hidx)
            elif b"\xff\x01\xfd" in pm[:hi if hi else len(pm)]:
                log.info("527 imzasi var ama tam 527B yok (@%d)" % hidx)
            else:
                log.info("DİKKAT: yanitta 527 el sikismasi YOK (ilk 64B: %s)"
                         % pm[:64].hex())
            ports = []
            if lst:
                log.pkt("IN", a.auth_port, lst, "84B port listesi")
                # Each entry has a variable type byte and a little-endian port.
                i = 7
                while i + 3 <= len(lst):
                    p = lst[i + 1] | (lst[i + 2] << 8)
                    if not (12000 <= p <= 12700):
                        break
                    ports.append(p)
                    i += 3
                log.info("port listesi: %d kayit -> %s"
                         % (len(ports), ", ".join(str(p) for p in ports)))
            else:
                log.info("port listesi imzasi (53 1a) YOK — ilk 96B: %s"
                         % pm[:96].hex())
            log.info("port-map yaniti: %dB (gercek: 629B / 5 paket)" % len(pm))
            log.step_ok("%dB, %d port" % (len(pm), len(ports)))
        except Exception as e:
            # Bu asama opsiyonel: basarisiz olursa asil oturumu engelleme.
            log.info("port-map atlandi: %r" % e)
            log.step_ok("port-map yapilamadi (devam)")

    log.step_start(2, "11151 TCP baglan (asil oturum)")
    try:
        sock = socket.create_connection((a.auth_host, a.auth_port), timeout=15)
        log.step_ok("%s:%d" % (a.auth_host, a.auth_port))
    except Exception as e:
        log.step_fail("baglanti: %r" % e)
        log.summary(); return 1

    # ---------------- S2/S3 handshake+KA (open_session ile)
    log.step_start(2, "11151 el sikisma (527 -> 525)")
    try:
        hs = b""
        d = time.time() + 10
        while len(hs) < 527 and time.time() < d:
            try:
                c = sock.recv(527 - len(hs))
            except socket.timeout:
                continue
            if not c:
                raise ProtocolError("koptu (%d/527)" % len(hs))
            hs += c
        if len(hs) != 527 or hs[:2] != b"\xff\x01":
            raise ProtocolError("beklenmeyen: %s" % hs[:16].hex())
        log.pkt("IN", a.auth_port, hs, "527 handshake")
        rep = build_handshake_reply(hs, a.auth_port)
        sock.sendall(rep)
        log.pkt("OUT", a.auth_port, rep, "525 fd yaniti")
        log.step_ok("tip=%02x" % hs[10])
    except Exception as e:
        log.step_fail(repr(e)); log.summary(); return 1

    log.step_start(3, "11151 ECDH/KA + fa")
    try:
        buf, _ = read_until(sock, lambda b: b.find(b"\xfb") >= 0 and len(b) >= b.find(b"\xfb") + 261,
                            time.time() + 10)
        off = buf.find(b"\xfb")
        if off < 0 or len(buf) < off + 261:
            raise ProtocolError("KA yok: %s" % buf[:24].hex())
        ka = buf[off:off + 261]
        log.pkt("IN", a.auth_port, ka, "261 KA (sunucu noktasi)")
        if ka[5] != 0x04:
            raise ProtocolError("kamu noktasi %02x" % ka[5])
        our_priv, our_pub = ecdh_keypair()
        reply = build_ka_reply(our_pub)
        sock.sendall(reply)
        log.pkt("OUT", a.auth_port, reply, "261 KA reply")
        shared = ecdh_shared_x(our_priv, pub_from_uncompressed(ka[5:70]))
        log.info("shared = %s" % shared.hex())
        rest = buf[off + 261:]
        b2, _ = read_until(sock, lambda b: len(b) >= 6, time.time() + 8, initial=rest)
        rest = b2
        if len(rest) < 6 or rest[0] != 0xfa:
            raise ProtocolError("fa yok: %s" % rest[:12].hex())
        # The four-byte plaintext marker precedes the first two encrypted bytes.
        log.pkt("IN", a.auth_port, rest[:4], "fa (sifre aktif)")
        oracle2 = rest[4:6]
        rest = rest[6:]
        log.pkt("IN", a.auth_port, oracle2, "fa-sonrasi 2B sifreli (oracle)")
        log.info("KA tamamlandi; sifre dogrulamasi henuz yapilmadi")
    except Exception as e:
        log.step_fail(repr(e)); log.summary(); return 1

    dec_algo, dec = detect_decoder(shared, oracle2)
    _der = derive_sessions(shared, True)
    enc_triple = _der["encoder"]
    enc_algo = enc_triple[0]
    log.info("decoder=%s encoder=%s" % (dec_algo, enc_algo))
    # Advance the same decoder before reading the login response.
    phase_pt = dec.crypt(oracle2)
    if phase_pt != b"\xff\x0a":
        log.step_fail("native AUTH phase mismatch: expected ff0a, got %s; S4 not sent" % phase_pt.hex())
        sock.close(); log.summary(); return 1
    log.step_ok("KA + decrypted AUTH phase ff0a confirmed")

    if a.handshake_only:
        sock.close()
        log.info("HANDSHAKE ONLY: verified ff0a; no account login sent")
        log.summary(); return 0

    # ---------------- S4 1051B login
    log.step_start(4, "11151 1051B login gonder")
    if native_tail is not None:
        login_pt = build_login_1051_native(ticket, native_tail)
        log.info("KAYNAK: olculen 0x61 + variant1 + cift-hex JSON + 21B opak kuyruk")
    elif a.login1051_file and os.path.exists(a.login1051_file):
        login_pt = open(a.login1051_file, "rb").read()
        if len(login_pt) != 1051:
            log.step_fail("dosya 1051B degil (%d)" % len(login_pt)); log.summary(); return 1
        if login_pt[0] == 0x61:
            client_key = parse_login_1051_native(login_pt)['client_key']
        log.info("KAYNAK: hazir 1051B pt (%s)" % a.login1051_file)
    elif not a.allow_legacy_layout:
        login_pt = build_login_1051_fields(ticket, client_key, language_bytes, a.client_setting)
        log.info("KAYNAK: native 0x61 / double-hex JSON / language / client key / setting / sequence")
    else:
        pre = tlr = None
        if a.prefix == "real":
            sample = open(a.real_sample, "rb").read()
            if len(sample) != 1051:
                log.step_fail("ornek %s 1051B degil (%d)"
                              % (a.real_sample, len(sample))); log.summary(); return 1
            pre = sample[:789]
        elif a.prefix == "file":
            pre = open(a.prefix_file, "rb").read()
        if a.tail == "real":
            sample = open(a.real_sample, "rb").read()
            tlr = sample[789 + 143:]
        elif a.tail == "file":
            tlr = open(a.tail_file, "rb").read()
        login_pt = build_login_1051(ticket, prefix=pre, tail=tlr)
        log.info("KAYNAK: sentetik 1051B (onek=%s kuyruk=%s, JSON@789)"
                 % (a.prefix, a.tail))
        nz = sum(1 for b in login_pt[:789] if b)
        log.info("       onek sifir-disi bayt: %d/789" % nz)
    log.info("login uzunluk=%d opcode=%02x (ticket baytlari konsola yazilmadi)" % (len(login_pt), login_pt[0]))
    save("s4_login_1051_pt.bin", login_pt)
    if enc_algo not in ALGO_PARAMS:
        log.step_fail("turetilen encoder '%s' bu kurulumda YOK — yanlis "
                      "algoritmayla gondermek yerine duruyorum" % enc_algo)
        log.summary(); return 1
    enc = stream_from_triple(enc_triple)
    ct = enc.crypt(login_pt)
    save("s4_login_1051_ct.bin", ct)
    send_mode = a.s4_mode
    if send_mode == "none":
        wire_bytes = b""
        log.info("S4 MODU: none — 1051B GONDERILMIYOR (kontrol kosusu). "
                 "FIN gelmiyorsa baglanti canli, ret 1051B'den.")
    elif send_mode == "random":
        wire_bytes = os.urandom(1051)
        log.info("S4 MODU: random — 1051 rastgele bayt (encoder KULLANILMADI)")
    elif send_mode == "plain":
        wire_bytes = login_pt
        log.info("S4 MODU: plain — duz metin SIFRESIZ gonderiliyor")
    else:
        wire_bytes = ct
    save("s4_wire_%s.bin" % send_mode, wire_bytes)
    if wire_bytes:
        sock.sendall(wire_bytes)
        log.pkt("OUT", a.auth_port, wire_bytes,
                "1051B login (mod=%s%s)"
                % (send_mode,
                   ", enc=%s" % enc_algo if send_mode == "enc" else ""),
                dec=login_pt if send_mode not in ("random", "none") else None)
        log.step_ok("%dB gonderildi (mod=%s)" % (len(wire_bytes), send_mode))
    else:
        log.step_ok("0B gonderildi (mod=none) — kontrol kosusu")

    # ---------------- S5 yanit
    log.step_start(5, "11151 yanit oku/coz (37B login_key beklenir)")
    # The login response follows directly, without a separate sync packet.
    _d = time.time() + (min(a.wait, 4) if send_mode == "none" else a.wait)
    buf, got = read_until(sock, lambda b: len(b) >= 37,
                          _d if send_mode == "none" else time.time() + a.wait, initial=rest)
    if not buf:
        if send_mode == "none":
            if LAST_CLOSE:
                log.step_fail("KONTROL (none): 1051B GONDERILMEDEN de FIN geldi — "
                              "oturum 1051B'den ONCE oluyor. 1051B'nin sucu yok.")
            else:
                log.step_fail("KONTROL (none): FIN YOK, baglanti ACIK kaldi — "
                              "ret dogrudan 1051B gonderiminden geliyor.")
        elif LAST_CLOSE:
            log.step_fail("sunucu baglantiyi KAPATTI (FIN) — aktif ret. "
                          "Neden yalniz FIN ile belirlenemez; token, paket ve sifre akisina bakilmali.")
        else:
            log.step_fail("yanit YOK, baglanti acik kaldi (%.1fs timeout) — "
                          "pasif: sunucu bekliyor, paket eksik olabilir" % a.wait)
        log.summary(); return 1
    save("s5_resp_ct.bin", buf)
    # Decrypt once; each call advances the CTR stream.
    pt = dec.crypt(buf[:min(len(buf), 128)])
    save("s5_resp_pt.bin", pt)
    log.pkt("IN", a.auth_port, buf, "yanit (%dB)" % len(buf), dec=pt)
    if len(buf) >= 37:
        resp37 = pt[:37]
        log.info("37B cozulmus: %s" % resp37.hex())
        candidates = parse_login_key(resp37)
        if not candidates:
            log.step_fail("37B response is not native auth success 0x28")
            sock.close(); log.summary(); return 1
        login_key = candidates[0][1]
        log.step_ok("native auth success 0x28; login key extracted")
    else:
        log.step_fail("eksik yanit: %d/37B (%s); login_key dogrulanmadi" %
                      (len(buf), "baglanti kapandi" if LAST_CLOSE else "timeout"))
        sock.close()
        log.summary(); return 1

    if a.auth_only:
        sock.close()
        log.summary(); return 0
    try:
        sock.close()
    except OSError:
        pass

    # ---------------- S6 kanal sec
    log.step_start(6, "kanal sunucusu sec")
    ch_host, ch_port = a.channel_host, a.login_port
    log.info("hedef: %s:%d" % (ch_host, ch_port))
    log.step_ok("%s:%d" % (ch_host, ch_port))

    # ---------------- S7/S8 kanal baglan + KA
    log.step_start(7, "kanal TCP baglan")
    try:
        csock = socket.create_connection((ch_host, ch_port), timeout=15)
        log.step_ok("baglandi")
    except Exception as e:
        log.step_fail(repr(e)); log.summary(); return 1

    log.step_start(8, "kanal el sikisma + KA")
    try:
        csock, cshared, crest = open_session(log, ch_host, ch_port, "kanal", sock=csock)
        c_dec_algo, c_dec = detect_decoder(cshared, crest[:2])
        log.info("kanal decoder=%s" % c_dec_algo)
        log.pkt("IN", ch_port, crest[:2], "ilk sifreli 2B")
        channel_phase = c_dec.crypt(crest[:2])
        if channel_phase != b"\xff\x02":
            raise ProtocolError("channel phase mismatch: expected ff02, got %s" % channel_phase.hex())
        crest = crest[2:]
        c_enc_triple = derive_sessions(cshared, True)["encoder"]
        c_enc_algo = c_enc_triple[0]
        if c_enc_algo not in ALGO_PARAMS:
            raise ProtocolError("turetilen kanal encoder '%s' YOK" % c_enc_algo)
        c_enc = stream_from_triple(c_enc_triple)
        log.step_ok("decoder=%s encoder=%s" % (c_dec_algo, c_enc_algo))
    except Exception as e:
        log.step_fail(repr(e)); log.summary(); return 1

    # ---------------- S9 login55 + surum
    log.step_start(9, "kanal login55 + surum/komut gonder")
    try:
        # encoder'i tek akista kullan (durum onemli)
        c_enc = stream_from_triple(c_enc_triple)
        p55 = build_login55(name, login_key, client_key)
        c55 = c_enc.crypt(p55)
        csock.sendall(c55)
        log.pkt("OUT", ch_port, c55, "login55 (%dB)" % len(p55), dec=p55)
        if a.send_extra_controls:
            time.sleep(0.2)
            pv = pkt_version(version_bytes)
            cv = c_enc.crypt(pv)
            csock.sendall(cv)
            log.pkt("OUT", ch_port, cv, "surum raporu (%dB)" % len(pv), dec=pv)
            time.sleep(0.2)
            pc = pkt_command()
            cc = c_enc.crypt(pc)
            csock.sendall(cc)
            log.pkt("OUT", ch_port, cc, "komut (%dB)" % len(pc), dec=pc)
        log.step_ok("native login55 sent with auth login key")
    except Exception as e:
        log.step_fail(repr(e)); log.summary(); return 1

    # ---------------- S10 karakter listesi
    log.step_start(10, "kanal yanit oku/coz (karakter listesi)")
    raw, got = read_until(csock, lambda b: len(b) >= 422, time.time() + a.wait, initial=crest)
    pt = c_dec.crypt(raw) if raw else b""
    save("s10_charlist_ct.bin", raw)
    save("s10_charlist_pt.bin", pt)
    if not raw:
        log.step_fail("yanit YOK")
        log.summary(); return 1
    log.pkt("IN", ch_port, raw, "%dB (%dB cozuldu)" % (len(raw), len(pt)), dec=pt)
    if len(pt) < 422 or pt[0] != 0x1f:
        log.step_fail("character-list mismatch: expected >=422B / opcode 1f")
        csock.close(); log.summary(); return 1
    log.step_ok("native character list 0x1f received (%dB)" % len(pt))
    if a.character_list_only:
        csock.close()
        log.info("CHARACTER LIST ONLY: no character selected")
        log.summary(); return 0

    # ---------------- S11-S13 native game endpoint, entry and keepalive
    csock.close()
    from world_session import run_native_world
    result = run_native_world(log, ch_host, a.game_port, name, login_key,
                              client_key, os.path.join(rundir, 'world'),
                              expected_name=a.character_name, slot=a.select_slot,
                              stay_seconds=a.world_seconds, version=a.client_version,
                              open_session_fn=open_session,trade_search_once=a.trade_search_once,
                              trade_search_source=a.trade_source,
                              confirm_selection=confirm_selection)
    log.summary()
    log.raw("  world state: %s" % os.path.join(rundir, 'world', 'world_state.json'))
    return 0 if result.get('success') else 1


if __name__ == "__main__":
    sys.exit(main())
