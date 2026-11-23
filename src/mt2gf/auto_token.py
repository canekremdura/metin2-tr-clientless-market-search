# -*- coding: utf-8 -*-
"""auto_token.py — TEK KOMUT: giris + token + game_token.json (otomatik).

HER TEST SEANSI ONCESI BUNU CALISTIR.

Sifre saklama (ilk sefer):
  python auto_token.py --save-credentials
  (sifre getpass ile sorulur, DPAPI ile kullanicinin hesabina bagli sifrelenir)

Sonra sadece:
  python auto_token.py                 # oturum gecerliyse yeniden kullanir
  python auto_token.py --force         # oturumu zorla yenile

Cikti: game_token.json (auth_client.py bunu okur)

NOT: Gameforge Bearer token'i ~1 saat yasar. .gf_session.json da eskir.
Bu arac once oturumu dogrular; gecersizse sifreyle yeniden giris yapar.
"""
import argparse
import base64
import getpass
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

CRED_FILE = os.path.join(HERE, '.gf_cred')
SESSION_FILE = os.path.join(HERE, '.gf_session.json')
TOKEN_FILE = os.path.join(HERE, 'game_token.json')
ACCOUNTS_FILE = os.path.join(HERE, 'accounts.json')
IDENTITY = os.path.join(HERE, 'identity.json')


# ---------------------------------------------------------------- DPAPI
def _dpapi_encrypt(data: bytes) -> bytes:
    import win32crypt
    return win32crypt.CryptProtectData(data, 'mt2gf', None, None, None, 0)


def _dpapi_decrypt(data: bytes) -> bytes:
    import win32crypt
    return win32crypt.CryptUnprotectData(data, None, None, None, 0)[1]


def save_credentials(email, password):
    blob = _dpapi_encrypt(json.dumps(
        {'email': email, 'password': password}).encode())
    with open(CRED_FILE, 'wb') as f:
        f.write(blob)
    try:
        os.chmod(CRED_FILE, 0o600)
    except Exception:
        pass
    print('[+] kimlik kaydedildi (DPAPI, bu kullaniciya bagli): %s' % CRED_FILE)


def load_credentials():
    if not os.path.exists(CRED_FILE):
        return None
    try:
        raw = _dpapi_decrypt(open(CRED_FILE, 'rb').read())
        return json.loads(raw.decode())
    except Exception as e:
        print('[!] kimlik okunamadi: %s' % e)
        return None


# ---------------------------------------------------------------- akis
def session_valid(g):
    """Bearer token gercekten calisiyor mu? (accounts cagrisi)"""
    if not g.token:
        return False
    try:
        accs = g.get_accounts_full('metin2')
        return bool(accs)
    except Exception:
        return False


def login(g, email, password, otp=''):
    res = g.authenticate(email, password, otp)
    if not res.get('ok'):
        errs = res.get('errors') or []
        if 'OTP_REQUIRED' in errs:
            code = input('OTP kodu: ').strip()
            res = g.authenticate(email, password, code)
        if not res.get('ok'):
            print('[-] giris basarisiz: %s' % res)
            return False
    print('[+] oturum acildi: %s' % g.email)
    return True


COOLDOWN_FILE = os.path.join(HERE, '.gf_cooldown')

# Optional local cooldown; these values are not server limits.
COOLDOWN_STEPS = (20, 40, 60)
COOLDOWN_MAX = 60


def _in_cooldown():
    if not os.path.exists(COOLDOWN_FILE):
        return None
    try:
        d = json.load(open(COOLDOWN_FILE, encoding='utf-8'))
        until = d.get('until', 0)
        if time.time() < until:
            left = until - time.time()
            return (d.get('reason', '?'), left)
    except Exception:
        pass
    return None


def _next_cooldown_seconds():
    """Kademeli: 20 -> 40 -> 60 -> 60... (deneme sayaci dosyada tutulur)."""
    n = 0
    try:
        n = int(json.load(open(COOLDOWN_FILE, encoding='utf-8')).get('strikes', 0))
    except Exception:
        pass
    return (COOLDOWN_STEPS[min(n, len(COOLDOWN_STEPS) - 1)], n + 1)


def _set_cooldown(reason):
    secs, strikes = _next_cooldown_seconds()
    with open(COOLDOWN_FILE, 'w', encoding='utf-8') as f:
        json.dump({'until': time.time() + secs,
                   'secs': secs,
                   'strikes': strikes,
                   'reason': reason,
                   'set_at': time.strftime('%Y-%m-%d %H:%M:%S')}, f, indent=1)
    print()
    print('!' * 62)
    print('!! YEREL POLITIKA: %d saniye (yerel sayac %d)' % (secs, strikes))
    print('!! Sebep: %s' % reason)
    print('!! Bu sure sunucunun bildirdigi bir bekleme suresi degildir.')
    print('!! Kilit dosyasi: %s' % COOLDOWN_FILE)
    print('!' * 62)


def cached_token(account_id, max_age):
    """Return a matching local ticket within max_age seconds, if caching is enabled."""
    if not max_age or max_age <= 0:
        return None
    if not os.path.exists(TOKEN_FILE):
        return None
    try:
        d = json.load(open(TOKEN_FILE, encoding='utf-8'))
    except Exception:
        return None
    tok = d.get('token')
    if not tok:
        return None
    if d.get('account_id') != account_id:
        return None
    age = time.time() - os.path.getmtime(TOKEN_FILE)
    if age > max_age:
        return None
    d['_age'] = age
    return d


def get_token(g, account_id, retries=3, until_thin=False, max_tries=6,
              max_age=0, local_cooldown=False):
    """Request a token; default is one transaction, without a local wait lock.

    local_cooldown is optional client policy, never evidence of server limits.
    until_thin explicitly enables bounded retries of failed iovation calls.
    A thin/codes rejection ends this invocation; its cause remains unproven.
    """
    hit = cached_token(account_id, max_age)
    if hit:
        print('[+] gecerli token ZATEN VAR (%.0f sn once alindi) — '
              'yeniden istenmiyor' % hit['_age'])
        print('    zorla yenilemek icin: --force-token')
        return hit['token']

    cd = _in_cooldown() if local_cooldown else None
    if cd:
        print('[-] BEKLEME: %s — %.0f sn kaldi' % (cd[0], cd[1]))
        return None

    tries = max_tries if until_thin else 1
    for i in range(1, tries + 1):
        try:
            code = g.get_game_token(account_id, retries=1)
        except TypeError:
            code = g.get_game_token(account_id)
        if code:
            if os.path.exists(COOLDOWN_FILE):
                os.remove(COOLDOWN_FILE)
            return code

        # iovation gecti mi? Gectiyse thin/codes'te reddedildik -> DUR.
        if getattr(g, '_iovation_ok', False):
            print('[*] iovation GECILDI, thin/codes reddetti — duruluyor')
            if local_cooldown:_set_cooldown('local policy: thin/codes rejected')
            return None

        if i < tries:
            wait = 20 + 10 * (i - 1)          # 20, 30, 40, 50, 60 sn
            wait = min(wait, 60)
            print('[*] iovation 403 (%d/%d) — %d sn sonra tekrar'
                  % (i, tries, wait))
            time.sleep(wait)

    if local_cooldown:_set_cooldown('local policy: iovation attempts failed')
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--save-credentials', action='store_true')
    ap.add_argument('--force', action='store_true', help='oturumu zorla yenile')
    ap.add_argument('--email', default=None)
    ap.add_argument('--account', default=None, help='hesap id veya adi')
    ap.add_argument('--clear-cooldown', action='store_true',
                    help='kilidi elle kaldir (RISKLI)')
    ap.add_argument('--until-thin', action='store_true',
                    help='iovation gecene kadar dene (bot skoru, '
                         'deterministik degil); thin/codes reddederse dur')
    ap.add_argument('--max-tries', type=int, default=6,
                    help='--until-thin ile en fazla kac iovation denemesi')
    ap.add_argument('--max-token-age', type=float, default=1500.0,
                    help='game_token.json bu yastan (sn) gencse YENIDEN '
                         'ISTENMEZ — mevcut token kullanilir. Varsayilan 1500 '
                         '(token ~30 dk gecerli). 0 = onbellegi kapat.')
    ap.add_argument('--force-token', action='store_true',
                    help='gecerli token olsa bile YENI token iste')
    ap.add_argument('--installation-id', default=None,
                     help='Yerel Gameforge kurulum kimligini acikca belirt.')
    args = ap.parse_args()

    # --- kimlik kaydi ---
    if args.clear_cooldown:
        if os.path.exists(COOLDOWN_FILE):
            os.remove(COOLDOWN_FILE)
            print('[+] kilit kaldirildi')
        else:
            print('[*] kilit yok')
        return 0

    if args.save_credentials:
        email = args.email or input('GF e-posta: ').strip()
        pw = getpass.getpass('GF sifre: ')
        save_credentials(email, pw)
        return 0

    from gf_auth import GfAuth

    cred = load_credentials()
    g = GfAuth(identity_path=IDENTITY if os.path.exists(IDENTITY) else None,
               installation_id=args.installation_id)
    if args.installation_id:
        print('[*] tnt-installation-id ZORLANDI: %s' % g.installation_id)

    # --- oturum dogrula ---
    need_login = args.force or not session_valid(g)
    if need_login:
        if g.token and not args.force:
            print('[*] kayitli oturum gecersiz — yeniden giris')
        elif args.force:
            print('[*] --force: oturum yenileniyor')
        if not cred:
            print('[-] kayitli kimlik yok. Once: python auto_token.py --save-credentials')
            return 2
        if not login(g, cred['email'], cred['password']):
            return 2
    else:
        print('[*] oturum gecerli: %s' % g.email)

    # --- hesap sec ---
    accs = g.get_accounts_full('metin2') or []
    ids = [a for a in accs if isinstance(a, str)]
    if not ids:
        # dict listesi olabilir
        ids = [a.get('id') for a in accs if isinstance(a, dict) and a.get('id')]
    if not ids:
        print('[-] hesap bulunamadi')
        return 2

    target = args.account
    if not target:
        # game_token.json'daki id'yi tercih et, yoksa ilk hesap
        if os.path.exists(TOKEN_FILE):
            try:
                target = json.load(open(TOKEN_FILE, encoding='utf-8')).get('account_id')
            except Exception:
                target = None
        if target not in ids:
            target = ids[0]
    elif target not in ids:
        # isimle eslesme
        for a in accs:
            if isinstance(a, dict) and a.get('name') == target:
                target = a['id']
                break
        else:
            if target not in ids:
                print('[-] hesap bulunamadi: %s  (mevcut: %s)' % (target, ids))
                return 2

    print('[*] hesap: %s' % target)
    # display_name + numeric_id'yi API'den al (hard-code YASAK — eski bug:
    # eski hesap degerleri sabit yaziliyordu, oysa ticket tek bir hesaba ait
    # olmali. 1051B JSON'i sunucuda hesapla eslesmezse FIN.)
    disp, numeric, srv, lang = None, None, None, None
    acc_obj = accs.get(target) if isinstance(accs, dict) else None
    if isinstance(acc_obj, dict):
        disp = acc_obj.get('displayName')
        guls = acc_obj.get('guls') or {}
        # The observed ticket uses accountNumericId, not the internal guls.user ID.
        numeric = str(acc_obj.get('accountNumericId') or '')
        if not numeric:
            numeric = str(guls.get('user', '') or '')
            print('[!] accountNumericId BOS — guls.user yedegi kullaniliyor '
                  '(%s); 1051B reddedilebilir' % numeric)
        srv = str(guls.get('server', '') or '') or None
        lang = str(guls.get('lang', '') or '') or None
    print('[*] display_name=%s numeric_id=%s server=%s lang=%s'
          % (disp, numeric, srv, lang))

    print('[*] oyun tokeni aliniyor...')
    code = get_token(g, target, until_thin=args.until_thin,
                     max_tries=args.max_tries,
                     max_age=0 if args.force_token else args.max_token_age)
    if not code:
        print('[-] token alinamadi')
        return 1

    print('[+] token alindi (%d karakter)' % len(code))
    with open(TOKEN_FILE, 'w', encoding='utf-8') as f:
        json.dump({'token': code, 'account_id': target,
                   'display_name': disp or 'unknown',
                   'numeric_id': numeric,
                   'server': srv or '1', 'lang': lang or 'tr',
                   'grabbed_at': time.strftime('%Y-%m-%d %H:%M:%S')},
                  f, indent=1)
    if not srv:
        print('[!] UYARI: guls.server BOS — world_login varsayilan auth IP '
              '(.137) kullanacak; yanlis sunucuysa --auth-host ver.')
    print('[+] yazildi: %s' % TOKEN_FILE)
    return 0


if __name__ == '__main__':
    sys.exit(main())
