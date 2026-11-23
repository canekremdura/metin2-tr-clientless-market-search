# -*- coding: utf-8 -*-
"""Gameforge OAuth + oyun token zinciri — GflessClient (nostaleauth.cpp) portu.

Kullanim:
  python gf_auth.py identity                    # Playwright ile parmak izi uret (identity.json)
  python gf_auth.py login                       # e-posta/sifre -> Bearer token -> hesaplar
  python gf_auth.py token <accountId>           # iovation + thin/codes -> oyun token'i (code)

Guvenlik: sifre getpass ile sorulur, ASLA diske yazilmaz.
"""
import argparse
import base64
import hashlib
import getpass
import json
import os
import random
import sys
import time
import uuid

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from blackbox import (GAME1_URL, blackbox_decode, blackbox_encode,
                      create_play_now_blackbox, encrypted_blackbox,
                      update_fingerprint)

METIN2_GAME_ID = "fab180a3-cd65-4b7e-bd0e-2ef77fd0c258.tr-TR"
METIN2_TR_ENV_ID = "5401ee5b-1316-41ae-a628-73377b8676ba"

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36")
VERSION_INFO_URL = "http://dl.tnt.gameforge.com/tnt/final-ms3/clientversioninfo.json"
CERT_PEM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "all_certs.pem")


SESSION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            ".gf_session.json")

IDENTITY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "identity.json")


class _NullDbg:
    """DebugLog kurulamazsa sessiz yedek."""
    path = None

    def req(self, *a, **k):
        pass

    def resp(self, *a, **k):
        pass

    def note(self, *a, **k):
        pass

    def close(self):
        pass


class GfAuth:
    def __init__(self, identity_path=None, installation_id=None, proxy=None, *, debug=True):
        # Do not silently change the installation of an existing bearer session.
        self.installation_id = installation_id or self._registry_installation_id()
        self._explicit_installation_id = installation_id is not None
        self.installation_source = ('explicit' if installation_id else
                                    'local_launcher' if self.installation_id else 'unavailable')
        self.identity = None
        self._identity_path = identity_path
        if identity_path and os.path.exists(identity_path):
            with open(identity_path) as f:
                self.identity = json.load(f)
        elif self.identity is None and os.path.exists(IDENTITY_FILE):
            try:
                with open(IDENTITY_FILE, encoding='utf-8') as f:
                    self.identity = json.load(f)
            except Exception as e:
                print("[!] identity.json okunamadi: %s" % e)
        self.proxy = proxy
        self.token = ""
        self.email = ""
        self._load_session()
        # Fallback launcher version; this is not a Chromium version.
        self.chrome_version = "C3.0.4.2238"
        self.gameforge_version = ""
        self.cert = self._load_cert()
        self.game_session_id = ""
        self._iovation_ok = False
        self._bb_source = "?"
        self.locale = "tr-TR"
        self._dbg = _NullDbg()
        if debug:
            try:
                from gf_debug import DebugLog
                self._dbg = DebugLog()
                if self._dbg.path:
                    print("[i] debug kaydi: %s" % self._dbg.path)
            except Exception as e:
                print("[!] debug kaydi kurulamadi: %r" % (e,))
        self._init_gf_version()

    def _load_session(self):
        try:
            with open(SESSION_FILE) as f:
                s = json.load(f)
            self.token = s.get("token", "")
            self.email = s.get("email", "")
            if s.get('installation_id') and not self._explicit_installation_id:
                self.installation_id = s['installation_id']
                self.installation_source = 'saved_auth_session'
            if not self.installation_id:
                self.token = ''
        except Exception:
            pass

    def _save_session(self):
        try:
            with open(SESSION_FILE, "w") as f:
                json.dump({"token": self.token, "email": self.email,
                           "installation_id":self.installation_id}, f)
        except Exception:
            pass

    @staticmethod
    def _registry_installation_id():
        try:
            import winreg
        except ImportError:
            return None
        paths=[
            (winreg.HKEY_CURRENT_USER,r'SOFTWARE\Gameforge4d\GameforgeClient\MainApp',0),
            (winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Gameforge4d\GameforgeClient\MainApp',winreg.KEY_WOW64_32KEY),
            (winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\WOW6432Node\Gameforge4d\GameforgeClient\MainApp',0),
        ]
        for hive,path,view in paths:
            try:
                with winreg.OpenKey(hive,path,0,winreg.KEY_READ|view) as key:
                    value=str(winreg.QueryValueEx(key,'InstallationId')[0]).strip()
                uuid.UUID(value)
                return value
            except (OSError,ValueError,TypeError):
                continue
        return None

    def _load_cert(self):
        try:
            with open(CERT_PEM) as f:
                data = f.read()
            start = data.find("-----BEGIN CERTIFICATE-----")
            end = data.find("-----END CERTIFICATE-----", start)
            return data[start:end + len("-----END CERTIFICATE-----") + 1]
        except Exception:
            return ""

    def _init_gf_version(self):
        """Load launcher version metadata, which may include a UTF-8 BOM."""
        try:
            r = requests.get(VERSION_INFO_URL, timeout=10)
            if r.status_code == 200:
                j = json.loads(r.content.decode('utf-8-sig'))
                ver = str(j.get("version", "") or "")
                if ver:
                    self.chrome_version = "C" + ver
                self.gameforge_version = j.get(
                    "minimumVersionForDelayedUpdate", "") or ""
        except Exception as e:
            print("[!] launcher surumu okunamadi (%s) — sabit %s kullanilacak"
                  % (e, self.chrome_version))

    def _proxies(self):
        if self.proxy:
            return {"http": self.proxy, "https": self.proxy}
        return None

    def _server_date_iso(self):
        """game1.js isteginin Date header'i -> ISO (Fingerprint::getServerDate)."""
        try:
            r = requests.get(GAME1_URL, timeout=10, proxies=self._proxies())
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(r.headers["Date"])
            return dt.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        except Exception:
            return None

    def _update_and_save_identity(self):
        """Identity::update — zaman damgalarini guncelle + dosyaya kaydet (C++ save())."""
        fp = dict(self.identity)
        update_fingerprint(fp, self._server_date_iso())
        self.identity = fp
        try:
            id_path = getattr(self, '_identity_path', None)
            if id_path:
                # 'request' KALICI DEGIL: her istekte yeniden uretilir
                # (EncryptedBlackBox::createRequest) ve duz blackbox'ta
                # null'dur (BlackBox(identity, QJsonValue::Null)).
                # Okurken hicbir yerde kullanilmiyor; diske yazmak sadece
                # bir sonraki calistirmaya bayat kurulum/session sizdirir.
                disk = dict(fp)
                disk["request"] = None
                with open(id_path, "w") as f:
                    json.dump(disk, f, indent=2)
        except Exception:
            pass
        return fp

    def _make_blackbox(self):
        """Prepare the browser verification value for sign-in."""
        try:
            from gf_blackbox import generate_blackbox
            bb, err = generate_blackbox(None, None)
            if bb:
                if not bb.startswith('tra:'):
                    bb = 'tra:' + bb
                self._bb_source = 'game1.js'
                return bb
            print("[!] gercek blackbox basarisiz: %s" % err)
        except Exception as e:
            print("[!] gf_blackbox hata: %s" % e)

        # 2) YEDEK: identity.json taklidi (BILINEN EKSIK — son care)
        if self.identity is not None:
            print("[!] UYARI: taklit blackbox'a dusuldu — iovation 403 riski "
                  "yuksek (gercek JS ile 10/30 alan farkli)")
            fp = self._update_and_save_identity()
            fp = dict(fp)
            fp["request"] = None          # BlackBox(identity, QJsonValue::Null)
            self._bb_source = 'identity.json(taklit)'
            return blackbox_encode(fp)

        raise RuntimeError("blackbox uretilemedi (JS yok, identity yok)")

    def _make_encrypted_blackbox(self, gsid, account_id):
        """Prepare the browser verification value for the game ticket."""
        plain = None
        try:
            from gf_blackbox import generate_blackbox
            bb, err = generate_blackbox(gsid, self.installation_id)
            if bb:
                plain = bb if bb.startswith('tra:') else 'tra:' + bb
            else:
                print("[!] gercek blackbox basarisiz: %s" % err)
        except Exception as e:
            print("[!] gf_blackbox hata: %s" % e)

        # 2) YEDEK: identity.json taklidi (BILINEN EKSIK — son care)
        if plain is None and self.identity is not None:
            print("[!] UYARI: taklit blackbox'a dusuldu (10/30 alan farkli)")
            fp = dict(self.identity)
            # zaman alanlarini tazele (Identity::update)
            try:
                update_fingerprint(fp, self._server_date_iso())
            except Exception as e:
                print("[!] kimlik zaman guncellemesi atlandi: %s" % e)
            fp["request"] = {
                "features": [random.randint(1, 2 ** 31 - 1)],
                "installation": self.installation_id,
                "session": gsid.rsplit('-', 1)[0],
            }
            plain = blackbox_encode(fp)

        if plain is None:
            raise RuntimeError("blackbox uretilemedi (identity yok, JS yok)")

        # --- EncryptedBlackBox::encrypt (her iki yolda da ZORUNLU) ---
        key = hashlib.sha512(
            (gsid + "-" + account_id).encode()).hexdigest().encode()
        klen = len(key)
        raw = plain.encode('latin1')
        out = bytes(raw[i] ^ key[i % klen] ^ key[klen - (i % klen) - 1]
                    for i in range(len(raw)))
        return base64.b64encode(out).decode()

    def _third_type_magic(self, account_id):
        """generateThirdTypeUserAgentMagic — hash'li UA parcası."""
        inst = self.installation_id
        fd = next((c for c in inst if c.isdigit()), None)
        acct2 = account_id[:2]
        if fd is None or int(fd) % 2 == 0:
            h_cert = hashlib.sha256(self.cert.encode()).hexdigest()
            h_ver = hashlib.sha1(self.chrome_version.encode()).hexdigest()
            h_inst = hashlib.sha256(inst.encode()).hexdigest()
            h_acct = hashlib.sha1(account_id.encode()).hexdigest()
        else:
            # nostaleauth.cpp:269-275 — bu dalda ALGORITMALAR TERS:
            # cert=sha1, version=sha256, installationId=sha1, accountId=sha256
            h_cert = hashlib.sha1(self.cert.encode()).hexdigest()
            h_ver = hashlib.sha256(self.chrome_version.encode()).hexdigest()
            h_inst = hashlib.sha1(inst.encode()).hexdigest()
            h_acct = hashlib.sha256(account_id.encode()).hexdigest()
        h_sum = hashlib.sha256(
            (h_cert + h_ver + h_inst + h_acct).encode()).hexdigest()
        if fd is None or int(fd) % 2 == 0:
            return acct2 + h_sum[:8]
        return acct2 + h_sum[-8:]

    def authenticate(self, email, password, otp_code=""):
        """POST /api/v2/authProviders/credentials/sessions -> Bearer token."""
        if not self.installation_id:
            return {'ok': False, 'errors': ['LAUNCHER_INSTALLATION_MISSING']}
        url = ("https://spark.gameforge.com/api/v2/authProviders/"
               "credentials/sessions")
        content = {
            "blackbox": self._make_blackbox(),
            "email": email,
            "locale": self.locale,
            "password": password,
        }
        if otp_code:
            content["otpCode"] = otp_code
        r = requests.post(url, json=content, headers={
            "User-Agent": BROWSER_UA,
            "tnt-installation-id": self.installation_id,
            "gf-installation-id": self.installation_id,
        }, proxies=self._proxies(), timeout=30)
        j = {}
        try:
            j = r.json()
        except Exception:
            pass
        if r.status_code == 201:
            self.token = j.get("token", "")
            self.email = email
            self._save_session()
            return {"ok": True, "token": self.token}
        errors = j.get("errorTypes", [])
        return {"ok": False, "status": r.status_code, "errors": errors,
                "challenge_id": r.headers.get("gf-challenge-id", "")}

    def get_accounts(self, game="metin2"):
        """GET /api/v1/user/accounts -> {displayName: id} (guls.game filtreli)."""
        if not self.token:
            return {}
        r = requests.get(
            "https://spark.gameforge.com/api/v1/user/accounts",
            headers={
                "User-Agent": BROWSER_UA,
                "TNT-Installation-Id": self.installation_id,
                "Authorization": "Bearer " + self.token,
            }, proxies=self._proxies(), timeout=30)
        if r.status_code != 200:
            return {}
        accounts = {}
        for key, acc in r.json().items():
            guls = acc.get("guls", {})
            if guls.get("game") != game:
                continue
            accounts[acc.get("displayName", key)] = acc.get("id", key)
        return accounts

    def get_accounts_full(self, game="metin2"):
        """GET /api/v1/user/accounts -> {id: ham hesap nesnesi}."""
        if not self.token:
            return {}
        r = requests.get(
            "https://spark.gameforge.com/api/v1/user/accounts",
            headers={
                "User-Agent": BROWSER_UA,
                "TNT-Installation-Id": self.installation_id,
                "Authorization": "Bearer " + self.token,
            }, proxies=self._proxies(), timeout=30)
        if r.status_code != 200:
            return {}
        out = {}
        for key, acc in r.json().items():
            guls = acc.get("guls", {})
            if guls.get("game") != game:
                continue
            out[acc.get("id", key)] = acc
        return out

    def send_iovation(self, account_id):
        """Submit account verification and return whether it succeeded."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": BROWSER_UA,
            "TNT-Installation-Id": self.installation_id,
            "Authorization": "Bearer " + self.token,
        }
        bb = self._make_blackbox()
        body = {"accountId": account_id, "blackbox": bb, "type": "play_now"}
        self._dbg.req("iovation",
                      "https://spark.gameforge.com/api/v1/auth/iovation",
                      headers, body,
                      note="blackbox kaynagi=%s" % getattr(self, "_bb_source", "?"))
        r = requests.post(
            "https://spark.gameforge.com/api/v1/auth/iovation",
            json=body, headers=headers, proxies=self._proxies(), timeout=30)
        self._dbg.resp("iovation", r)
        if r.status_code != 200:
            print("[-] iovation HTTP %d: %s" % (r.status_code, r.text[:300]))
            return False
        if r.json().get("status") != "ok":
            print("[-] iovation status: %s" % r.text[:300])
            return False
        return True

    def get_game_token(self, account_id, game_id=METIN2_GAME_ID, retries=1):
        """One complete transaction, matching reference getToken; no automatic retry.

        retries remains accepted for older callers, but does not replay failed
        transactions. Each explicit call performs its own iovation step.
        """
        return self._get_game_token_once(account_id,game_id,allow_iovation=True)

    def _captured_thin_ua(self, account_id):
        """capture_identity.py'nin yakaladigi GERCEK UA'yi dondur (varsa).
        gf_requests.jsonl: {"path", "headers", "body"} kayitlari."""
        try:
            path = os.path.normpath(os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..", "..", "captures", "gf_requests.jsonl"))
            best = None
            with open(path, encoding="utf-8") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if rec.get("path") != "/api/v1/auth/thin/codes":
                        continue
                    if (rec.get("body") or {}).get("platformGameAccountId") != account_id:
                        continue
                    for h in (rec.get("headers") or "").split("\r\n"):
                        if h.lower().startswith("user-agent:"):
                            best = h.split(":", 1)[1].strip()
            return best
        except Exception:
            return None

    def _get_game_token_once(self, account_id, game_id, allow_iovation=True):
        if allow_iovation:
            self.game_session_id = str(uuid.uuid4())
        elif not self.game_session_id:
            raise ValueError('no existing game session for thin/codes')
        if allow_iovation:
            if not self.send_iovation(account_id):
                self._iovation_ok = False
                print("[-] iovation basarisiz")
                return None
            self._iovation_ok = True
            print("[+] iovation OK")
            time.sleep(1.0)
        gsid = self.game_session_id + "-" + str(random.randint(1000, 9999))
        magic = self._third_type_magic(account_id)
        ua = "Chrome/%s (%s)" % (self.chrome_version, magic)
        ua_src = "current_context"
        print("[*] thin/codes UA: current version/account/installation context")
        self._dbg.note('token_context',installation_source=self.installation_source,
                       launcher_version=self.chrome_version,ua_source=ua_src,
                       generated_session=True)
        enc_bb = self._make_encrypted_blackbox(gsid, account_id)
        body = {
            "platformGameAccountId": account_id,
            "gsid": gsid,
            "blackbox": enc_bb,
            "gameId": game_id,
        }
        headers = {
            "User-Agent": ua,
            "Authorization": "Bearer " + self.token,
            "tnt-installation-id": self.installation_id,
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "tr-TR,en,*",
        }
        self._dbg.req("thin/codes",
                      "https://spark.gameforge.com/api/v1/auth/thin/codes",
                      headers, body,
                      note="ua_kaynagi=%s bb_uzunluk=%d iovation=%s"
                           % (ua_src, len(enc_bb),
                              "gecildi" if self._iovation_ok else "ATLANDI"))
        r = requests.post(
            "https://spark.gameforge.com/api/v1/auth/thin/codes",
            json=body, headers=headers, proxies=self._proxies(), timeout=30)
        self._dbg.resp("thin/codes", r)
        if r.status_code != 201:
            print("[-] thin/codes HTTP %d: %s" % (r.status_code, r.text[:500]))
            return None
        return r.json().get("code")


def generate_identity(out_path="identity.json", gsid=None, installation_id=None,
                      headless=False):
    """Playwright ile gercek iovation blackbox'i uret -> decode -> identity.json
    headless=True -> gizli mod (iovation reddedebilir!)
    headless=False -> gorunur pencere, GERCEK GPU/UA (oneerilen)"""
    from playwright.sync_api import sync_playwright
    inst = installation_id or GfAuth._registry_installation_id()
    if not inst:
        raise RuntimeError('Gameforge istemci kurulum kimligi bulunamadi.')
    real_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent=real_ua,
            locale="tr-TR",
            timezone_id="Europe/Istanbul",
        )
        page = context.new_page()
        page.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', "
            "{get: () => undefined});")
        page.goto("https://gameforge.com/tr", wait_until="domcontentloaded",
                  timeout=30000)
        page.add_script_tag(url=GAME1_URL)
        if gsid:
            req = {"features": [random.randint(1, 2 ** 31 - 1)],
                   "installation": inst,
                   "session": gsid.rsplit("-", 1)[0]}
            bb = page.evaluate(
                "(req) => new Promise(r => game1(r, req))", req)
        else:
            bb = page.evaluate(
                "() => new Promise(r => game1(r))")
        browser.close()
    if not bb:
        raise RuntimeError("blackbox uretilemedi: bos")
    if not bb.startswith("tra:"):
        bb = "tra:" + bb
    fp = blackbox_decode(bb)
    with open(out_path, "w") as f:
        json.dump(fp, f, indent=2)
    print("[+] Identity kaydedildi: %s (%d alan)" % (out_path, len(fp)))
    print("[*] userAgent: %s" % str(fp.get("userAgent"))[:80])
    print("[*] gpu: %s" % str(fp.get("gpu"))[:80])
    return fp


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    p_id = sub.add_parser("identity", help="Playwright ile parmak izi uret")
    p_id.add_argument("--out", default="identity.json")
    p_login = sub.add_parser("login", help="e-posta/sifre ile giris")
    p_login.add_argument("--identity", default="identity.json")
    p_login.add_argument("--email", default=None)
    p_tok = sub.add_parser("token", help="oyun token'i al")
    p_tok.add_argument("--identity", default="identity.json")
    p_tok.add_argument("account")
    p_tok.add_argument("--email", default=None)
    args = ap.parse_args()

    if args.cmd == "identity":
        generate_identity(args.out)
        return

    if args.cmd in ("login", "token"):
        auth = GfAuth(identity_path=args.identity)
        if auth.token:
            if auth.get_accounts():
                print("[*] Kayitli oturum gecerli (%s)" % auth.email)
            else:
                print("[*] Kayitli oturum gecersiz — yeniden giris")
                auth.token = ""
        if not auth.token:
            email = args.email or input("GF e-posta: ").strip()
            password = getpass.getpass("GF sifre: ")
            res = auth.authenticate(email, password)
            if not res["ok"]:
                print("[-] Giris basarisiz: %s" % res)
                if "OTP_REQUIRED" in res.get("errors", []):
                    otp = input("OTP kodu: ").strip()
                    res = auth.authenticate(email, password, otp)
                    if not res["ok"]:
                        print("[-] OTP sonrasi da basarisiz: %s" % res)
                        return
                else:
                    return
            print("[+] Token alindi (%d karakter)" % len(auth.token))
        if args.cmd == "login":
            accounts = auth.get_accounts()
            print("[+] Metin2 hesaplari:")
            for name, acc_id in accounts.items():
                print("    %s  ->  %s" % (name, acc_id))
            print("[!] Oyun tokeni icin: python gf_auth.py token <accountId>")
        else:
            code = auth.get_game_token(args.account)
            if code:
                print("[+] OYUN TOKEN'I (%d karakter):" % len(code))
                print(code)
                with open("game_token.txt", "w") as f:
                    f.write(code)
                print("[+] game_token.txt kaydedildi")
                info = {"token": code, "account_id": args.account}
                try:
                    accs = auth.get_accounts_full()
                    acc = accs.get(args.account)
                    if acc:
                        guls = acc.get("guls") or {}
                        info["display_name"] = acc.get("displayName", "")
                        info["numeric_id"] = str(guls.get("user", ""))
                        info["server"] = str(guls.get("server", ""))
                        info["lang"] = str(guls.get("lang", ""))
                except Exception as e:
                    print("[*] hesap bilgisi alınamadı: %s" % e)
                with open("game_token.json", "w") as f:
                    json.dump(info, f, indent=2)
                print("[+] game_token.json kaydedildi (name=%s numeric_id=%s)" % (
                    info.get("display_name"), info.get("numeric_id")))
            else:
                print("[-] Token alinamadi")


if __name__ == "__main__":
    main()
