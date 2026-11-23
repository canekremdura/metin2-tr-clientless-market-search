# -*- coding: utf-8 -*-
"""Gameforge blackbox (iovation) portu — GflessClient C++ kaynagindan.
- BlackBox encode/decode (tra: kodlamasi)
- EncryptedBlackBox (thin/codes icin SHA512 XOR)
- Fingerprint guncellemeleri (serverTime, vector, creation, timings)
"""
import base64
import hashlib
import json
import random
import time
import urllib.parse

BLACKBOX_FIELDS = [
    "v", "tz", "osType", "app", "vendor", "mem", "con", "lang", "plugins",
    "gpu", "fonts", "audioC", "width", "height", "video", "audio", "media",
    "permissions", "audioFP", "webglFP", "canvasFP", "creation", "uuid",
    "d", "osVersion", "vector", "userAgent", "serverTimeInMS", "request",
    "browserEnvMask",
]

GAME1_URL = "https://gameforge.com/tra/game1.js"


def blackbox_encode(fp_dict):
    """Fingerprint dict -> "tra:..." blackbox stringi (BlackBox::encode)."""
    arr = [fp_dict.get(f) for f in BLACKBOX_FIELDS]
    arr_str = json.dumps(arr, separators=(',', ':'))
    uri = urllib.parse.quote(arr_str, safe="-_!~*.'()")
    b = bytearray()
    b.append(ord(uri[0]))
    for i in range(1, len(uri)):
        b.append((b[i - 1] + ord(uri[i])) & 0xFF)
    bb = base64.urlsafe_b64encode(bytes(b)).decode().rstrip('=')
    return "tra:" + bb


def blackbox_decode(bb):
    """"tra:..." blackbox -> fingerprint dict (BlackBox::decode)."""
    d = bb
    if d.startswith("blackbox="):
        d = d[9:]
    d = d.replace("tra:", "").replace('_', '/').replace('-', '+')
    d += '=' * (-len(d) % 4)
    raw = base64.b64decode(d)
    uri = bytearray()
    uri.append(raw[0])
    for i in range(1, len(raw)):
        uri.append((raw[i] - raw[i - 1]) & 0xFF)
    s = urllib.parse.unquote(bytes(uri).decode('latin1'))
    arr = json.loads(s)
    if len(arr) != len(BLACKBOX_FIELDS):
        raise ValueError("blackbox alan sayisi uyusmadi: %d" % len(arr))
    return dict(zip(BLACKBOX_FIELDS, arr))


def encrypted_blackbox(fp_dict, gsid, account_id, installation_id):
    """EncryptedBlackBox::encrypted — thin/codes icin."""
    fp = dict(fp_dict)
    fp["request"] = {
        "features": [random.randint(1, 2 ** 31 - 1)],
        "installation": installation_id,
        "session": gsid.rsplit("-", 1)[0],
    }
    bb = blackbox_encode(fp).encode('latin1')
    key = hashlib.sha512((gsid + "-" + account_id).encode()).hexdigest().encode()
    res = bytearray()
    klen = len(key)
    for i in range(len(bb)):
        ki = i % klen
        res.append(bb[i] ^ key[ki] ^ key[klen - ki - 1])
    return base64.b64encode(bytes(res)).decode()


def update_fingerprint(fp, server_date_iso=None):
    """Identity::update — kullanım oncesi zaman damgalarini guncelle."""
    cur_ms = int(time.time() * 1000)
    vec = base64.b64decode(fp["vector"])
    last_blank = vec.rfind(b' ')
    old_time = int(vec[last_blank + 1:])
    head = vec[:last_blank]
    if old_time + 1000 < cur_ms:
        head = head[1:] + bytes([random.randint(32, 126)])
    fp["vector"] = base64.b64encode(
        head + b' ' + str(cur_ms).encode()).decode()
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    fp["creation"] = now.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    fp["d"] = random.randint(150, 300)
    if server_date_iso:
        fp["serverTimeInMS"] = server_date_iso
    return fp


def create_play_now_blackbox(fp, server_date_iso=None):
    """sendIovation / authenticate icin duz blackbox (request=null)."""
    fp = dict(fp)
    fp["request"] = None
    update_fingerprint(fp, server_date_iso)
    return blackbox_encode(fp)
