# -*- coding: utf-8 -*-
"""gf_debug.py — Gameforge auth zinciri icin kablolu (wire) debug kaydi.

AMAC: "iovation gecti ama thin/codes 403" gibi durumlarda ELDE OLCUM kalsin.
Her istek/yanit captures/gf_debug_<ts>.jsonl dosyasina yazilir; her satirda
flush edilir, yani cokme olsa da bulgu kalir.

GUVENLIK: Bearer token, oyun kodu (code) ve blackbox ICERIGI yazilmaz.
Yalnizca uzunluk + sha256 ilk 16 karakter yazilir. Boylece iki kosumu
karsilastirmak mumkun olur, sir sizmaz.

Kullanim (gf_auth.py icinde otomatik):
    dbg = DebugLog()                 # env GF_DEBUG=0 ise sessiz
    dbg.req("thin/codes", url, headers, body)
    dbg.resp("thin/codes", r)
    dbg.close()
"""
import hashlib
import json
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CAPTURES = os.path.join(ROOT, "captures")

# Bu basliklarin DEGERI asla yazilmaz; sadece varligi ve uzunlugu.
SECRET_HEADERS = {"authorization", "cookie", "set-cookie"}


def _mask(v):
    """Sir olabilecek degeri maskele: uzunluk + sha256 ilk 16."""
    if v is None:
        return None
    s = str(v)
    if s.lower().startswith("bearer "):
        s = s[7:]
    h = hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]
    return {"len": len(s), "sha16": h}


def _summ(v):
    """Govde degeri: kisa ise aynen, uzun ise uzunluk + sha16."""
    if v is None:
        return None
    s = v if isinstance(v, str) else str(v)
    if len(s) <= 64:
        return s
    return {"len": len(s),
            "sha16": hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16],
            "head": s[:24]}


class DebugLog:
    def __init__(self, path=None, enabled=None):
        if enabled is None:
            enabled = os.environ.get("GF_DEBUG", "1") != "0"
        self.enabled = enabled
        self.path = None
        self.f = None
        self.seq = 0
        if not enabled:
            return
        try:
            os.makedirs(CAPTURES, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            self.path = path or os.path.join(CAPTURES, "gf_debug_%s.jsonl" % ts)
            self.f = open(self.path, "w", encoding="utf-8")
        except Exception:
            self.enabled = False

    # ------------------------------------------------------------- yazim
    def _w(self, rec):
        if not self.enabled or self.f is None:
            return
        try:
            self.seq += 1
            rec["seq"] = self.seq
            rec["t"] = round(time.time(), 3)
            self.f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.f.flush()
        except Exception:
            pass

    # ------------------------------------------------------------- API
    def req(self, tag, url, headers=None, body=None, note=None):
        h = {}
        for k, v in (headers or {}).items():
            h[k] = _mask(v) if k.lower() in SECRET_HEADERS else (
                _summ(v) if len(str(v)) > 120 else v)
        b = {}
        for k, v in (body or {}).items():
            # blackbox / code / token gibi alanlar maskelenir
            if k.lower() in ("blackbox", "code", "token", "authorization"):
                b[k] = _mask(v)
            else:
                b[k] = _summ(v)
        self._w({"dir": "REQ", "tag": tag, "url": url,
                 "headers": h, "body": b, "note": note})

    def resp(self, tag, r, note=None):
        try:
            status = r.status_code
            text = r.text
        except Exception as e:
            self._w({"dir": "RESP", "tag": tag, "error": repr(e)})
            return
        # yanit govdesi: 'code' alani varsa maskelenir
        shown = text[:600]
        try:
            j = r.json()
            if isinstance(j, dict):
                shown = {k: (_mask(v) if k.lower() in ("code", "token")
                             else _summ(v))
                         for k, v in j.items()}
        except Exception:
            pass
        self._w({"dir": "RESP", "tag": tag, "status": status,
                 "elapsed_ms": int(getattr(r, "elapsed", None).total_seconds()
                                   * 1000) if getattr(r, "elapsed", None) else None,
                 "body": shown, "note": note,
                 "resp_headers": {k: v for k, v in r.headers.items()
                                  if k.lower() in
                                  ("content-type", "date", "server", "retry-after",
                                   "x-request-id", "cf-ray")}})

    def note(self, tag, **kw):
        self._w(dict({"dir": "NOTE", "tag": tag}, **kw))

    def close(self):
        try:
            if self.f:
                self.f.flush()
                self.f.close()
        except Exception:
            pass
        self.f = None
