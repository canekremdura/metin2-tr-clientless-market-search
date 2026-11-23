# -*- coding: utf-8 -*-
"""Browser verification helper for the Gameforge sign-in flow."""
import argparse
import json
import os
import sys
import time


BLACKBOX_URL = 'https://gameforge.com/tra/blackbox.html'
GAME1_JS = 'https://gameforge.com/tra/game1.js'

HTML = """<!DOCTYPE html>
<html><head>
<script src="https://gameforge.com/tra/game1.js"></script>
</head>
<body><script>
window.__bb = null;
window.__err = null;
window.callback = function(v) { window.__bb = v; };
window.makeBB = function(req) {
  try {
    game1(window.callback, req);
  } catch (e) { window.__err = String(e); }
};
</script></body></html>"""


PROFILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           '..', '..', 'captures', '_bb_profile')

# Gercek istemcinin browserUserAgent'i (nostaleauth.cpp:26)
REAL_UA = ("Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36")

BB_HTML = """<!DOCTYPE html>
<html><head>
<script src="https://gameforge.com/tra/game1.js"></script>
<script>
window.__bb = null; window.__err = null; window.__done = false;
window.cb = function(v) { window.__bb = v; window.__done = true; };
window.go = function(req) {
  try {
    var r = req ? game1(window.cb, req) : game1(window.cb);
    if (r && typeof r.then === 'function') {
      r.catch(function(e){ window.__err = String(e); window.__done = true; });
    }
  } catch (e) { window.__err = String(e); window.__done = true; }
};
</script></head>
<body></body></html>"""


def _screen_size():
    """Return the local display's work-area size."""
    try:
        import ctypes
        import ctypes.wintypes
        u = ctypes.windll.user32
        u.SetProcessDPIAware()
        rc = ctypes.wintypes.RECT()
        if u.SystemParametersInfoW(0x0030, 0, ctypes.byref(rc), 0):
            return rc.right - rc.left, rc.bottom - rc.top
    except Exception:
        pass
    return 1920, 1040


# Keep the local browser storage origin stable across runs.
FIXED_PORT = 47821

DEVICE_MEMORY_PATCH = """
(() => {
  try {
    Object.defineProperty(Navigator.prototype, 'deviceMemory', {
      get: function () { return 8; },
      configurable: true, enumerable: true
    });
  } catch (e) {}
})();
"""


def _serve_html():
    """Serve the page on localhost so browser storage has an origin."""
    import http.server
    import socketserver
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            b = BB_HTML.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass

    socketserver.TCPServer.allow_reuse_address = True
    try:
        httpd = socketserver.TCPServer(('127.0.0.1', FIXED_PORT), H)
    except OSError:
        print('[!] SABIT PORT %d mesgul — rastgele porta dusuldu; '
              'bu kosumda uuid YENIDEN uretilecek' % FIXED_PORT)
        httpd = socketserver.TCPServer(('127.0.0.1', 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, 'http://127.0.0.1:%d/' % httpd.server_address[1]


def _load_verification_page(page, url, timeout_ms):
    from playwright.sync_api import TimeoutError as BrowserTimeout

    try:
        page.goto(url, wait_until='networkidle', timeout=timeout_ms)
    except BrowserTimeout:
        # Retry navigation only, before invoking the verification callback.
        print('[i] Dogrulama sayfasi zaman asimina ugradi; 5 saniye sonra bir kez daha denenecek.')
        time.sleep(5)
        page.goto(url, wait_until='networkidle', timeout=timeout_ms)


def generate_blackbox(gsid, installation_id, timeout_ms=45000, headless=False):
    """Return a prefixed verification value or an error description."""
    from playwright.sync_api import sync_playwright
    import random

    if gsid is None and installation_id is None:
        # iovation yolu: game1(cb) ARGUMANSIZ (GflessClient createBlackbox)
        request = None
    else:
        session = gsid.rsplit('-', 1)[0] if '-' in gsid else gsid
        request = {
            'features': [random.randint(1, 2147483646)],
            'installation': installation_id,
            'session': session,
        }

    w, h = _screen_size()
    os.makedirs(PROFILE_DIR, exist_ok=True)
    httpd, url = _serve_html()

    try:
        with sync_playwright() as p:
            browser_options = {}
            explicit_browser = os.environ.get('MT2_BROWSER_EXECUTABLE')
            if explicit_browser:
                if not os.path.isfile(explicit_browser):
                    return None, 'MT2_BROWSER_EXECUTABLE does not exist'
                browser_options['executable_path'] = explicit_browser
            elif not os.path.isfile(p.chromium.executable_path):
                for root, relative, channel in [
                    ('PROGRAMFILES(X86)', r'Microsoft\Edge\Application\msedge.exe', 'msedge'),
                    ('PROGRAMFILES', r'Google\Chrome\Application\chrome.exe', 'chrome'),
                ]:
                    candidate = os.path.join(os.environ.get(root, ''), relative)
                    if os.path.isfile(candidate):
                        browser_options['channel'] = channel
                        break
            ctx = p.chromium.launch_persistent_context(
                PROFILE_DIR,
                headless=headless,
                user_agent=REAL_UA,
                viewport={'width': w, 'height': h},
                screen={'width': w, 'height': h},
                args=['--disable-blink-features=AutomationControlled',
                      '--window-size=%d,%d' % (w, h),
                      '--window-position=0,0'],
                **browser_options,
            )
            ctx.add_init_script(DEVICE_MEMORY_PATCH)
            try:
                page = ctx.new_page()
                _load_verification_page(page, url, timeout_ms)
                if page.evaluate("typeof game1") != 'function':
                    return None, 'game1.js yuklenemedi (koken: %s)' % page.url
                page.evaluate("(req) => window.go(req)", request)
                page.wait_for_function("() => window.__done === true",
                                       timeout=timeout_ms)
                err = page.evaluate("() => window.__err")
                if err:
                    return None, 'game1 hata: %s' % err
                bb = page.evaluate("() => window.__bb")
                if not bb:
                    return None, 'blackbox bos'
                return (bb if bb.startswith('tra:') else 'tra:' + bb), None
            finally:
                ctx.close()
    except Exception as e:
        return None, '%s: %s' % (type(e).__name__, e)
    finally:
        httpd.shutdown()


def self_test():
    """game1.js erisilebiliyor mu? (blackbox uretmeden)"""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        try:
            pg = b.new_page()
            pg.set_content(HTML, wait_until='networkidle', timeout=25000)
            ok = pg.evaluate("typeof game1 === 'function'")
            print('[%s] game1.js yuklendi' % ('OK' if ok else 'FAIL'))
            return 0 if ok else 1
        finally:
            b.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--gsid', default=None)
    ap.add_argument('--install', default=None)
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--visible', action='store_true')
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if not args.gsid or not args.install:
        print('[-] --gsid ve --install gerekli (veya --self-test)')
        return 2

    print('[*] blackbox uretiliyor (Chromium)...')
    bb, err = generate_blackbox(args.gsid, args.install,
                                headless=not args.visible)
    if err:
        print('[-] %s' % err)
        return 1
    print('[+] blackbox (%d karakter)' % len(bb))
    print(bb[:120] + ('...' if len(bb) > 120 else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())
