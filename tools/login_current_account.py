"""Interactive Gameforge login shared by the launcher and standalone CLI."""
import getpass
import argparse
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src/mt2gf'))
from gf_auth import GfAuth


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--email')
    parser.add_argument('--launcher-installation',action='store_true',help='authenticate using this PC launcher installation ID')
    args=parser.parse_args()
    installation_id=None
    if args.launcher_installation:
        installation_id=GfAuth._registry_installation_id()
        if not installation_id:
            print('Bu bilgisayarin launcher kurulum kimligi okunamadi; rastgele kimlik uretilmedi.')
            return 4
    email = (args.email or input('Gameforge e-postasi: ')).strip()
    if not email:
        print('Gameforge e-postasi bos birakilamaz.')
        return 2
    auth = GfAuth(installation_id=installation_id)
    if not authenticate_interactively(auth, email):
        return 2
    print('Gameforge oturumu acildi.')
    return 0


def authenticate_interactively(auth, email):
    password=getpass.getpass('Gameforge sifresi (gizli): ')
    try:
        result=auth.authenticate(email,password)
        if not result.get('ok') and 'OTP_REQUIRED' in (result.get('errors') or []):
            otp=input('Tek kullanimlik dogrulama kodu: ').strip()
            result=auth.authenticate(email,password,otp)
    finally:
        del password
    if not result.get('ok'):
        errors = result.get('errors') or []
        if 'LAUNCHER_INSTALLATION_MISSING' in errors:
            print('Yerel Gameforge istemcisi bulunamadi. Resmi istemciyi kurup acin.')
        elif 'CHALLENGE_REQUIRED' in errors:
            print('Gameforge bu giris icin dogrulama (captcha) istiyor; sifreniz yanlis degil.')
            print('Ayni bilgisayar ve internet baglantisiyla resmi Gameforge istemcisinden')
            print('bir kez giris yapip captcha\'yi orada cozun, sonra tekrar deneyin.')
            print('VPN kullaniyorsaniz kapatin; cok deneme yaptiysaniz bir sure bekleyin.')
            print('Konsolda "taklit blackbox" uyarisi goruyorsaniz Edge/Chrome kurun veya')
            print('"python -m playwright install chromium" calistirin.')
        else:
            print('Giris tamamlanamadi; hata turleri:', errors)
        return False
    return True


if __name__=='__main__':raise SystemExit(main())
