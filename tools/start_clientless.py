"""Profil tabanli clientless baslatici."""
import argparse
import contextlib
import json
import msvcrt
import os
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER_CATALOG = ROOT / 'src/clientless/protocol_data/servers_tr.json'
sys.path[:0] = [str(ROOT / 'src/mt2gf'), str(ROOT / 'src/clientless'), str(ROOT / 'src/ecdh-lab')]


def load_profile(path, character=None):
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('profil bir JSON nesnesi olmali')
    required = ('email', 'account_id', 'display_name', 'numeric_id', 'host')
    missing = [k for k in required if not data.get(k) and data.get(k) != 0]
    if missing:
        raise ValueError('profil eksik: ' + ', '.join(missing))
    return dict(data, character=character) if character else data


def ask_required(prompt):
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print('Bu alan bos birakilamaz.')


def confirm_character(name):
    print('Sunucudan gelen ilk karakter: %s' % name)
    print('1. Bu karakterle gir  /  0. Vazgec')
    while True:
        choice = input('Karakter secimi: ').strip()
        if choice in ('0', '1'):
            return choice == '1'
        print('1 veya 0 girin.')


def choose_server():
    servers = json.loads(SERVER_CATALOG.read_text(encoding='utf-8'))
    options = {str(index): server for index, server in enumerate(servers, 1)}
    print('Metin2 TR sunuculari (CH1):')
    for number, server in options.items():
        group = ' [%s]' % server['group'] if server.get('group') else ''
        status = '' if server.get('ch1') else ' (CH1 adresi dogrulanmadi)'
        print('%s. %s%s%s' % (number, server['name'], group, status))
    print('0. Baska sunucu / adresi elle gir')
    while True:
        choice = input('Sunucu numarasi: ').strip()
        if choice == '0':
            return {'host': ask_required('Sunucu adresi (IP veya alan adi): ')}
        if choice in options:
            server = options[choice]
            if not server.get('ch1'):
                print('Bu sunucunun CH1 adresi dogrulanmadi. Baska bir sunucu secin.')
                continue
            host, auth_port = server['auth']
            channel_host, login_port = server['ch1']
            return {'server_name': server['name'], 'host': host, 'auth_port': auth_port,
                    'channel_host': channel_host, 'login_port': login_port}
        print('Listeden bir numara secin.')


def create_profile(path, auth, character=None):
    from login_current_account import authenticate_interactively

    print('Ilk kurulum: sifre profile yazilmaz.')
    email = ask_required('Gameforge e-postasi: ')
    if not authenticate_interactively(auth, email):
        return None, None

    accounts = [(aid, acc) for aid, acc in auth.get_accounts_full('metin2').items()
                if aid and acc.get('displayName') and acc.get('accountNumericId') is not None
                and str(acc['accountNumericId']).isdigit()]
    if not accounts:
        print('Bu oturumda kullanilabilir Metin2 hesabi bulunamadi.')
        return None, None
    for index, (_, acc) in enumerate(accounts, 1):
        print('%d. %s' % (index, acc['displayName']))
    selected = 0
    if len(accounts) > 1:
        choices = {str(index + 1): index for index in range(len(accounts))}
        while True:
            value = input('Kullanilacak Metin2 hesap numarasi: ').strip()
            if value in choices:
                selected = choices[value]
                break
            print('Listeden bir numara secin.')
    account_id, account = accounts[selected]
    server = choose_server()
    profile = {
        'email': email,
        'account_id': account_id,
        'display_name': account['displayName'],
        'numeric_id': account['accountNumericId'],
        **server,
    }
    if character:
        profile['character'] = character
    with path.open('x', encoding='utf-8') as output:
        json.dump(profile, output, ensure_ascii=False, indent=2)
        output.write('\n')
    print('Profil kaydedildi: %s' % path)
    return profile, account


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', type=Path, default=ROOT / 'tools/clientless_profile.json')
    parser.add_argument('--character')
    parser.add_argument('--choose-server', action='store_true',
                        help='kayitli profili degistirmeden bu calistirma icin sunucu sec')
    parser.add_argument('--trade-search-once', action='store_true')
    parser.add_argument('--trade-source', type=Path, help='yerel decoded_records.jsonl')
    parser.add_argument('--diagnostics', action='store_true', help='ayrintili teshis kaydini ac')
    args = parser.parse_args()
    os.chdir(ROOT)
    if args.trade_search_once and (not args.trade_source or not args.trade_source.is_file()):
        parser.error('--trade-search-once icin --trade-source ile yerel bir kayit verin')
    work = ROOT / 'work'
    work.mkdir(exist_ok=True)
    lock = (work / 'clientless_launcher.lock').open('a+b')
    lock.seek(0)
    lock.write(b'0')
    lock.flush()
    lock.seek(0)
    try:
        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        print('Bu baslatici zaten acik. Ikinci bir oturum baslatilmadi.')
        lock.close()
        return 2
    try:
        auth, acc = None, None
        try:
            profile = load_profile(args.profile, args.character)
        except FileNotFoundError:
            if not args.profile.parent.is_dir():
                print('Profil klasoru bulunamadi: %s' % args.profile.parent)
                return 2
            from gf_auth import GfAuth

            auth = GfAuth(debug=args.diagnostics)
            try:
                profile, acc = create_profile(args.profile, auth, args.character)
            except OSError as e:
                print('Profil olusturulamadi: %s' % e)
                return 2
            if profile is None:
                return 2
        except (OSError, ValueError) as e:
            print('Profil okunamadi: %s' % e)
            return 2
        if args.choose_server and auth is None:
            for field in ('server_name', 'auth_port', 'channel_host', 'login_port'):
                profile.pop(field, None)
            profile.update(choose_server())
            if not args.character:
                profile.pop('character', None)
        character = profile.get('character')
        server_label = profile['server_name'] + ' CH1' if profile.get('server_name') else profile['host']
        print('Sunucu: %s%s' % (server_label, ' | Tek pazar aramasi' if args.trade_search_once else ''))
        from auto_token import session_valid, get_token
        if auth is None:
            from gf_auth import GfAuth
            from login_current_account import authenticate_interactively

            auth = GfAuth(debug=args.diagnostics)
            if auth.email.casefold() != profile['email'].casefold() or not session_valid(auth):
                print('Gameforge oturumu yenilenmeli.')
                if not authenticate_interactively(auth, profile['email']):
                    return 2
            acc = auth.get_accounts_full('metin2').get(profile['account_id'])
        if (not acc or acc.get('displayName') != profile['display_name']
                or str(acc.get('accountNumericId')) != str(profile['numeric_id'])):
            print('Hesap kimligi dogrulanamadi. Diger hesapla devam edilmedi.')
            return 2
        token_log = work / ('clientless_token_' + time.strftime('%Y%m%d_%H%M%S') + '.log')
        print('Taze oyun bileti aliniyor...')
        with token_log.open('w', encoding='utf-8') as output, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                code = get_token(auth, profile['account_id'], until_thin=False, max_tries=1, max_age=0)
            except RuntimeError:
                traceback.print_exc(file=output)
                code = None
        if not code:
            print('Oyun bileti alinamadi. Ayrinti: ' + str(token_log))
            return 1
        from world_login import main as world_main
        world_args = ['--no-portmap', '--auth-host', profile['host'],
                    '--auth-port', str(profile.get('auth_port', 11151)),
                    '--channel-host', profile.get('channel_host', profile['host']),
                    '--login-port', str(profile.get('login_port', 12105)), '--game-port', '12102',
                    '--name', profile['display_name'], '--account-id', str(profile['numeric_id']),
                    '--select-slot', '0', '--world-seconds', '20' if args.trade_search_once else '0']
        if character:
            world_args.extend(['--character-name', character])
        if args.trade_search_once:
            world_args.extend(['--trade-search-once', '--trade-source', str(args.trade_source)])
        return world_main(world_args, token=code, diagnostics=args.diagnostics,
                          confirm_selection=None if character else confirm_character)
    finally:
        lock.close()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, EOFError):
        print('\nKullanici tarafindan durduruldu.')
        raise SystemExit(130)
