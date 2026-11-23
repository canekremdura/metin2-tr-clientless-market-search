# Metin2 TR Clientless — Pazar Araması

[English](README.md) · Türkçe

Gameforge token oturumu, istemcisiz (clientless) dünya girişi ve pazar taraması
için Python araçları. Depo giriş/token zincirini ve tarama motorunu içerir;
site API'si, canlı kayıtlar ve hesap bilgileri dahil değildir.

> Uyarı: Gerçek hesap ve token ile oyun sunucusuna doğrudan bağlanmak hesap
> güvenliği ve kullanım koşulları açısından risk taşır. Yalnızca yetkiniz olan
> hesaplarda ve kendi sorumluluğunuzda kullanın.

Başlatıcı ilk açılışta numaralı bir sunucu menüsü gösterir. Pazar tarama
örnekleri Charon içindir.

## Kapsam

| Bileşen | Amaç |
|---|---|
| `src/mt2gf/` | Gameforge oturumu, blackbox/iovation akışı ve oyun bileti |
| `src/clientless/` | Auth, ECDH anahtar değişimi, dünya oturumu, paket çerçeveleme ve pazar protokolü |
| `src/ecdh-lab/` | Bağlantıda kullanılan ECDH ve şifreleme uygulamaları |
| `tools/` | Başlatıcı, pazar taraması ve çevrimdışı testler |
| `docs/` | Başlatıcı açıklaması |

`captures/`, `work/`, oturum dosyaları ve kimlik bilgileri depoda bulunmaz;
çalışma sırasında yerelde oluşur ve `.gitignore` ile dışarıda tutulur.

## Gereksinimler

- Python 3.11+ (Windows)
- Yerel Gameforge istemcisi
- Edge, Chrome veya Playwright Chromium
- Windows'ta `pywin32`

## Kurulum

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Ana giriş akışı sistemdeki Edge veya Chrome'u kullanabilir. Bunlar yoksa
`.\.venv\Scripts\python.exe -m playwright install chromium` komutunu çalıştırın.

İlk açılışta Gameforge e-postası ve parola sorulur. Girişten sonra Metin2
hesabınızı ve sunucuyu seçin, ardından sunucudan gelen ilk karakteri onaylayın.
Başlatıcı hesap ve sunucu seçiminizi
`tools/clientless_profile.json` dosyasına kaydeder; parola ve doğrulama kodu
profile yazılmaz.

## Kullanım

```powershell
.\.venv\Scripts\python.exe tools\start_clientless.py
.\.venv\Scripts\python.exe tools\start_clientless.py --choose-server
```

Kök dizindeki `Clientless-Baslat.cmd` aynı komutu çalıştırır. Ayrıntılar:
[Başlatıcı](docs/BASLATICI.md).

### Giriş hatası: `CHALLENGE_REQUIRED` (captcha)

E-posta ve şifre doğru olduğu hâlde `Giris tamamlanamadi; hata turleri:
['CHALLENGE_REQUIRED', 'SERVICE_ERROR']` görüyorsanız, Gameforge bu giriş için
captcha istiyor demektir. Araç captcha çözmez. Bu durum genelde yeni bir IP
ya da cihazdan girişte, VPN kullanırken veya kısa sürede çok deneme yapıldığında
ortaya çıkar.

1. Aynı bilgisayar ve aynı internet bağlantısıyla resmi Gameforge istemcisinden
   bir kez giriş yapın. Captcha çıkarsa orada çözün, sonra aracı tekrar deneyin.
2. VPN kullanıyorsanız kapatın. Çok deneme yaptıysanız bir süre bekleyin.
3. Konsolda `taklit blackbox` ya da `gercek blackbox basarisiz` uyarısı
   görüyorsanız Edge/Chrome kurun veya
   `.\.venv\Scripts\python.exe -m playwright install chromium` çalıştırın.

### Pazar tarama

Tek arama seçeneği yerel bir arama kaydı ister. Linux pazar süreci de
önceden hazırlanmış bir oturum dosyası gerektirir; bu girdiler depoda bulunmaz.

## Doğrulama

```powershell
python tools\selftest_scan_policy.py
python tools\selftest_skipjack.py
python tools\selftest_world_io.py
python tools\selftest_gf_flow.py
python tools\selftest_market_daemon.py
python tools\selftest_launcher_profile.py
```

## Güvenlik

- `src/mt2gf/all_certs.pem` yalnızca blackbox parmak izi için genel sertifika
  içerir; özel anahtar yoktur.
- `.gf_cred`, `.gf_session.json`, `game_token.json`, `accounts.json`,
  `identity.json` gizli veri içerir; commit etmeyin.
- `captures/` ve `work/` oturum/hesap verisi taşıyabilir.
- Token ve parolaları log veya issue içine koymayın.

## İletişim

Discord: `vervooo`
