# Başlatıcı

Proje kökündeki `Clientless-Baslat.cmd` dosyasını çift tıklayın veya doğrudan
Python ile çalıştırın:

```powershell
.\.venv\Scripts\python.exe tools\start_clientless.py
```

## İlk açılış

1. Gameforge e-postanızı ve gizli alanda parolanızı girin. Gerekirse tek kullanımlık doğrulama kodu da sorulur.
2. Birden fazla Metin2 hesabı varsa listeden birini seçin. Hesap kimliklerini başlatıcı alır.
3. Sunucuyu numarayla seçin. Listede olmayanlar
   için `0` ile adresi elle girebilirsiniz.
4. Başlatıcı sunucudan ilk yuvadaki karakterin adını alır. Ekrandaki adı
   kontrol edin ve `1` ile girişe devam edin veya `0` ile vazgeçin. Diğer
   yuvalarla giriş şu anda desteklenmez.

Başlatıcı bu seçimi `tools/clientless_profile.json` dosyasına kaydeder. Sonraki
açılışlarda aynı profili kullanır. Parola ve doğrulama kodu profile yazılmaz.
Profil dosyası `.gitignore` ile dışarıda tutulur.

[Yerel sunucu kataloğu](../src/clientless/protocol_data/servers_tr.json), eldeki
listenin giriş ve CH1 adreslerini saklar. Katalog canlı sunucu durumunu göstermez.

## Davranış

- Süre sınırı yoktur. Ctrl+C veya pencereyi kapatmak bağlantıyı sonlandırır.
- Aynı anda ikinci bir başlatıcı açılmaz; ortak kilit kullanılır.
- Gameforge oturumu kontrol edilir; gerekirse parola gizli alanda
  sorulur ve diske yazılmaz.
- Başlatıcı taze oyun biletini dünya girişine bellekte verir. Bu akışta
  `game_token.json` veya ayrı bir hesap listesi oluşturulmaz.
- Sunucu bağlantıyı keserse hata gösterilir; otomatik yeniden giriş yapılmaz.

## Farklı karakter veya profil

Kayıtlı profili değiştirmeden bir çalıştırma için sunucu seçmek üzere:

```powershell
.\.venv\Scripts\python.exe tools\start_clientless.py --choose-server
```

İlk yuvadaki karakterin adını önceden biliyorsanız, bu çalıştırmada adı
doğrulamak için belirtebilirsiniz:

```powershell
.\.venv\Scripts\python.exe tools\start_clientless.py --character KARAKTER_ADI
```

Ayrı bir profil kullanmak için:

```powershell
.\.venv\Scripts\python.exe tools\start_clientless.py --profile tools\ikinci_profile.json
```

Dosya yoksa ilk kurulum bu profil için açılır. `tools/*_profile.json` dosyaları
Git dışında tutulur.

## Tek arama

Yerel çözülmüş bir arama kaydıyla tek pazar araması yapıp 20 saniye gözlemlemek için:

```powershell
.\.venv\Scripts\python.exe tools\start_clientless.py --trade-search-once --trade-source work\decoded_records.jsonl
```

## Çıktılar

Normal başlatıcı kısa durum mesajları ve karakter onayını gösterir. Ham
paketleri konsola yazmaz ve paket dökümü oluşturmaz. Yerel durum ve bilet
işlemi günlükleri `captures/` ve `work/` altında kalabilir.

Ayrıntılı teşhis gerekirse:

```powershell
.\.venv\Scripts\python.exe tools\start_clientless.py --diagnostics
```

Teşhis kayıtları oturum verisi içerebilir; paylaşmayın veya depoya eklemeyin.
