# Undercover
![Tests](https://github.com/Notron00/Undercover/actions/workflows/tests.yml/badge.svg)
![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-yellow)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

> [🇬🇧 English](README.md) | 🇹🇷 Türkçe

> Python ile yazılmış, eğitim amaçlı şifreli TCP sohbet uygulaması.

Undercover; ağ programlama, soket iletişimi, kriptografi ve güvenli iletişim protokollerini keşfetmek için geliştirilmiş bir istemci-sunucu TCP sohbet uygulamasıdır.

Proje, istemci ile sunucu arasında bir AES oturum anahtarını güvenli şekilde değişmek için RSA kullanır. Anahtar değişiminden sonra sohbet iletişimi AES-256-GCM ile şifrelenir.

## İçerikler

- [Features](#features)
- [Security Features](#security-features)
- [Architecture](#architecture)
- [Cryptographic Design](#cryptographic-design)
- [Installation](#installation)
- [Usage](#running-the-server)
- [Commands](#commands)
- [Security Considerations](#security-considerations)


## Özellikler

- İstemci-sunucu TCP mimarisi
- Çoklu istemci desteği
- Thread tabanlı istemci yönetimi
- RSA genel/özel anahtar çifti
- RSA ile şifrelenmiş AES oturum anahtarı değişimi
- AES-256-GCM ile şifrelenmiş sohbet mesajları
- Özel paket protokolü
- Kullanıcı adı yönetimi
- Tekrarlanan kullanıcı adı koruması
- Linux geliştirme ortamı
- Modüler proje yapısı

## Güvenlik Özellikleri

- **Hibrit şifreleme**: Oturum anahtarı değişimi için RSA-2048 (OAEP), mesajlar için AES-256-GCM
- **Authenticated encryption**: AES-GCM hem gizlilik hem bütünlük sağlar
- **MITM koruması**: TOFU tabanlı sunucu anahtarı pinning (SSH tarzı). İstemci, ilk bağlantıda sunucunun genel anahtar fingerprint'ini doğrular ve bilinen bir sunucunun anahtarı değişirse uyarır. Fingerprint argümanla da açıkça sabitlenebilir.
- **DoS sertleştirmesi**: Paket boyutu sınırları, aşırı büyük mesajları bellek ayrılmadan önce reddeder
- **Thread güvenli broadcast**: İstemci listesi kilit altında kopyalanır, ağ gönderiminden önce kilit bırakılır; böylece yavaş bir istemci tüm sunucuyu kilitleyemez
- **Uçtan uca şifreleme (özel mesajlar)**: `/msg` ile yapılan yazışmalar, X25519 Diffie-Hellman ile sunucunun asla göremediği ortak bir anahtar türetir. Sunucu özel mesajları taşır ama okuyamaz.
- **Safety number doğrulaması**: `/verify <kullanıcı>` komutu, ortak anahtardan türetilen bir güvenlik numarası gösterir. Bu numarayı karşı tarafla güvenilir bir kanaldan (telefon, yüz yüze) karşılaştırarak man-in-the-middle saldırısını tespit edebilirsiniz. Sunucu üzerinden doğrulama korumayı anlamsız kılacağından, doğrulama bilinçli olarak dış kanaldan (out-of-band) yapılır.
- **Sunucu tarafında metadata yok**: Sunucu hiçbir kullanıcı adı, mesaj, IP veya bağlantı bilgisi yazdırmaz — kimin kiminle konuştuğunu açığa çıkarabilecek hiçbir şey loglanmaz veya saklanmaz.
- **Uçtan uca şifrelemenin kapsamı**: E2E, özel mesajları pasif dinleyiciye ve kötü niyetli sunucuya karşı korur — *kullanıcıların safety number'ı dış kanaldan doğrulaması şartıyla*. Doğrulama yapılmazsa, ilk temasta araya giren aktif bir MITM henüz otomatik tespit edilemiyor. Oda (özel olmayan) mesajları yalnızca transport şifreleme kullanır (sunucu bunları okuyabilir). Henüz forward secrecy yok — bir oturum anahtarı sızarsa, o oturumun mesajları çözülebilir.


## Güvenlik Sertleştirmesi

Kod tabanı, yaygın sunucu taraflı güvenlik açıklarına karşı incelendi. Bulgular ve yapılanlar:

- **Kimlik doğrulama brute-force (düzeltildi):** Giriş denemeleri sadece bağlantı başına sınırlıydı; saldırgan tekrar bağlanıp denemeye devam edebiliyordu. IP başına ve hesap başına, geçici kilit penceresiyle rate limiting eklendi (bellekte, loglanmıyor). Hesap başına kilit, dağıtık (çok IP'li) saldırıları da engeller.
- **Connection-flood / slowloris DoS (düzeltildi):** Server her bağlantı için sınırsız thread açıyordu ve idle timeout yoktu. Eşzamanlı bağlantı sınırı (semaphore) ve el sıkışmayı zamanında tamamlamayan bağlantıları düşüren bir handshake timeout eklendi.
- **Mesaj replay (incelendi — düzeltme gerekmedi):** Replay zaten şu üç mekanizmayla engelleniyor: oturum başına AES anahtarı (yakalanan bir mesaj yeni oturumda çözülemez), bağlantı başına sequence number (eski sequence'ler reddedilir) ve kimlik doğrulama zorunluluğu (replay edilen bir handshake, geçerli kimlik olmadan chat mesajı gönderemez).
- **Sunucu tarafında loglama yok**: Sunucu hiçbir kullanıcı adı, mesaj, IP veya bağlantı metadata'sı yazdırmaz — kimin kiminle konuştuğunu açığa çıkarabilecek hiçbir şey loglanmaz veya saklanmaz.

## Mimari

```text
                     TCP BAĞLANTISI
İstemci  ──────────────────────────────────►  Sunucu
  │                                             │
  │          RSA Genel Anahtarı                 │
  │ ◄────────────────────────────────────────── │
  │                                             │
  │          AES Oturum Anahtarı                │
  │ ───────────── RSA ile Şifreli ───────────►  │
  │                                             │
  │          AES ile Şifreli Mesajlar           │
  │ ◄────────────────────────────────────────►  │
  │                                             │
```

## Kriptografik Tasarım

Undercover hibrit bir şifreleme yaklaşımı kullanır.

### 1. RSA

Sunucu bir RSA-2048 anahtar çifti üretir ve diske kaydeder (`server_key.pem`); böylece fingerprint'i yeniden başlatmalar arasında sabit kalır.

Sunucu genel anahtarını istemciye gönderir. İstemci, güvenmeden önce anahtarın SHA-256 fingerprint'ini doğrular (bkz. MITM koruması).

İstemci rastgele bir AES oturum anahtarı üretir ve bunu sunucunun RSA genel anahtarıyla (OAEP padding) şifreler.

Sunucu, AES anahtarını kendi RSA özel anahtarıyla çözer.

### 2. AES-256-GCM

Anahtar değişiminden sonra istemci ve sunucu sohbet iletişimi için AES oturum anahtarını kullanır.

AES-256-GCM kullanılır; bu hem gizlilik hem bütünlük sağlar (authenticated encryption). Her mesaj için yeni bir 12 baytlık nonce üretilir. Bu, her mesajı ayrı ayrı RSA ile şifrelemekten kaçınmayı sağlar.

## Proje Yapısı

```text
Undercover/
│
├── client.py
├── server.py
├── requirements.txt
├── README.md
├── .gitignore
│
└── modules/
    ├── __init__.py
    ├── crypto.py
    ├── protocol.py
    └── makeup.py
```

### `client.py`

Sunucu bağlantısı, RSA genel anahtarının alınması ve fingerprint doğrulaması, AES oturum anahtarı üretimi ve şifrelenmesi, kullanıcı adı kaydı, mesaj şifreleme/çözme ve kullanıcı girdisini yönetir.

### `server.py`

TCP sunucusu, istemci bağlantıları, RSA anahtarı üretimi/kalıcılığı, AES oturum anahtarı çözme, kullanıcı adı yönetimi, mesaj broadcast ve istemci thread'lerini yönetir.

### `modules/crypto.py`

Kriptografik fonksiyonları içerir: RSA/AES işlemleri, anahtar kalıcılığı ve genel anahtar fingerprint hesaplama.

### `modules/protocol.py`

Özel paket protokolünü (uzunluk önekli çerçeveleme) içerir; bellek tüketimi tabanlı DoS'u önlemek için boyut sınırları vardır.

### `modules/makeup.py`

Terminal arayüzü, renkler ve banner fonksiyonlarını içerir.

## Kurulum

Depoyu klonlayın:

```bash
git clone https://github.com/Notron00/Undercover.git
cd Undercover
```

Bir sanal ortam oluşturun ve bağımlılıkları kurun:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Sunucuyu Çalıştırma

Sunucuyu bir port ile başlatın:

```bash
python server.py 5555
```

İlk çalıştırmada sunucu bir RSA anahtar çifti üretip kaydeder, ardından genel anahtar fingerprint'ini yazdırır:

```text
[SERVER] Public key fingerprint:
  <64 karakterlik hex fingerprint>
[SERVER] Listening 0.0.0.0:5555
```

## İstemciyi Çalıştırma

Bağlanmak için:

```bash
python client.py 127.0.0.1 5555
```

İlk bağlantıda istemci sunucunun fingerprint'ini gösterir ve ona güvenip güvenmeyeceğinizi sorar (trust-on-first-use). Güvenilen sunucuları `~/.undercover_known_hosts` dosyasında hatırlar ve bir sunucunun anahtarı sonradan değişirse uyarır.

Bilinen bir fingerprint'i açıkça sabitlemek için (katı mod) üçüncü argüman olarak verin:

```bash
python client.py 127.0.0.1 5555 <fingerprint>
```

Başka bir makineden bağlanırken `127.0.0.1` yerine sunucunun IP adresini yazın.

Sunucuyu bir VDS üzerinde ya da yönlendirilmiş bir portta çalıştırabilirsiniz.
**TOR Hidden Service desteklenir**

### Komutlar

- `/join <oda> [şifre]` — bir odaya katıl veya oluştur (oluşturan odanın sahibi olur)
- `/setpass <şifre>` — oda sahibi odaya şifre koyar
- `/delpass` — oda sahibi odanın şifresini kaldırır
- `/quit` veya `/exit` — bağlantıyı kapat
- `/msg <kullanıcı> <mesaj>` — özel mesaj gönder

## Güvenlik Değerlendirmesi

Bu proje öncelikle ağ güvenliği ve kriptografi öğrenmek için geliştirilmiş eğitim amaçlı bir uygulamadır.

MITM koruması, DoS sertleştirmesi ve authenticated encryption içermesine rağmen, ek bir inceleme olmadan tam anlamıyla üretime hazır güvenli bir mesajlaşma uygulaması olarak değerlendirilmemelidir.

**Şifre hash'leme**: Oda ve kullanıcı şifreleri düz metin olarak değil, bcrypt hash'leri (salt'lı) olarak saklanır.


## Öğrenme Hedefleri

Proje şunları pratik etmek için geliştirildi:

- Python ağ programlama
- TCP soketleri
- İstemci-sunucu mimarisi
- Çoklu thread (multithreading)
- Simetrik kriptografi
- Asimetrik kriptografi
- Hibrit şifreleme
- Ağ protokolleri
- Key pinning ve fingerprint doğrulama
- Linux geliştirme
- Git ve GitHub

## Tamamlanan Güvenlik İyileştirmeleri

- [✓] AES-256-GCM authenticated encryption
- [✓] TOFU key pinning ile MITM koruması (SSH tarzı)
- [✓] Paket boyutu sınırları (DoS sertleştirmesi)
- [✓] Thread güvenli broadcast (lock contention yok)
- [✓] Fingerprint doğrulamalı kalıcı sunucu anahtarı
- [✓] Replay koruması (DoS sertleştirmesi)
- [✓] Şifre korumalı odalar için bcrypt hash'leme
- [✓] Sohbet odaları
- [✓] Kullanıcı kimlik doğrulama (user authentication)
- [✓] Özel mesajlaşma (private messaging)
- [✓] Server_key.pem dosyası artık sahip yetkisine sahip (0600 kuralı)
- [✓] Brute-force'a karşı rate limiting (IP + hesap kilidi)
- [✓] Flood/slowloris DoS'a karşı bağlantı sınırı ve handshake timeout
- [✓] Özel mesajlar için uçtan uca şifreleme (X25519 + AES-256-GCM)
- [✓] Safety number ile MITM doğrulaması
- [✓] Sessiz sunucu (metadata loglama yok)

## Gelecek Geliştirmele
- [ ] Double Ratchet
- [ ] Windows uyumluluğu