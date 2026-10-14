# Scoped Infrastructure Assessment — MVP 0.1.0

Nmap tabanlı, kapsam kontrolü ve denetim kaydı bulunan bir başlangıç projesidir. **Yalnızca taramaya açıkça yetkili olduğun sistemlerde kullan.** Bu MVP tüm zafiyetleri bulduğunu iddia etmez.

## İçerik

- `scanner.py`: CLI ve scope doğrulaması
- `core.py`: Nmap komutunu güvenli argüman listesiyle çalıştırır; XML ve log çıktısı üretir
- `parser.py`: Nmap XML sonuçlarını JSON'a dönüştürür
- `audit.py`: JSONL denetim kaydı
- `web.py`, `smb.py`: Tespit edilen servisleri sonraki fazlara hazırlamak için sınıflandırır; henüz aktif web/SMB testi yapmaz
- `config.py`: varsayılanlar
- `scope.txt`: yetkili IP/CIDR kapsamı
- `targets.txt`: isteğe bağlı hedef listesi

## 1. Ön kontrol

```bash
nmap --version
python3 --version
python3 -m py_compile scanner.py core.py parser.py web.py smb.py audit.py ui.py config.py
```

İlk MVP, Python standart kütüphanesini kullanır; terminal arayüzü için `rich` opsiyoneldir. Paket kurmak zorunda değilsin. `requirements.txt` doğru dosya adıdır.

## 2. Scope tanımla

`scope.txt` içine yalnızca izinli IP adreslerini veya CIDR ağlarını yaz. Örnek:

```text
192.168.56.0/24
```

Bu sadece örnek özel ağ aralığıdır; kendi lab topolojinle değiştir. Dosya boşken tarama çalışmaz. Her hedef, scope içindeki bir IP olmak zorundadır. İlk sürüm hedef olarak IP kabul eder; hostname ve hedef CIDR kabul etmez.

## 3. İlk, daha düşük etkili deneme

Önce kendi izole lab VM'inin IP adresini scope ve hedef olarak gir. Yalnızca seçili portları taramak için:

```bash
python3 scanner.py -t 192.168.56.10 --scope-file scope.txt -p 22,80,443 --profile safe
```

`192.168.56.10` örnektir; gerçek lab IP'nle değiştir. `safe` profili `-sV --version-light` kullanır. Bu da hedefe ağ trafiği gönderir; yalnızca izinli hedeflerde çalıştır.

## 4. Standart profil

```bash
python3 scanner.py -t 192.168.56.10 --scope-file scope.txt -p 22,80,443 --profile standard
```

`standard` profili `-sC` ekler. `-sC`, Nmap'in varsayılan NSE scriptlerini çalıştırır; tamamen pasif değildir. Önce lab'de test et. Bu MVP bilerek `vuln`, `exploit`, `intrusive`, `http*` veya `smb*` kategorilerini topluca çalıştırmaz.

`-p` doğrudan port listesi (`-p 22,80,443`) veya port dosyası (`-p ports.txt`) kabul eder. Port dosyasında portları virgülle, boşlukla, tab ile veya alt alta yazabilirsin; boş satırlar ve `#` yorumları yok sayılır. Örnek:

```text
22 80 443
445
8000-8100
```

Dosya içeriği Nmap'e virgülle ayrılmış biçimde aktarılır; portlar doğrulanır ve tekrar eden değerler ayıklanır. Port belirtmezsen Nmap'in ilk 1000 yaygın TCP portu taranır. UDP taraması bu MVP'de yapılmaz.

## 5. Birden fazla hedef

`targets.txt` içine satır başına IP koy ve her IP'nin `scope.txt` içinde tanımlanan bir aralığa düştüğünü doğrula:

```bash
python3 scanner.py --target-file targets.txt --scope-file scope.txt --profile safe
```

## 6. Çıktılar

`output/` altında:
- Her hedef için Nmap XML çıktısı
- Hedef başına JSON raporu
- Nmap stdout/stderr ve komut bilgilerini içeren log
- `audit.jsonl` denetim olayları

JSON'daki `status: incomplete`, taramanın başarılı tamamlandığı doğrulanamadığında kullanılır. Hata veya timeout durumlarını “temiz sonuç” olarak yorumlama.

## Sınırlar / sonraki fazlar

- Bu sürüm bir CVE eşleştiricisi değildir; yerel CVE DB henüz bağlanmadı.
- Sürüm tespiti tek başına CVE etkilenimini kanıtlamaz. Dağıtım/vendor backport'ları, yapılandırma ve doğrulama gerekir.
- Web/SMB modülleri bu sürümde yalnızca servis sınıflandırması yapar; aktif HTTP/SMB kontrolleri çalıştırmaz.
- Metasploit entegrasyonu ve exploit doğrulaması yoktur.
- Nmap XML, hedef erişilebilirliği, port kapsamı ve NSE çıktıları birlikte değerlendirilmelidir. Hiçbir tarayıcı “asla bulgu kaçırmama” garantisi veremez.
- Gerçek kurumsal ortama taşımadan önce kurumun kod, veri, GitHub ve AI araçları politikalarını kontrol et; gerçek IP'leri ve tarama çıktısını kişisel repoya koyma.
