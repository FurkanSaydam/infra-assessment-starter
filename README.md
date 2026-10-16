# MFS Scanner

MFS Scanner, yalnızca açıkça tarama iznin bulunan IP/CIDR kapsamlarında kullanılmak üzere hazırlanmış Nmap tabanlı bir altyapı değerlendirme aracıdır.

## Kullanım

Hedefler `ip.txt` dosyasında, satır başına bir IP olacak şekilde; portlar `ports.txt` dosyasında olabilir:

```bash
python3 scanner.py -t ip.txt -p ports.txt
```

Örnek port dosyası:

```text
# yorumlar desteklenir
22,80,443
8000-8010
```

Kapsam dosyası `scope.txt` içinde izinli IP/CIDR ağları olmalıdır. Dosya boşsa tarama başlatılmaz. Her hedef scope içinde olmalıdır.

```text
python3 -m pip install -r requirements.txt
python3 scanner.py -t ip.txt -p ports.txt --scope-file scope.txt
```

`--profile standard` Nmap varsayılan NSE scriptlerini (`-sC`) ekler; bu nedenle daha fazla etkileşimlidir. Varsayılan `safe` profilini önce kontrollü lab ortamında doğrula.

## Çıktı

Her çalıştırma `result/YYYYMMDD_HHMMSS/` altında ayrı klasör oluşturur:
- `report.docx`, `report.pdf`, `summary.json`
- Her hedef için JSON raporu
- `logs/nmap.xml`, `nmap.txt`, `web.txt`, `smb.txt`, `rpc.txt`, `audit.jsonl`, `error.txt`
- Nmap'ın hedef başına ham XML ve ayrıntı logları `logs/` altında

Progress göstergesi hedef bazlıdır: bekleyen hedef, taranıyor, tamamlandı veya hata. Ara yüzde tarama sürecinin gerçek yüzdesi Nmap tarafından bu sürümde güvenilir şekilde alınmadığından yapay yüzde üretilmez.

## Sınırlar
Bu sürüm servis/port keşfi ve servis sınıflandırması yapar; web, SMB veya RPC için aktif özel güvenlik testleri uygulamaz. Açık port veya servis sürümü tek başına zafiyet kanıtı değildir.
