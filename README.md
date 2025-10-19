
---

````markdown
# 🕵️ SBHunter — Smart Subdomain Hunter

Modern, hızlı ve kullanıcı dostu **subdomain keşif aracı**.  
Pasif OSINT + aktif brute-force + wildcard tespiti + canlılık doğrulaması (httpx) — hepsi tek komutta.

---

## 🚀 Özellikler

- 🔍 **Amass (passive)** otomatik çalışır  
- 🧩 **Tüm araç çıktıları birleşir:** `subdomains/*.txt` → unique → `final.txt`  
- 🌐 **Canlılık doğrulaması:** `final.txt` → **httpx** → `final_alive.txt`  
- 🧠 **Wildcard filtresi:** Yalancı pozitifleri otomatik eler  
- ⚙️ **Fallback mekanizması:** `puredns`/`dnsx` yoksa gömülü `dig` döngüsü  
- 🎨 **Kullanıcı dostu arayüz:** `--pretty` ile renkli, bölümlenmiş çıktı  
- 🧱 **Eksik araç yoksa bile durmaz:** Eksikler raporlanır, akış devam eder  

---

## 📦 Kurulum

```bash
git clone https://github.com/serkanbenol/sbhunter.git
cd sbhunter
chmod +x sbhunter.py
````

> Gereksinimler (isteğe bağlı ama önerilir):
> `amass`, `subfinder`, `assetfinder`, `findomain`, `chaos`, `dnsx`, `puredns`, `httpx`, `ffuf`, `gobuster`

---

## ⚡️ Kullanım

Tek domain:

```bash
./sbhunter.py -d example.com --auto --pretty
```

Domain listesi (satır başına 1 domain):

```bash
./sbhunter.py --auto -f targets.txt --pretty
```

Brute-force dahil:

```bash
./sbhunter.py -d example.com --auto --bruteforce --pretty
```

Amass **aktif** tarama (opsiyonel, uzun sürebilir):

```bash
./sbhunter.py -d example.com --auto --amass-active --pretty
```

Özel resolver (fallback `dig` için):

```bash
./sbhunter.py -d example.com --auto --resolver 8.8.8.8 --pretty
```

---

## 🔄 Çalışma Aşamaları

1. **Subdomain Enumeration**

   * `assetfinder`, `sublist3r`, `subfinder`, `chaos`, `findomain`, `amass (passive)`
   * (İsteğe bağlı) `puredns`, `dnsx`, ya da fallback `dig` loop
2. **Overlay Prefix → DNS**
   `vpn`, `sso`, `admin` gibi ön eklerle yeni adaylar
3. **Validation & Wildcard Filtering**
4. **VHOST & Dir Brute** (isteğe bağlı, `ffuf` veya `gobuster`)
5. **Unique Merge → final.txt**
6. **HTTPX Alive Scan → final_alive.txt**
7. **Sonuç Özeti**: renkli, sade, okunaklı çıktı

---

## 📁 Çıktı Yapısı

```
example.com_2025-10/
├─ subdomains/
│  ├─ assetfinder.txt
│  ├─ chaos.txt
│  ├─ amass_passive.txt
│  ├─ ...
├─ raw_outputs/
│  ├─ amass_passive.txt
│  ├─ bruteforce_puredns.txt
│  └─ ...
├─ validated.txt
├─ validated_filtered.txt
├─ wildcard_info.txt
├─ final.txt
└─ final_alive.txt
```

---

## 💡 Parametreler

| Parametre                | Açıklama                    |
| ------------------------ | --------------------------- |
| `-d` / `--domain`        | Tek domain                  |
| `-f` / `--file`          | Domain listesi              |
| `--auto`                 | Tüm akışı otomatik çalıştır |
| `--bruteforce`           | DNS brute-force ekle        |
| `--amass-active`         | Amass aktif modu            |
| `-w` / `--wordlist`      | DNS wordlist yolu           |
| `-aw` / `--alt-wordlist` | VHOST/dir/overlay wordlist  |
| `--resolver`             | `dig` fallback resolver     |
| `--pretty`               | Renkli, başlıklı çıktı      |

---

## 🎯 Örnek Çıktı

```
============================================================
Chaos
------------------------------------------------------------
api.tesla.com
dev.tesla.com
www.tesla.com

============================================================
Amass_passive
------------------------------------------------------------
mail.tesla.com
sso.tesla.com
...

============================================================
[FINAL CANDIDATES] (24)
[FINAL ALIVE] (17)
============================================================
```

---

## ⚠️ Yasal Uyarı

Bu araç **yalnızca yetkili sızma testleri** ve **eğitim amaçlı** kullanılmalıdır.
Yetkisiz taramalar yasa dışıdır ve tüm sorumluluk kullanıcıya aittir.

---


```
