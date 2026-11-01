# f2b_guard

fail2ban loglarından bot hücumlarını tapan və hansı IP-lər üçün hansı `ufw` əmrini yazmağı göstərən sadə CLI aləti.

Alət yalnız oxuyur: `ufw` qaydalarını özü dəyişmir, əmrləri siz baxıb işlədirsiniz.

## Nə edir?

- Ən aktiv hücumçu IP-ləri tapır
- Hər IP-nin neçə dəqiqədə neçə sorğu göndərdiyini göstərir
- IP-ləri riskinə görə ayırır: `KRİTİK`, `YÜKSƏK`, `ORTA`, `TƏHLÜKƏSİZ`
- `KRİTİK` və `YÜKSƏK` IP-lər üçün hazır `ufw` əmri yazır
- Köhnə logları da oxuyur (`.gz` daxil)

## Tələblər

- Ubuntu 20.04 və ya daha yeni
- Python 3.8+
- fail2ban və ufw

Əlavə Python paketi lazım deyil.

## İstifadə

```bash
sudo python3 f2b_guard.py
```

| Nümunə | Nə edir |
|---|---|
| `--since 24h` | Yalnız son 24 saatı göstərir (`30m`, `24h`, `7d`) |
| `--top 10` | Hər siyahıda 10 IP göstərir (`0` = hamısı) |
| `--whitelist 203.0.113.7` | Bu IP və ya şəbəkə üçün blok əmri vermir (təkrarlana bilər) |
| `--commands-only` | Yalnız bütün `ufw` əmrlərini çıxarır |
| `--no-color` | Rəngsiz çıxış verir |

Başqa log faylını yoxlamaq üçün yolunu yazın:

```bash
sudo python3 f2b_guard.py /path/to/fail2ban.log
```

## Nümunə çıxış

```text
RİSK    IP            FƏALİYYƏT           TEMP      PİK/10d  BAN  JAIL  VƏZİYYƏT
KRİTİK  45.33.32.156  150 sorğu / 15 dəq  10.1/dəq  101      1    sshd  fail2ban banlayıb

UFW BLOK ƏMRLƏRİ (KRİTİK və YÜKSƏK)
sudo ufw prepend deny from 45.33.32.156 comment 'f2b_guard sshd'

TƏHLÜKƏSİZ (blok lazım deyil)
TƏHLÜKƏSİZ  9.9.9.9  2 sorğu / 30 dəq  aşağı aktivlik, hücum əlaməti yoxdur
```

## Risk qaydaları

Şərtlərdən biri ödənsə, IP həmin səviyyəyə düşür:

| Səviyyə | Sorğu | 10 dəqiqədə pik | Ban | Jail |
|---|---|---|---|---|
| `KRİTİK` | 100+ | 30+ | 3+ | 3+ |
| `YÜKSƏK` | 20+ | 10+ | 2+ | 2+ |
| `ORTA` | 5+ | 5+ | 1+ | – |
| `TƏHLÜKƏSİZ` | daha az | daha az | 0 | – |

Həddləri `f2b_guard.py` faylının əvvəlində dəyişə bilərsiniz.

Bu IP-lərə aktivliyindən asılı olmayaraq blok əmri verilmir:

- Aktiv SSH sessiyanızın IP-si
- `--whitelist` ilə verilən IP-lər
- Cloudflare IP-ləri
- Daxili şəbəkə IP-ləri

## Bilməli olduqlarınız

- **Sorğu sayı:** bu, bütün trafik deyil, fail2ban-ın tutduğu uğursuz cəhdlərdir. Sayın görünməsi üçün fail2ban `loglevel` dəyəri `INFO` olmalıdır.
- **Cloudflare və Docker:** veb trafik Cloudflare-dən keçirsə və ya port Docker ilə açılıbsa, `ufw` hücumu dayandırmaya bilər. Belə halda IP-ni Cloudflare WAF-da bloklayın.
- **"Təhlükəsiz" zəmanət deyil:** bu, sadəcə logda hücum əlaməti tapılmadığını bildirir.
