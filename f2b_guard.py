#!/usr/bin/env python3
"""fail2ban loglarını analiz edir, təhlükəli IP-ləri tapır və ufw blok əmrlərini göstərir.

Alət yalnız oxuyur: heç bir ufw qaydası dəyişmir, əmrləri siz özünüz işlədirsiniz.

İstifadə:
    sudo python3 f2b_guard.py                     # /var/log/fail2ban.log* (.gz daxil)
    sudo python3 f2b_guard.py --since 24h --top 10
    sudo python3 f2b_guard.py --whitelist 203.0.113.7 --whitelist 198.51.100.0/24
    sudo python3 f2b_guard.py --commands-only > block.sh
"""
from __future__ import annotations

import argparse
import glob
import gzip
import ipaddress
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta

DEFAULT_LOG_GLOB = "/var/log/fail2ban.log*"
PEAK_WINDOW_MINUTES = 10

# Risk həddləri: hər hansı bir şərt ödənsə, IP həmin səviyyəyə düşür.
CRITICAL = {"attempts": 100, "peak": 30, "bans": 3, "jails": 3}
HIGH = {"attempts": 20, "peak": 10, "bans": 2, "jails": 2}
MEDIUM = {"attempts": 5, "peak": 5, "bans": 1, "jails": 99}

RISK_ORDER = {"KRİTİK": 0, "YÜKSƏK": 1, "ORTA": 2, "TƏHLÜKƏSİZ": 3}
RISK_COLOR = {"KRİTİK": "1;31", "YÜKSƏK": "31", "ORTA": "33", "TƏHLÜKƏSİZ": "32"}
BLOCK_LEVELS = {"KRİTİK", "YÜKSƏK"}

# Bu jail-lər HTTP trafikini izləyir; Cloudflare/Docker arxasında ufw onları dayandırmır.
WEB_JAIL_RE = re.compile(r"nginx|apache|http|web|php|wordpress|wp-|caddy|traefik|bot", re.I)

# Mənbə: https://www.cloudflare.com/ips/
CLOUDFLARE_NETS = tuple(ipaddress.ip_network(net) for net in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
))

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+fail2ban\.\S+\s*\[\d+\]:\s+"
    r"\w+\s+\[(?P<jail>[\w.-]+)\]\s+(?P<msg>.*)$"
)
FOUND_RE = re.compile(r"^Found (?P<ip>\S+)(?: - (?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}))?")
BAN_RE = re.compile(r"^(?P<restore>Restore )?Ban (?P<ip>\S+)")
UNBAN_RE = re.compile(r"^Unban (?P<ip>\S+)")
# Yalnız bütün portları bağlayan qaydalar sayılır ("22/tcp DENY 1.2.3.4" tam blok deyil).
UFW_BLOCK_RE = re.compile(
    r"^Anywhere(?: \(v6\))?\s+(?:DENY|REJECT)(?: IN)?\s+(?P<src>[0-9a-fA-F:.]+(?:/\d+)?)(?:\s|$)"
)
WHO_IP_RE = re.compile(r"\(([0-9a-fA-F:.]+)\)\s*$")


@dataclass
class IpStats:
    ip: str
    attempts: list[datetime] = field(default_factory=list)
    jails: set[str] = field(default_factory=set)
    bans: int = 0
    banned_now: bool = False

    @property
    def first(self) -> datetime:
        return min(self.attempts)

    @property
    def last(self) -> datetime:
        return max(self.attempts)

    @property
    def minutes(self) -> float:
        return (self.last - self.first).total_seconds() / 60 if self.attempts else 0.0

    def peak(self, window_minutes: int = PEAK_WINDOW_MINUTES) -> int:
        """Sürüşən pəncərədə ən çox cəhd sayı."""
        times = sorted(self.attempts)
        window = timedelta(minutes=window_minutes)
        best = start = 0
        for end, moment in enumerate(times):
            while moment - times[start] > window:
                start += 1
            best = max(best, end - start + 1)
        return best


def parse_since(value: str) -> timedelta:
    match = re.fullmatch(r"(\d+)([mhd])", value.strip().lower())
    if not match:
        raise argparse.ArgumentTypeError("format: 30m, 24h və ya 7d")
    unit = {"m": "minutes", "h": "hours", "d": "days"}[match.group(2)]
    return timedelta(**{unit: int(match.group(1))})


def parse_network(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"yanlış IP/CIDR: {value}") from exc


def valid_ip(text: str) -> str | None:
    """Normallaşdırılmış IP qaytarır; bu, loga yazılmış zərərli mətnin əmrə düşməsinin qarşısını alır."""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def to_time(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")


def read_lines(path: str):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        yield from handle


def parse_logs(paths: list[str], cutoff: datetime | None) -> tuple[dict[str, IpStats], list[str]]:
    """Logları oxuyur. Ban vəziyyəti üçün hadisələr zamana görə düzülür (rotasiya olunmuş fayllar qarışıq gəlir)."""
    stats: dict[str, IpStats] = {}
    ban_events: list[tuple[datetime, str, str, bool]] = []
    warnings: list[str] = []

    for path in paths:
        try:
            for line in read_lines(path):
                match = LINE_RE.match(line)
                if not match:
                    continue
                logged_at = to_time(match["ts"])
                jail, msg = match["jail"], match["msg"]

                found = FOUND_RE.match(msg)
                if found:
                    ip = valid_ip(found["ip"])
                    moment = to_time(found["ts"]) if found["ts"] else logged_at
                    if ip and (cutoff is None or moment >= cutoff):
                        entry = stats.setdefault(ip, IpStats(ip))
                        entry.attempts.append(moment)
                        entry.jails.add(jail)
                    continue

                banned = BAN_RE.match(msg)
                unbanned = UNBAN_RE.match(msg)
                event = banned or unbanned
                ip = valid_ip(event["ip"]) if event else None
                if ip:
                    is_new_ban = bool(banned and not banned["restore"])
                    ban_events.append((logged_at, ip, jail, bool(banned)))
                    if is_new_ban and (cutoff is None or logged_at >= cutoff):
                        stats.setdefault(ip, IpStats(ip)).bans += 1
                        stats[ip].jails.add(jail)
        except (PermissionError, FileNotFoundError):
            raise
        except (OSError, EOFError) as exc:
            warnings.append(f"{path} tam oxunmadı: {exc}")

    active: dict[str, set[str]] = {}
    for _, ip, jail, is_ban in sorted(ban_events, key=lambda item: item[0]):
        (active.setdefault(ip, set()).add if is_ban else active.setdefault(ip, set()).discard)(jail)
    for ip, jails in active.items():
        if ip in stats:
            stats[ip].banned_now = bool(jails)

    return stats, warnings


def classify(entry: IpStats) -> str:
    values = {
        "attempts": len(entry.attempts),
        "peak": entry.peak(),
        "bans": entry.bans,
        "jails": len(entry.jails),
    }
    for name, limits in (("KRİTİK", CRITICAL), ("YÜKSƏK", HIGH), ("ORTA", MEDIUM)):
        if any(values[key] >= limits[key] for key in limits):
            return name
    return "TƏHLÜKƏSİZ"


def run_quiet(command: list[str]) -> str:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def active_session_ips() -> set[str]:
    """Hazırkı SSH sessiyalarının IP-ləri: admin səhvən özünü bloklamasın."""
    found = set()
    connection = os.environ.get("SSH_CONNECTION", "").split()
    if connection:
        found.add(connection[0])
    for line in run_quiet(["who"]).splitlines():
        match = WHO_IP_RE.search(line)
        if match:
            found.add(match.group(1))
    return {ip for ip in map(valid_ip, found) if ip}


def parse_ufw_blocks(status_output: str) -> list:
    networks = []
    for line in status_output.splitlines():
        match = UFW_BLOCK_RE.search(line)
        if match:
            try:
                networks.append(ipaddress.ip_network(match["src"], strict=False))
            except ValueError:
                pass
    return networks


def in_networks(ip: str, networks) -> bool:
    address = ipaddress.ip_address(ip)
    return any(address.version == net.version and address in net for net in networks)


def protected_reason(ip: str, whitelist, sessions: set[str]) -> str | None:
    address = ipaddress.ip_address(ip)
    if ip in sessions:
        return "sizin aktiv SSH sessiyanız"
    if in_networks(ip, whitelist):
        return "whitelist-dədir"
    if in_networks(ip, CLOUDFLARE_NETS):
        return "Cloudflare IP-si (blok saytı sındırar)"
    if not address.is_global:
        return "daxili/şəxsi şəbəkə"
    return None


def ufw_command(entry: IpStats) -> str:
    comment = f"f2b_guard {','.join(sorted(entry.jails))}"
    # "ufw deny" qaydanı sona əlavə edir və öncəki allow qaydası onu kölgədə qoyur; prepend ən başa yazır.
    return f"sudo ufw prepend deny from {entry.ip} comment {shlex.quote(comment)}"


def format_duration(minutes: float) -> str:
    if minutes < 1:
        return "<1 dəq"
    total = int(round(minutes))
    days, rest = divmod(total, 1440)
    hours, mins = divmod(rest, 60)
    if days:
        return f"{days} gün {hours} saat"
    if hours:
        return f"{hours} saat {mins} dəq"
    return f"{mins} dəq"


def activity(entry: IpStats) -> str:
    count = len(entry.attempts)
    return f"{count} sorğu / {format_duration(entry.minutes)}" if count else "yalnız ban qeydi"


def rate(entry: IpStats) -> str:
    if not entry.attempts:
        return "-"
    return f"{len(entry.attempts) / max(entry.minutes, 1):.1f}/dəq"


def build_paint(enabled: bool):
    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if enabled else text
    return paint


def render_table(headers, rows, colors, paint) -> None:
    widths = [max(len(str(row[col])) for row in [headers, *rows]) for col in range(len(headers))]
    print(paint("  ".join(head.ljust(width) for head, width in zip(headers, widths)).rstrip(), "1"))
    for row, color in zip(rows, colors):
        cells = [str(cell).ljust(width) for cell, width in zip(row, widths)]
        cells[0] = paint(cells[0], color)
        print("  ".join(cells).rstrip())


def attack_row(entry: IpStats, risk: str, already_blocked: bool) -> list[str]:
    if already_blocked:
        state = "ufw-də bloklanıb"
    elif entry.banned_now:
        state = "fail2ban banlayıb"
    else:
        state = "aktiv ban yoxdur"
    return [
        risk, entry.ip, activity(entry), rate(entry),
        entry.peak(), entry.bans, ",".join(sorted(entry.jails)), state,
    ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="fail2ban loglarından bot hücumlarını tapır və ufw blok əmrlərini göstərir (qaydaları özü dəyişmir)."
    )
    parser.add_argument("logs", nargs="*", help=f"log faylları (standart: {DEFAULT_LOG_GLOB})")
    parser.add_argument("--since", type=parse_since, metavar="MÜDDƏT", help="yalnız son müddət: 30m, 24h, 7d")
    parser.add_argument("--top", type=int, default=20, metavar="N", help="hər siyahıda neçə IP (0 = hamısı, standart 20)")
    parser.add_argument("--whitelist", type=parse_network, action="append", default=[], metavar="IP/CIDR",
                        help="heç vaxt blok təklif olunmayacaq IP/şəbəkə (təkrarlana bilər)")
    parser.add_argument("--commands-only", action="store_true", help="yalnız ufw əmrlərini çıxar (bütün riskli IP-lər)")
    parser.add_argument("--no-color", action="store_true", help="rəngsiz çıxış")
    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)

    paths = args.logs or sorted(glob.glob(DEFAULT_LOG_GLOB))
    if not paths:
        print(f"Xəta: log tapılmadı ({DEFAULT_LOG_GLOB}). fail2ban quraşdırılıb?", file=sys.stderr)
        return 1

    cutoff = datetime.now() - args.since if args.since else None
    try:
        stats, warnings = parse_logs(paths, cutoff)
    except PermissionError as exc:
        print(f"Xəta: {exc.filename} oxunmur. sudo ilə işlədin.", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"Xəta: fayl tapılmadı: {exc.filename}", file=sys.stderr)
        return 1
    for warning in warnings:
        print(f"Xəbərdarlıq: {warning}", file=sys.stderr)

    sessions = active_session_ips()
    ufw_blocks = parse_ufw_blocks(run_quiet(["ufw", "status"]))

    threats, safe = [], []
    for entry in stats.values():
        reason = protected_reason(entry.ip, args.whitelist, sessions)
        risk = classify(entry)
        if reason or risk == "TƏHLÜKƏSİZ":
            safe.append((entry, reason or "aşağı aktivlik, hücum əlaməti yoxdur"))
        else:
            threats.append((entry, risk))

    threats.sort(key=lambda item: (RISK_ORDER[item[1]], -len(item[0].attempts), -item[0].bans))
    safe.sort(key=lambda item: -len(item[0].attempts))

    to_block = [entry for entry, risk in threats
                if risk in BLOCK_LEVELS and not in_networks(entry.ip, ufw_blocks)]

    if args.commands_only:
        for entry in to_block:
            print(ufw_command(entry))
        return 0

    limit = args.top if args.top > 0 else None
    paint = build_paint(sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ)

    all_times = [moment for entry in stats.values() for moment in entry.attempts]
    print(paint("fail2ban hücum hesabatı", "1"))
    if all_times:
        print(f"Dövr: {min(all_times):%Y-%m-%d %H:%M} → {max(all_times):%Y-%m-%d %H:%M}")
    print(f"Qeydə alınan sorğu: {len(all_times)} | Unikal IP: {len(stats)} | "
          f"Təhlükəli: {len(threats)} | Təhlükəsiz: {len(safe)}")

    total_bans = sum(entry.bans for entry in stats.values())
    if total_bans and not all_times:
        print(paint("Diqqət: ban var, 'Found' sətri yoxdur. fail2ban loglevel-i INFO olmalıdır, "
                    "əks halda sorğu sayı hesablanmır.", "33"))

    print()
    if threats:
        print(paint("TƏHLÜKƏLİ IP-LƏR", "1"))
        shown = threats[:limit]
        render_table(
            ["RİSK", "IP", "FƏALİYYƏT", "TEMP", f"PİK/{PEAK_WINDOW_MINUTES}d", "BAN", "JAIL", "VƏZİYYƏT"],
            [attack_row(entry, risk, in_networks(entry.ip, ufw_blocks)) for entry, risk in shown],
            [RISK_COLOR[risk] for _, risk in shown],
            paint,
        )
        if len(threats) > len(shown):
            print(f"... daha {len(threats) - len(shown)} IP gizlədildi (--top 0 hamısını göstərir)")
    else:
        print(paint("Təhlükəli IP tapılmadı.", "32"))

    print()
    if to_block:
        shown_block = to_block[:limit]
        print(paint("UFW BLOK ƏMRLƏRİ (KRİTİK və YÜKSƏK)", "1"))
        for entry in shown_block:
            print(ufw_command(entry))
        if len(to_block) > len(shown_block):
            print(f"... daha {len(to_block) - len(shown_block)} əmr (--commands-only hamısını verir)")
        print("sudo ufw status numbered   # yoxlamaq üçün")
        if any(WEB_JAIL_RE.search(jail) for entry in to_block for jail in entry.jails):
            print()
            print(paint("Diqqət: bu IP-lərin bəziləri veb jail-dəndir. Server Cloudflare arxasındadırsa, "
                        "HTTP trafiki Cloudflare IP-lərindən gəlir;\nDocker portları da ufw-dən yan keçir. "
                        "Belə halda ufw bu hücumu dayandırmır, IP-ni Cloudflare WAF-da bloklayın.", "33"))
    elif threats:
        print(paint("Yeni blok lazım deyil: KRİTİK/YÜKSƏK IP yoxdur və ya hamısı artıq ufw-dədir.", "32"))

    if safe:
        print()
        print(paint("TƏHLÜKƏSİZ (blok lazım deyil)", "1"))
        shown_safe = safe[:limit]
        render_table(
            ["STATUS", "IP", "FƏALİYYƏT", "SƏBƏB"],
            [["TƏHLÜKƏSİZ", entry.ip, activity(entry), reason] for entry, reason in shown_safe],
            [RISK_COLOR["TƏHLÜKƏSİZ"]] * len(shown_safe),
            paint,
        )
        if len(safe) > len(shown_safe):
            print(f"... daha {len(safe) - len(shown_safe)} IP gizlədildi")

    print()
    print("Qeyd: 'sorğu' fail2ban-ın tutduğu uğursuz cəhddir, IP-nin bütün trafiki deyil.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
