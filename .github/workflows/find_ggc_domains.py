#!/usr/bin/env python3
"""
find_ggc_domains.py

Ищет в hosts.txt строки, похожие на имена Google Global Cache (GGC), вида:
    rr4---sn-5hne6n6l.googlevideo.com

Разбирает такие имена на составные части (префикс, номер сервера, "sn-код",
доменный суффикс), собирает по всем найденным именам "закономерность"
(какие позиции внутри кода варьируются, какие номера серверов встречались),
на основе этого генерирует кандидатов новых имён и проверяет их через
несколько независимых DNS-резолверов (Cloudflare, Google, Quad9, MAXnet).

Новые имена, которые ответили хотя бы у одного резолвера, дописываются
в конец hosts.txt (без дублей).

Использование:
    python3 find_ggc_domains.py
    python3 find_ggc_domains.py --hosts-file /path/to/hosts.txt --max-num 60
"""

from __future__ import annotations

import argparse
import itertools
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    import dns.resolver
    import dns.exception
except ImportError:
    sys.exit(
        "Нужен пакет dnspython. Установи: pip install dnspython --break-system-packages"
    )


# --------------------------------------------------------------------------
# DNS-резолверы, через которые проверяем существование домена.
# Впиши свой IP для MAXnet Systems, если он у тебя есть — иначе эта запись
# просто будет пропускаться (см. resolve_via()).
# --------------------------------------------------------------------------
RESOLVERS: dict[str, list[str]] = {
    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
    "Google": ["8.8.8.8", "8.8.4.4"],
    "Quad9": ["9.9.9.9", "149.112.112.112"],
    # TODO: заполни реальный IP публичного/локального резолвера MAXnet Systems.
    # Пока оставлено пустым и в проверке пропускается.
    "MAXnet Systems": [],
}

# Шаблон типового имени GGC-редиректора: rr4---sn-5hne6n6l.googlevideo.com
GGC_RE = re.compile(
    r"^(?P<pre>[a-z]{1,4})(?P<num>\d{1,3})---sn-(?P<code>[a-z0-9]+)\.(?P<suffix>[a-z0-9.-]+)$"
)

DNS_TIMEOUT = 3.0
DNS_RETRIES = 1
QUERY_DELAY = 0.15  # пауза между запросами, чтобы не долбить резолверы очередями


@dataclass
class GGCName:
    raw: str
    pre: str
    num: int
    code: str
    suffix: str


@dataclass
class Pattern:
    pre: str
    suffix: str
    numbers: set[int] = field(default_factory=set)
    codes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Чтение hosts.txt и разбор имён
# --------------------------------------------------------------------------

def read_existing_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def extract_hostname(line: str) -> str | None:
    """Из строки hosts.txt достаёт вероятное имя хоста (последнее слово,
    если строка вида "IP hostname", либо само слово, если строка — просто домен).
    Комментарии и пустые строки игнорируются."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    candidate = parts[-1]
    # грубая проверка, что это похоже на домен
    if "." in candidate and re.match(r"^[a-z0-9.\-]+$", candidate, re.IGNORECASE):
        return candidate.lower()
    return None


def parse_ggc(hostname: str) -> GGCName | None:
    m = GGC_RE.match(hostname)
    if not m:
        return None
    return GGCName(
        raw=hostname,
        pre=m.group("pre"),
        num=int(m.group("num")),
        code=m.group("code"),
        suffix=m.group("suffix"),
    )


# --------------------------------------------------------------------------
# Сбор закономерностей и генерация кандидатов
# --------------------------------------------------------------------------

def collect_patterns(names: list[GGCName]) -> dict[tuple[str, str], Pattern]:
    """Группирует найденные имена по (pre, suffix) — то есть по типу
    редиректора и домену — и собирает встреченные номера серверов и коды."""
    patterns: dict[tuple[str, str], Pattern] = {}
    for n in names:
        key = (n.pre, n.suffix)
        p = patterns.setdefault(key, Pattern(pre=n.pre, suffix=n.suffix))
        p.numbers.add(n.num)
        if n.code not in p.codes:
            p.codes.append(n.code)
    return patterns


def variable_code_positions(codes: list[str]) -> list[set[str]] | None:
    """Если все коды одной длины — возвращает список множеств символов,
    встречавшихся в каждой позиции (позиции без вариаций содержат один символ).
    Так мы находим, какие "буквы" в sn-коде меняются между известными узлами."""
    lengths = {len(c) for c in codes}
    if len(lengths) != 1:
        return None  # разной длины коды — не мутируем посимвольно, слишком рискованно
    length = lengths.pop()
    positions: list[set[str]] = [set() for _ in range(length)]
    for c in codes:
        for i, ch in enumerate(c):
            positions[i].add(ch)
    return positions


def generate_code_candidates(codes: list[str], max_candidates: int) -> list[str]:
    """Генерирует новые sn-коды, комбинируя символы, которые реально
    наблюдались в известных кодах на каждой позиции. Если вариативность
    слишком велика (комбинаций больше max_candidates), просто возвращает
    исходные коды без мутаций — брутфорсить рандомные хэши бессмысленно."""
    if len(codes) < 2:
        return list(codes)
    positions = variable_code_positions(codes)
    if positions is None:
        return list(codes)

    variable_idx = [i for i, s in enumerate(positions) if len(s) > 1]
    if not variable_idx:
        return list(codes)

    # оцениваем размер комбинаторики
    combo_size = 1
    for i in variable_idx:
        combo_size *= len(positions[i])
        if combo_size > max_candidates:
            return list(codes)  # слишком много вариантов — не гадаем

    template = list(codes[0])
    variants = [sorted(positions[i]) for i in variable_idx]
    results = []
    for combo in itertools.product(*variants):
        candidate = template[:]
        for idx, ch in zip(variable_idx, combo):
            candidate[idx] = ch
        results.append("".join(candidate))
    # исходные коды тоже включаем
    for c in codes:
        if c not in results:
            results.append(c)
    return results[:max_candidates]


def generate_candidates(
    patterns: dict[tuple[str, str], Pattern],
    max_num: int,
    max_code_candidates: int,
    known_hostnames: set[str],
) -> list[str]:
    candidates: list[str] = []
    for (pre, suffix), p in patterns.items():
        seen_numbers = p.numbers
        # диапазон номеров: от 1 до max(увиденный номер, max_num)
        num_range = range(1, max(max(seen_numbers, default=0) + 1, max_num + 1))
        code_variants = generate_code_candidates(p.codes, max_code_candidates)
        for code in code_variants:
            for num in num_range:
                host = f"{pre}{num}---sn-{code}.{suffix}"
                if host not in known_hostnames and host not in candidates:
                    candidates.append(host)
    return candidates


# --------------------------------------------------------------------------
# DNS-проверка
# --------------------------------------------------------------------------

def resolve_via(hostname: str, resolver_ips: list[str]) -> bool:
    if not resolver_ips:
        return False
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = resolver_ips
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    for rtype in ("A", "AAAA"):
        for attempt in range(DNS_RETRIES + 1):
            try:
                answer = r.resolve(hostname, rtype)
                if len(answer) > 0:
                    return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                break  # домен точно не существует / нет записи этого типа — не ретраим
            except dns.exception.Timeout:
                continue
            except Exception:
                break
    return False


def check_candidate(hostname: str) -> list[str]:
    """Возвращает список названий провайдеров, у которых домен резолвится."""
    hits = []
    for provider, ips in RESOLVERS.items():
        if resolve_via(hostname, ips):
            hits.append(provider)
        time.sleep(QUERY_DELAY)
    return hits


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--hosts-file",
        type=Path,
        default=Path(__file__).resolve().parent / "hosts.txt",
        help="путь к hosts.txt (по умолчанию — рядом со скриптом)",
    )
    parser.add_argument("--max-num", type=int, default=40, help="максимальный номер сервера rrN для перебора")
    parser.add_argument(
        "--max-code-candidates",
        type=int,
        default=200,
        help="предохранитель: сколько максимум вариантов sn-кода генерировать на один шаблон",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="только показать, что было бы добавлено, не писать в файл",
    )
    args = parser.parse_args()

    lines = read_existing_lines(args.hosts_file)
    known_hostnames: set[str] = set()
    ggc_names: list[GGCName] = []

    for line in lines:
        host = extract_hostname(line)
        if not host:
            continue
        known_hostnames.add(host)
        parsed = parse_ggc(host)
        if parsed:
            ggc_names.append(parsed)

    if not ggc_names:
        print("В hosts.txt не найдено ни одного имени в формате GGC (rrN---sn-XXXX.domain). Нечего анализировать.")
        return

    patterns = collect_patterns(ggc_names)
    print(f"Найдено {len(ggc_names)} GGC-имён, {len(patterns)} групп(а) по (префикс, домен):")
    for (pre, suffix), p in patterns.items():
        print(f"  {pre}*---sn-*.{suffix}: номера={sorted(p.numbers)}, кодов={len(p.codes)}")

    candidates = generate_candidates(patterns, args.max_num, args.max_code_candidates, known_hostnames)
    print(f"\nСгенерировано {len(candidates)} кандидатов для проверки в DNS...\n")

    found: list[str] = []
    for i, host in enumerate(candidates, 1):
        hits = check_candidate(host)
        status = f"OK ({', '.join(hits)})" if hits else "нет"
        print(f"[{i}/{len(candidates)}] {host} -> {status}")
        if hits:
            found.append(host)

    if not found:
        print("\nНичего нового не найдено.")
        return

    print(f"\nНайдено {len(found)} новых существующих доменов:")
    for h in found:
        print(f"  {h}")

    if args.dry_run:
        print("\n(--dry-run: файл не изменён)")
        return

    with args.hosts_file.open("a", encoding="utf-8") as f:
        for h in found:
            f.write(f"{h}\n")
    print(f"\nДобавлено в {args.hosts_file}")


if __name__ == "__main__":
    main()
