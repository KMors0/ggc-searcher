#!/usr/bin/env python3
from __future__ import annotations

import argparse
import itertools
import json
import re
import subprocess
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


RESOLVERS: dict[str, list[str]] = {
    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
    "Google": ["8.8.8.8", "8.8.4.4"],
    "Quad9": ["9.9.9.9", "149.112.112.112"],
 "MAXnet Systems": ["195.112.96.21", "195.112.112.1"],
}

GGC_RE = re.compile(
    r"^(?P<pre>[a-z]{1,4})(?P<num>\d{1,3})---sn-(?P<code>[a-z0-9]+)\.(?P<suffix>[a-z0-9.-]+)$"
)

DNS_TIMEOUT = 3.0
DNS_RETRIES = 1
QUERY_DELAY = 0.15


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
# hosts.txt
# --------------------------------------------------------------------------

def read_existing_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def extract_hostname(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    candidate = parts[-1]
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
# закономерности / генерация кандидатов
# --------------------------------------------------------------------------

def collect_patterns(names: list[GGCName]) -> dict[tuple[str, str], Pattern]:
    patterns: dict[tuple[str, str], Pattern] = {}
    for n in names:
        key = (n.pre, n.suffix)
        p = patterns.setdefault(key, Pattern(pre=n.pre, suffix=n.suffix))
        p.numbers.add(n.num)
        if n.code not in p.codes:
            p.codes.append(n.code)
    return patterns


def variable_code_positions(codes: list[str]) -> list[set[str]] | None:
    lengths = {len(c) for c in codes}
    if len(lengths) != 1:
        return None
    length = lengths.pop()
    positions: list[set[str]] = [set() for _ in range(length)]
    for c in codes:
        for i, ch in enumerate(c):
            positions[i].add(ch)
    return positions


def generate_code_candidates(codes: list[str], max_candidates: int) -> list[str]:
    if len(codes) < 2:
        return list(codes)
    positions = variable_code_positions(codes)
    if positions is None:
        return list(codes)
    variable_idx = [i for i, s in enumerate(positions) if len(s) > 1]
    if not variable_idx:
        return list(codes)
    combo_size = 1
    for i in variable_idx:
        combo_size *= len(positions[i])
        if combo_size > max_candidates:
            return list(codes)
    template = list(codes[0])
    variants = [sorted(positions[i]) for i in variable_idx]
    results = []
    for combo in itertools.product(*variants):
        candidate = template[:]
        for idx, ch in zip(variable_idx, combo):
            candidate[idx] = ch
        results.append("".join(candidate))
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
        num_range = range(1, max(max(seen_numbers, default=0) + 1, max_num + 1))
        code_variants = generate_code_candidates(p.codes, max_code_candidates)
        for code in code_variants:
            for num in num_range:
                host = f"{pre}{num}---sn-{code}.{suffix}"
                if host not in known_hostnames and host not in candidates:
                    candidates.append(host)
    return candidates


# --------------------------------------------------------------------------
# кэш уже проверенных кандидатов (чтобы не пере-долбить одно и то же)
# --------------------------------------------------------------------------

def load_cache(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_cache(path: Path, cache: dict) -> None:
    path.write_text(json.dumps(cache, ensure_ascii=False, indent=0), encoding="utf-8")


def cache_is_fresh(entry: dict, recheck_after_days: float) -> bool:
    age_days = (time.time() - entry.get("ts", 0)) / 86400
    return age_days < recheck_after_days


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
        for _ in range(DNS_RETRIES + 1):
            try:
                answer = r.resolve(hostname, rtype)
                if len(answer) > 0:
                    return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                break
            except dns.exception.Timeout:
                continue
            except Exception:
                break
    return False


def check_candidate(hostname: str) -> list[str]:
    hits = []
    for provider, ips in RESOLVERS.items():
        if resolve_via(hostname, ips):
            hits.append(provider)
        time.sleep(QUERY_DELAY)
    return hits


# --------------------------------------------------------------------------
# git
# --------------------------------------------------------------------------

def run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True
    )


def git_commit_and_push(repo_dir: Path, hosts_file: Path, message: str) -> None:
    """Коммитит и пушит текущее состояние hosts.txt. Тихо ничего не делает,
    если это не git-репозиторий (например, при локальном тестовом запуске)."""
    status = run_git(["rev-parse", "--is-inside-work-tree"], repo_dir)
    if status.returncode != 0:
        return  # не git-репозиторий — просто пропускаем

    run_git(["config", "user.name", "github-actions[bot]"], repo_dir)
    run_git(["config", "user.email", "github-actions[bot]@users.noreply.github.com"], repo_dir)

    diff = run_git(["diff", "--quiet", "--", str(hosts_file)], repo_dir)
    if diff.returncode == 0:
        return  # изменений нет

    run_git(["add", str(hosts_file)], repo_dir)
    commit = run_git(["commit", "-m", message], repo_dir)
    if commit.returncode != 0:
        print(f"  [git] commit не удался: {commit.stderr.strip()}")
        return
    push = run_git(["push"], repo_dir)
    if push.returncode != 0:
        print(f"  [git] push не удался: {push.stderr.strip()}")
    else:
        print(f"  [git] закоммичено и запушено: {message}")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    script_dir = Path(__file__).resolve().parent
    parser.add_argument("--hosts-file", type=Path, default=script_dir / "hosts.txt")
    parser.add_argument("--cache-file", type=Path, default=script_dir / "ggc_checked_cache.json")
    parser.add_argument("--max-num", type=int, default=40)
    parser.add_argument("--max-code-candidates", type=int, default=200)
    parser.add_argument("--recheck-after-days", type=float, default=7,
                         help="сколько дней не проверять повторно кандидата, который уже проверялся")
    parser.add_argument("--commit-every", type=int, default=5,
                         help="коммитить после каждых N новых находок")
    parser.add_argument("--commit-interval-sec", type=int, default=600,
                         help="а также коммитить, если прошло столько секунд с последнего коммита (и есть что коммитить)")
    parser.add_argument("--max-runtime-min", type=float, default=300,
                         help="максимальное время работы одного запуска в минутах; по истечении — "
                              "коммитим найденное и выходим, следующий cron-запуск продолжит")
    parser.add_argument("--dry-run", action="store_true", help="не писать в файл и не коммитить")
    args = parser.parse_args()

    repo_dir = args.hosts_file.resolve().parent
    deadline = time.monotonic() + args.max_runtime_min * 60

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
        print("В hosts.txt не найдено ни одного имени в формате GGC. Нечего анализировать.")
        return

    patterns = collect_patterns(ggc_names)
    print(f"Найдено {len(ggc_names)} GGC-имён, {len(patterns)} групп(а):")
    for (pre, suffix), p in patterns.items():
        print(f"  {pre}*---sn-*.{suffix}: номера={sorted(p.numbers)}, кодов={len(p.codes)}")

    all_candidates = generate_candidates(patterns, args.max_num, args.max_code_candidates, known_hostnames)

    cache = load_cache(args.cache_file)
    candidates = [
        c for c in all_candidates
        if not (c in cache and cache_is_fresh(cache[c], args.recheck_after_days))
    ]
    skipped = len(all_candidates) - len(candidates)
    print(f"\nВсего кандидатов: {len(all_candidates)}, из кэша (недавно проверялись) пропущено: {skipped}, "
          f"к проверке: {len(candidates)}\n")

    found_since_commit = 0
    total_found = 0
    last_commit_time = time.monotonic()

    def maybe_commit(reason: str) -> None:
        nonlocal found_since_commit, last_commit_time
        if args.dry_run or found_since_commit == 0:
            return
        git_commit_and_push(
            repo_dir, args.hosts_file,
            f"ggc-scan: +{found_since_commit} домен(ов) ({reason})",
        )
        found_since_commit = 0
        last_commit_time = time.monotonic()

    hosts_fh = None
    if not args.dry_run:
        hosts_fh = args.hosts_file.open("a", encoding="utf-8")

    try:
        for i, host in enumerate(candidates, 1):
            if time.monotonic() > deadline:
                print(f"\nВышли из бюджета времени ({args.max_runtime_min} мин) на {i}/{len(candidates)}. "
                      f"Коммитим и завершаемся — продолжим в следующем запуске.")
                break

            hits = check_candidate(host)
            cache[host] = {"ts": time.time(), "found": bool(hits)}

            status = f"OK ({', '.join(hits)})" if hits else "нет"
            print(f"[{i}/{len(candidates)}] {host} -> {status}")

            if hits:
                total_found += 1
                found_since_commit += 1
                if hosts_fh:
                    hosts_fh.write(f"{host}\n")
                    hosts_fh.flush()

                if found_since_commit >= args.commit_every:
                    maybe_commit("по числу находок")

            if time.monotonic() - last_commit_time >= args.commit_interval_sec:
                maybe_commit("по времени")

            # периодически сохраняем кэш проверок (даже отрицательных),
            # чтобы при обрыве не терять уже проделанную работу
            if i % 20 == 0 and not args.dry_run:
                save_cache(args.cache_file, cache)
    finally:
        if hosts_fh:
            hosts_fh.close()

    if not args.dry_run:
        save_cache(args.cache_file, cache)
        maybe_commit("финальный коммит")

    print(f"\nИтого новых доменов за этот запуск: {total_found}")
    if args.dry_run:
        print("(--dry-run: файл и git не тронуты)")


if __name__ == "__main__":
    main()
