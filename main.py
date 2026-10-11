import urllib.request
import ipaddress
import re
from pathlib import Path

APP_NAME = "Satr"
VERSION = "0.1.0"

SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
]

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\.?$"
)

def normalize_domain(value):
    value = value.strip().lower().rstrip(".")

    if not value or "." not in value:
        return None

    if value in {"localhost", "localhost.localdomain"}:
        return None

    if not DOMAIN_PATTERN.fullmatch(value):
        return None

    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass

    return value


def parse_blocklist(content):
    domains = set()

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith(("#", "!", "[")):
            continue

        fields = line.split()

        # Hosts format: 0.0.0.0 domain.example
        if len(fields) >= 2 and fields[0] in {
            "0.0.0.0", "127.0.0.1", "::1"
        }:
            candidates = fields[1:]

        # Plain domain format: domain.example
        elif len(fields) == 1:
            candidates = [fields[0]]

        else:
            continue

        for candidate in candidates:
            domain = normalize_domain(candidate)

            if domain:
                domains.add(domain)

    return domains


def download_source(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Satr/0.1.0"}
    )

    with urllib.request.urlopen(request, timeout=20) as response:
        data = response.read(30 * 1024 * 1024 + 1)

    if len(data) > 30 * 1024 * 1024:
        raise ValueError("Source exceeds the 30 MiB limit")

    return data.decode("utf-8", errors="replace")


def build_blocklist():
    blocked_domains = set()
    successful = 0

    for url in SOURCES:
        try:
            content = download_source(url)
            domains = parse_blocklist(content)
            blocked_domains.update(domains)
            successful += 1

            print(f"[+] Loaded {len(domains)} domains")

        except Exception as error:
            print(f"[!] Source failed: {url}")
            print(f"    Reason: {error}")

    if successful == 0:
        raise RuntimeError("No blocklist sources could be downloaded")

    output = Path("dist/satr-hosts.txt")
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as file:
        file.write("# Satr content blocklist\n")
        file.write("# Domain-level filtering; review before use.\n")

        for domain in sorted(blocked_domains):
            file.write(f"0.0.0.0 {domain}\n")

    print(f"\n{APP_NAME} v{VERSION}")
    print(f"Unique domains: {len(blocked_domains)}")
    print(f"Output file: {output}")


if __name__ == "__main__":
    try:
        build_blocklist()
    except Exception as error:
        print(f"[ERROR] {error}")
