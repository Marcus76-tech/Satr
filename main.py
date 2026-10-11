import json
import ipaddress
import re
import urllib.request
from pathlib import Path

APP_NAME = "Satr"
VERSION = "0.2.0"

# Adult-content source only; avoid unrelated block categories.
SOURCES = [
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
]

MAX_RULES = 25000

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
        return value


def parse_blocklist(content):
    domains = []
    seen = set()

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith(("#", "!", "[")):
            continue

        # Ignore exception rules and cosmetic filters.
        if line.startswith("@@") or "##" in line:
            continue

        candidates = []

        # Hosts format: 0.0.0.0 example.com
        fields = line.split()
        if len(fields) >= 2 and fields[0] in {
            "0.0.0.0", "127.0.0.1", "::1"
        }:
            candidates = fields[1:]

        # Adblock format: ||example.com^
        elif line.startswith("||") and line.endswith("^"):
            candidate = line[2:-1]

            # Only accept plain domain rules, not paths or wildcards.
            if "/" not in candidate and "*" not in candidate:
                candidates = [candidate]

        # Plain domain format: example.com
        elif len(fields) == 1 and not any(
            char in line for char in "/^*|"
        ):
            candidates = [line]

        for candidate in candidates:
            domain = normalize_domain(candidate)

            if domain and domain not in seen:
                seen.add(domain)
                domains.append(domain)

    return domains


def download_source(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": f"{APP_NAME}/{VERSION}"}
    )

    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(30 * 1024 * 1024 + 1)

    if len(data) > 30 * 1024 * 1024:
        raise ValueError("Source exceeds the 30 MiB limit")

    return data.decode("utf-8", errors="replace")


def build_blocklist():
    domains = []
    seen = set()
    successful = 0

    for url in SOURCES:
        try:
            content = download_source(url)
            source_domains = parse_blocklist(content)

            for domain in source_domains:
                if domain not in seen:
                    seen.add(domain)
                    domains.append(domain)

            successful += 1
            print(f"[+] Loaded {len(source_domains)} domains")

        except Exception as error:
            print(f"[!] Source failed: {url}")
            print(f"    Reason: {error}")

    if successful == 0:
        raise RuntimeError("No blocklist sources could be downloaded")

    if not domains:
        raise RuntimeError("The downloaded sources contained no valid domains")

    # Keep the initial extension within a conservative rule budget.
    # Preserve source order rather than silently sorting the list.
    selected_domains = domains[:MAX_RULES]

    rules = []
    for rule_id, domain in enumerate(selected_domains, start=1):
        rules.append({
            "id": rule_id,
            "priority": 1,
            "action": {"type": "block"},
            "condition": {
                "urlFilter": f"||{domain}^"
            }
        })

    # Keep the original hosts-list output.
    hosts_output = Path("dist/satr-hosts.txt")
    hosts_output.parent.mkdir(parents=True, exist_ok=True)

    with hosts_output.open("w", encoding="utf-8") as file:
        file.write("# Satr content blocklist\n")
        file.write("# Review the source before relying on it.\n")
        for domain in selected_domains:
            file.write(f"0.0.0.0 {domain}\n")

    # Generate rules for the browser extension.
    rules_output = Path("extension/rules.json")
    rules_output.parent.mkdir(parents=True, exist_ok=True)

    with rules_output.open("w", encoding="utf-8") as file:
        json.dump(rules, file, indent=2)
        file.write("\n")

    print(f"\n{APP_NAME} v{VERSION}")
    print(f"Unique domains found: {len(domains)}")
    print(f"Rules generated: {len(rules)}")
    print(f"Hosts output: {hosts_output}")
    print(f"Extension rules: {rules_output}")

    if len(domains) > MAX_RULES:
        print(
            f"[!] Rule limit reached: using the first "
            f"{MAX_RULES} domains from the source."
        )


if __name__ == "__main__":
    try:
        build_blocklist()
    except Exception as error:
        print(f"[ERROR] {error}")
        raise
