import json, csv, requests
from typing import Dict, List, Tuple

SEC_HEADERS = {
    "Content-Security-Policy": 2,
    "Strict-Transport-Security": 2,
    "X-Frame-Options": 1,
    "X-Content-Type-Options": 1,
    "Referrer-Policy": 1,
    "Permissions-Policy": 1,
}

def fetch_headers(url: str, timeout: float = 10.0, allow_redirects: bool = True) -> Dict[str, str]:
    if not url.startswith("http"):
        url = "https://" + url
    r = requests.get(url, timeout=timeout, allow_redirects=allow_redirects)
    return {k.strip(): v for k, v in r.headers.items()}

def compute_score(headers: Dict[str, str], only: List[str] | None = None) -> Tuple[int, int, List[str]]:
    to_check = {k: SEC_HEADERS[k] for k in SEC_HEADERS}
    if only:
        only_norm = {h.strip(): 1 for h in only}
        to_check = {k: SEC_HEADERS.get(k, 1) for k in SEC_HEADERS if k in only_norm}

    total = sum(to_check.values()) if to_check else 0
    missing = []
    score = 0
    lower = {k.lower(): v for k, v in headers.items()}
    for name, weight in to_check.items():
        if name.lower() in lower:
            score += weight
        else:
            missing.append(name)
    return score, total, missing

def export_json(data: Dict, filepath: str) -> None:
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

def export_csv(rows: List[Dict[str, str]], filepath: str) -> None:
    if not rows:
        with open(filepath, "w") as f:
            f.write("")
        return
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
