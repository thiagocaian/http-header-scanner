from __future__ import annotations
import csv, json
from typing import Dict, Tuple, List
import requests

# Cabeçalhos de segurança mais comuns
SEC_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def fetch_headers(url: str, timeout: float = 10.0) -> Dict[str, str]:
    """Faz GET e devolve os headers (case-preserving; acessamos com .get)."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    resp = requests.get(url, timeout=timeout, allow_redirects=True)
    # Normalizamos chaves para comparação case-insensitive, mas preservamos acesso via get.
    # requests.structures.CaseInsensitiveDict já resolve.
    return dict(resp.headers)

def evaluate(headers: Dict[str, str]) -> Tuple[int, List[str]]:
    """Retorna (score, issues_faltantes). Score = quantidade presente em SEC_HEADERS (0..len)."""
    missing = [h for h in SEC_HEADERS if headers.get(h) is None and headers.get(h.lower()) is None]
    score = len(SEC_HEADERS) - len(missing)
    return score, missing

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
        for r in rows:
            writer.writerow(r)
