import types
from src import scanner as sc

class DummyResp:
    def __init__(self, headers):
        self.headers = headers

def test_evaluate_score_and_missing():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        # faltando: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
    }
    score, missing = sc.evaluate(headers)
    assert score == 2
    assert "X-Frame-Options" in missing
    assert "Permissions-Policy" in missing

def test_fetch_headers_uses_https_by_default(monkeypatch):
    captured = {}
    def fake_get(url, timeout=10.0, allow_redirects=True):
        captured["url"] = url
        return DummyResp({"X-Content-Type-Options": "nosniff"})
    monkeypatch.setattr(sc.requests, "get", fake_get)

    headers = sc.fetch_headers("example.com")
    assert captured["url"].startswith("https://")
    assert headers.get("X-Content-Type-Options") == "nosniff"

def test_exports(tmp_path):
    sc.export_json({"ok": True}, tmp_path/"out.json")
    sc.export_csv([{"a":"1","b":"2"}], tmp_path/"out.csv")
    assert (tmp_path/"out.json").exists()
    assert (tmp_path/"out.csv").exists()
