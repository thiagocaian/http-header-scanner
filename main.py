import argparse
from typing import Dict
from src import scanner as sc

def build_parser():
    p = argparse.ArgumentParser(description="Minimal HTTP security header scanner.")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="Fetch headers and compute a security score.")
    ps.add_argument("url", help="Target site, e.g., https://example.com")
    ps.add_argument("--json", help="Save detailed result in JSON")
    ps.add_argument("--csv", help="Save one-line summary in CSV")
    return p

def main():
    args = build_parser().parse_args()

    if args.cmd == "scan":
        headers: Dict[str, str] = sc.fetch_headers(args.url)
        score, missing = sc.evaluate(headers)

        print(f"\nTarget: {args.url}")
        print(f"Score: {score}/{len(sc.SEC_HEADERS)}")
        if missing:
            print("Missing headers:")
            for h in missing:
                print(f"  - {h}")
        else:
            print("All recommended security headers present ✅")

        # Exports
        if args.json:
            sc.export_json(
                {
                    "url": args.url,
                    "score": score,
                    "total": len(sc.SEC_HEADERS),
                    "missing": missing,
                    "present": {k: headers.get(k) for k in sc.SEC_HEADERS if headers.get(k)},
                },
                args.json,
            )
            print(f"JSON saved to {args.json}")

        if args.csv:
            sc.export_csv(
                [
                    {
                        "url": args.url,
                        "score": str(score),
                        "total": str(len(sc.SEC_HEADERS)),
                        "missing": ";".join(missing),
                    }
                ],
                args.csv,
            )
            print(f"CSV saved to {args.csv}")

if __name__ == "__main__":
    main()
