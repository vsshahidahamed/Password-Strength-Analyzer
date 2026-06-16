"""Simple CLI for the Password Strength Analyzer."""
from __future__ import annotations

import argparse
import getpass
from .analyzer import (
    evaluate_password,
    generate_strong_password,
    store_password_to_db,
    is_reused_password,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Password Strength Analyzer CLI")
    parser.add_argument("--db", help="Path to sqlite DB for reuse checks and storing (optional)")
    parser.add_argument("--generate", action="store_true", help="Generate a strong password and exit")
    args = parser.parse_args()

    if args.generate:
        print(generate_strong_password())
        return

    pwd = getpass.getpass("Enter password to evaluate: ")
    summary = evaluate_password(pwd)

    print("\nPassword Analysis")
    print("Score:", summary["score"], "/ 100")
    print("Entropy (bits):", summary["entropy_bits"]) 
    print("Length:", summary["length"]) 
    print("Checks:")
    for k, v in summary["checks"].items():
        print(f" - {k}: {'OK' if v else 'FAIL'}")

    print("\nSuggestions:")
    for s in summary["suggestions"]:
        print(" -", s)

    if args.db:
        reused = is_reused_password(pwd, args.db)
        print("\nReuse check:", "REUSED" if reused else "Not seen before")
        if not reused:
            store = input("Store this password hash in DB to prevent future reuse? [y/N]: ")
            if store.lower().startswith("y"):
                store_password_to_db(pwd, args.db)
                print("Stored (hashed) in DB.")


if __name__ == "__main__":
    main()
