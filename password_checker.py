#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Password Strength Checker — zero-dependency CLI (Python 3.8+)

Features
- Score (0–100) + entropy estimate (bits)
- Checks: length, character classes, common password list, dictionary words,
  sequential patterns, keyboard runs, repeated characters, year patterns
- Outputs: human-readable, optional JSON and CSV

Usage:
  python password_checker.py --password "Example@2025"
  python password_checker.py --input samples_passwords.txt --out-json out.json --out-csv out.csv
"""

import argparse
import csv
import json
import math
import re
from typing import Dict, List, Tuple

# ---- Embedded minimal offline lists ----
COMMON_PASSWORDS = {
    # Small subset; expand later as you wish.
    "123456", "password", "123456789", "12345", "12345678", "qwerty", "111111", "abc123",
    "password1", "iloveyou", "123123", "000000", "qwerty123", "dragon", "monkey", "letmein",
    "welcome", "admin", "login", "princess", "starwars", "passw0rd", "1q2w3e4r", "qazwsx"
}

# Naive dictionary words (you can expand this too)
DICTIONARY_WORDS = {
    "summer", "winter", "spring", "autumn", "football", "soccer", "basketball",
    "dragon", "monkey", "love", "password", "admin", "welcome", "qwerty",
    "king", "queen", "secret", "money"
}

KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]
SPECIALS = r"!@#$%^&*()_+-={}[]:;\"'<>,.?/|\\"


# ---- Helpers ----
def char_classes(password: str) -> Dict[str, bool]:
    return {
        "lower": any(c.islower() for c in password),
        "upper": any(c.isupper() for c in password),
        "digit": any(c.isdigit() for c in password),
        "special": any(c in SPECIALS for c in password),
    }


def charspace_size(classes: Dict[str, bool]) -> int:
    size = 0
    if classes["lower"]:
        size += 26
    if classes["upper"]:
        size += 26
    if classes["digit"]:
        size += 10
    if classes["special"]:
        size += len(set(SPECIALS))
    return size or 1


def estimate_entropy_bits(pw: str) -> float:
    N = charspace_size(char_classes(pw))
    return len(pw) * math.log2(N)


def has_sequence(pw: str, min_len: int = 4) -> bool:
    """Detect ascending alpha or digit runs like abcd, 1234."""
    if len(pw) < min_len:
        return False
    low = pw.lower()
    for i in range(len(low) - min_len + 1):
        chunk = low[i:i + min_len]
        if chunk.isalpha() and all(ord(chunk[j]) + 1 == ord(chunk[j + 1]) for j in range(len(chunk) - 1)):
            return True
        if chunk.isdigit() and all(int(chunk[j]) + 1 == int(chunk[j + 1]) for j in range(len(chunk) - 1)):
            return True
    return False


def has_keyboard_run(pw: str, min_len: int = 4) -> bool:
    low = pw.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - min_len + 1):
            if row[i:i + min_len] in low:
                return True
    return False


def has_repeats(pw: str, max_repeat: int = 3) -> bool:
    return re.search(rf"(.)\1{{{max_repeat},}}", pw) is not None


def has_dictionary_word(pw: str, min_len: int = 4) -> Tuple[bool, str]:
    low = pw.lower()
    for w in DICTIONARY_WORDS:
        if len(w) >= min_len and w in low:
            return True, w
    return False, ""


def is_common_password(pw: str) -> bool:
    return pw.lower() in COMMON_PASSWORDS


# ---- Scoring ----
def score_password(pw: str, *, min_length: int = 12, required_classes: int = 3) -> Dict:
    findings: List[str] = []
    suggestions: List[str] = []
    warnings: List[str] = []
    score = 0

    length = len(pw)
    classes = char_classes(pw)
    class_count = sum(classes.values())
    entropy = estimate_entropy_bits(pw)

    # Length: up to 35 points (25 for meeting min; + up to 10 for extra length)
    if length >= min_length:
        score += 25
        score += min(10, (length - min_length))
        findings.append(f"✓ Length OK ({length}/{min_length})")
    else:
        findings.append(f"– Too short: {length} (need +{min_length - length} to reach {min_length})")
        warnings.append("Increase length to 14–16 for better resilience.")

    # Character classes: up to 25 points
    class_points = {2: 10, 3: 18, 4: 25}
    score += class_points.get(class_count, 0)
    if class_count >= required_classes:
        present = [k for k, v in classes.items() if v]
        findings.append("✓ Character variety (" + ", ".join(present) + ")")
    else:
        findings.append(f"– Low variety: only {class_count} class(es)")
        warnings.append("Add missing types (upper/lower/digit/special).")

    # Negative checks (deductions)
    if is_common_password(pw):
        score -= 35
        findings.append("× In common-passwords list (high risk)")
        warnings.append("Pick something unique; avoid top leaked passwords.")

    has_dict, word = has_dictionary_word(pw)
    if has_dict:
        score -= 10
        findings.append(f"– Contains dictionary word: '{word}'")
        warnings.append("Break dictionary words (substitute characters or use passphrases).")

    if has_sequence(pw):
        score -= 10
        findings.append("– Sequential pattern detected (e.g., 'abcd'/'1234')")
        warnings.append("Avoid straight sequences; interleave symbols.")

    if has_keyboard_run(pw):
        score -= 8
        findings.append("– Keyboard run detected (e.g., 'qwerty')")
        warnings.append("Avoid keyboard runs; randomize positions.")

    if has_repeats(pw):
        score -= 6
        findings.append("– Repeated character run detected")
        warnings.append("Limit consecutive repeats to 2.")

    # Year pattern heuristic (e.g., 1999–2099)
    if re.search(r"(19|20)\d{2}", pw):
        score -= 4
        findings.append("– Year-like pattern detected")
        warnings.append("Avoid using years or dates.")

    # Entropy bonus (up to +20)
    if entropy >= 60:
        score += 20
    elif entropy >= 50:
        score += 14
    elif entropy >= 40:
        score += 8
    elif entropy >= 35:
        score += 4

    score = max(0, min(100, score))
    verdict = (
        "VERY WEAK" if score < 30 else
        "WEAK" if score < 50 else
        "MODERATE" if score < 70 else
        "STRONG" if score < 85 else
        "VERY STRONG"
    )

    # Suggestions
    if length < max(min_length, 14):
        suggestions.append("Use 14–16+ characters.")
    if class_count < 4:
        suggestions.append("Include upper, lower, digits, and symbols.")
    if has_dict:
        suggestions.append("Break dictionary words or use multi-word passphrases with separators.")
    if is_common_password(pw):
        suggestions.append("Start from a unique base phrase — avoid common lists.")
    if has_sequence(pw) or has_keyboard_run(pw):
        suggestions.append("Avoid sequences/keyboard runs; shuffle components.")
    if has_repeats(pw):
        suggestions.append("Limit consecutive repeats to 2.")

    return {
        "password": pw,
        "score": score,
        "entropy_bits": round(entropy, 1),
        "verdict": verdict,
        "findings": findings,
        "suggestions": suggestions,
        "warnings": warnings,
    }


# ---- CLI ----
def run_interactive(min_length: int, required_classes: int):
    try:
        while True:
            pw = input("Enter password (or blank to quit): ")
            if not pw:
                break
            r = score_password(pw, min_length=min_length, required_classes=required_classes)
            print(f"\nScore: {r['score']}/100  |  Entropy: {r['entropy_bits']} bits  |  Verdict: {r['verdict']}")
            print("Findings:")
            for f in r["findings"]:
                print("  ", f)
            if r["warnings"]:
                print("Warnings:")
                for w in r["warnings"]:
                    print("  •", w)
            if r["suggestions"]:
                print("Suggestions:")
                for s in r["suggestions"]:
                    print("  •", s)
            print("")
    except KeyboardInterrupt:
        print("\nExiting…")


def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker (offline)")
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--password", help="Check a single password")
    g.add_argument("--input", help="Path to file with one password per line")
    parser.add_argument("--min-length", type=int, default=12, help="Minimum length policy (default 12)")
    parser.add_argument("--require-classes", type=int, default=3, help="Required character classes 2–4 (default 3)")
    parser.add_argument("--out-json", help="Write results to JSON file")
    parser.add_argument("--out-csv", help="Write results to CSV file")
    args = parser.parse_args()

    results: List[Dict] = []

    if args.password:
        results.append(score_password(args.password, min_length=args.min_length, required_classes=args.require_classes))
    elif args.input:
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pw = line.strip()
                if pw:
                    results.append(score_password(pw, min_length=args.min_length, required_classes=args.require_classes))
    else:
        run_interactive(args.min_length, args.require_classes)
        return

    # --- Print a human-readable summary if we have results ---
    if results:
        if len(results) == 1:
            r = results[0]
            print(f"Score: {r['score']}/100  |  Entropy: {r['entropy_bits']} bits  |  Verdict: {r['verdict']}")
            print("Findings:")
            for f in r["findings"]:
                print("  ", f)
            if r["warnings"]:
                print("Warnings:")
                for w in r["warnings"]:
                    print("  •", w)
            if r["suggestions"]:
                print("Suggestions:")
                for s in r["suggestions"]:
                    print("  •", s)
        else:
            # Compact summary line per password
            for r in results:
                print(f"{r['password']}: {r['score']}/100 ({r['verdict']})")

    # --- Write JSON/CSV if requested ---
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as jf:
            json.dump(results, jf, indent=2)
        print(f"Wrote JSON -> {args.out_json}")
    if args.out_csv:
        with open(args.out_csv, "w", newline="", encoding="utf-8") as cf:
            writer = csv.DictWriter(
                cf,
                fieldnames=["password", "score", "entropy_bits", "verdict", "findings", "warnings", "suggestions"],
            )
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "password": r["password"],
                    "score": r["score"],
                    "entropy_bits": r["entropy_bits"],
                    "verdict": r["verdict"],
                    "findings": "; ".join(r["findings"]),
                    "warnings": "; ".join(r["warnings"]),
                    "suggestions": "; ".join(r["suggestions"]),
                })
        print(f"Wrote CSV  -> {args.out_csv}")


if __name__ == "__main__":
    main()
