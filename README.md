# Password Strength Checker (Python)


A zero‑dependency CLI that scores password strength, estimates entropy, and flags weak patterns (dictionary words, sequences, keyboard runs, repeats, common passwords). Outputs human‑readable results or JSON/CSV.


## Quickstart
```bash
python password_checker.py --password "Summer2025!"
python password_checker.py --input samples/passwords.txt --out-json out.json --out-csv out.csv