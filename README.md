# Password Strength Analyzer

Simple tool to evaluate password strength, suggest improvements, and optionally prevent reuse by storing hashed passwords in a small sqlite DB.

Quick start

1. Run the CLI:

```
python -m password_analyzer.cli
```

2. Generate a random password:

```
python -m password_analyzer.cli --generate
```

3. Use `--db my.db` to enable reuse checks and store a hashed record of a password.

What it teaches

- Basic entropy estimation
- Character-class checks (upper/lower/digit/symbol)
- Simple suggestions and password generation
- Optional sqlite-based reuse prevention (stores SHA-256 hashes)
