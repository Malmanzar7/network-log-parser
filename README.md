# SSH Brute-Force Log Parser

A simple Python tool that parses Linux `auth.log` files to detect SSH brute-force attacks.

## How It Works
1. Scans log files for `Failed password` messages using Regex.
2. Groups failed attempts by IP address.
3. Flags any IP that hits a threshold (default: 10 failed attempts) within a set time window (default: 60 seconds).

## Quickstart

```bash
# Generate a test log file
python3 generate_sample_log.py

# Run detector on default settings
python3 log_parser.py sample_auth.log

# Custom settings (5 failures in 30 seconds)
python3 log_parser.py sample_auth.log --threshold 5 --window 30