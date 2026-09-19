# Python Security Log Analyser

A Python-based security log analysis tool that parses authentication logs and detects suspicious login activity.

Built as a cybersecurity portfolio project to develop practical experience with log analysis, security monitoring and Python.

## Features

- Parses authentication log files
- Counts successful and failed logins
- Detects brute-force attacks
- Detects password-spraying attacks
- Uses 60-second sliding time windows
- Assigns `HIGH` and `CRITICAL` severity levels
- Handles malformed log entries
- Calculates login failure rates
- Generates timestamped security reports
- Supports different input log files

## Detection Methods

### Brute Force

Detects 5 or more failed login attempts from the same IP within 60 seconds.

- 5–9 attempts → `HIGH`
- 10+ attempts → `CRITICAL`

### Password Spraying

Detects 5 or more unique usernames targeted by the same IP within 60 seconds.

- 5–9 accounts → `HIGH`
- 10+ accounts → `CRITICAL`

## Example

Example input:

    2026-09-19 11:02:15 LOGIN_FAILED 192.168.1.200 admin
    2026-09-19 11:02:24 LOGIN_FAILED 192.168.1.200 emily
    2026-09-19 11:02:36 LOGIN_FAILED 192.168.1.200 jack
    2026-09-19 11:02:48 LOGIN_FAILED 192.168.1.200 sarah
    2026-09-19 11:02:59 LOGIN_FAILED 192.168.1.200 tom

This is detected as password spraying because one IP targets five different accounts within 60 seconds.

Example alert:

    [HIGH] PASSWORD SPRAYING DETECTED
    Source IP: 192.168.1.200
    Accounts Targeted: 5
    Accounts: admin, emily, jack, sarah, tom

## How to Run

Set the log file you want to analyse in `analyser.py`:

    log_file_path = "logs/mixed_activity.log"

Run `analyser.py`.

A timestamped security report will be created in the `reports/` directory.

## Project Structure

    python-security-logs-analyser/
    ├── analyser.py
    ├── logs/
    │   ├── auth.log
    │   ├── normal_activity.log
    │   ├── small_brute_force.log
    │   ├── password_spraying.log
    │   ├── large_attack.log
    │   └── mixed_activity.log
    ├── reports/
    └── README.md

## Technologies

- Python
- Log parsing
- `datetime`
- Dictionaries, lists and sets
- Time-window based detection
- Security monitoring concepts
