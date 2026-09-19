# Python Security Log Analyser

A Python-based security log analysis tool that parses authentication logs and identifies potentially suspicious login activity.

The project was built as a practical cybersecurity portfolio project to develop experience with security monitoring, log analysis, attack detection and Python programming.

## Overview

The analyser processes authentication log files containing login events and produces a timestamped security report.

It identifies suspicious behaviour by analysing failed login attempts over time and looking for patterns associated with:

- Brute-force attacks
- Password-spraying attacks
- Repeated failed authentication attempts

The analyser also handles malformed log entries and calculates an overall login failure rate.

## Features

- Parses authentication log files
- Counts successful and failed login attempts
- Groups failed logins by source IP address
- Detects brute-force activity using a 60-second sliding time window
- Detects password spraying using multiple usernames within a 60-second window
- Assigns `HIGH` and `CRITICAL` severity levels
- Records malformed log entries without stopping the analysis
- Calculates the overall login failure rate
- Generates timestamped security reports
- Supports different input log files through a configurable file path

## Detection Methods

### Brute Force

A brute-force alert is generated when an IP address produces at least 5 failed login attempts within a 60-second window.

Severity is assigned based on the number of attempts:

- 5–9 attempts: `HIGH`
- 10+ attempts: `CRITICAL`

The analyser uses a sliding time window rather than simply comparing the first and last log entries.

### Password Spraying

A password-spraying alert is generated when an IP address attempts to authenticate against at least 5 unique usernames within a 60-second window.

Severity is assigned based on the number of accounts targeted:

- 5–9 accounts: `HIGH`
- 10+ accounts: `CRITICAL`

## Example

Example input:

```text
2026-09-19 11:02:15 LOGIN_FAILED 192.168.1.200 admin
2026-09-19 11:02:24 LOGIN_FAILED 192.168.1.200 emily
2026-09-19 11:02:36 LOGIN_FAILED 192.168.1.200 jack
2026-09-19 11:02:48 LOGIN_FAILED 192.168.1.200 sarah
2026-09-19 11:02:59 LOGIN_FAILED 192.168.1.200 tom
