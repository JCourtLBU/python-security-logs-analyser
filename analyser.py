from datetime import datetime, timedelta


log_info = {
    "login success": 0,
    "login failed": 0,
}

failed_by_ip = {}
failed_users_by_ip = {}

malformed_logs = 0
malformed_entries = []

alerts = []


with open("logs/auth.log") as logfile:
    for line_number, line in enumerate(logfile, start=1):
        try:
            date, time, event, ip, username = line.split()
        except ValueError:
            malformed_logs += 1
            malformed_entries.append({
                "line": line_number,
                "content": line.strip()
            })
            continue

        if event == "LOGIN_SUCCESS":
            log_info["login success"] += 1

        elif event == "LOGIN_FAILED":
            log_info["login failed"] += 1

            login_time = datetime.strptime(time, "%H:%M:%S")

            if ip in failed_by_ip:
                failed_by_ip[ip].append(login_time)
                failed_users_by_ip[ip].append({
                    "username": username,
                    "time": login_time
                })
            else:
                failed_by_ip[ip] = [login_time]
                failed_users_by_ip[ip] = [{
                    "username": username,
                    "time": login_time
                }]


def detect_brute_force():
    for ip, times in failed_by_ip.items():

        if len(times) < 5:
            continue

        for i in range(len(times)):
            window_start = times[i]
            window_end = window_start + timedelta(seconds=60)

            attempts_in_window = []

            for time in times[i:]:
                if time <= window_end:
                    attempts_in_window.append(time)
                else:
                    break

            if len(attempts_in_window) >= 5:

                if len(attempts_in_window) >= 10:
                    severity = "CRITICAL"
                else:
                    severity = "HIGH"

                alerts.append({
                    "type": "Brute Force",
                    "severity": severity,
                    "source_ip": ip,
                    "attempts": len(attempts_in_window),
                    "time_window": (
                            attempts_in_window[-1] - attempts_in_window[0]
                    ).total_seconds(),
                    "first_attempt": attempts_in_window[0],
                    "last_attempt": attempts_in_window[-1]
                })

                break


def detect_password_spraying():
    for ip, attempts in failed_users_by_ip.items():

        if len(attempts) < 5:
            continue

        for i in range(len(attempts)):
            window_start = attempts[i]["time"]
            window_end = window_start + timedelta(seconds=60)

            users_in_window = []

            for attempt in attempts[i:]:
                if attempt["time"] <= window_end:
                    users_in_window.append(attempt["username"])
                else:
                    break

            unique_users = set(users_in_window)

            if len(unique_users) >= 5:

                if len(unique_users) >= 10:
                    severity = "CRITICAL"
                else:
                    severity = "HIGH"

                alerts.append({
                    "type": "Password Spraying",
                    "severity": severity,
                    "source_ip": ip,
                    "accounts_targeted": len(unique_users),
                    "accounts": sorted(unique_users)
                })

                break


def generate_report():
    report = ""

    severity_order = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
    }

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for alert in alerts:
        severity_counts[alert["severity"]] += 1

    sorted_alerts = sorted(
        alerts,
        key=lambda alert: severity_order[alert["severity"]]
    )

    total_events = log_info["login success"] + log_info["login failed"]
    failure_rate = (log_info["login failed"] / total_events) * 100

    report += "--- SECURITY LOG ANALYSIS REPORT ---\n\n"

    report += "SUMMARY\n"
    report += "-------\n"
    report += f"Successful Logins: {log_info['login success']}\n"
    report += f"Failed Logins: {log_info['login failed']}\n"
    report += f"Total Events: {total_events}\n"
    report += f"Malformed Log Entries: {malformed_logs}\n"
    report += f"Login Failure Rate: {failure_rate:.1f}%\n"
    report += f"Security Alerts: {len(alerts)}\n"

    if malformed_entries:
        report += "\nMALFORMED ENTRIES\n"
        report += "-----------------\n"

        for entry in malformed_entries:
            report += f"Line {entry['line']}: {entry['content']}\n"

    report += "\n"

    report += "ALERT SEVERITY\n"
    report += "--------------\n"
    report += f"Critical: {severity_counts['CRITICAL']}\n"
    report += f"High: {severity_counts['HIGH']}\n"
    report += f"Medium: {severity_counts['MEDIUM']}\n"
    report += f"Low: {severity_counts['LOW']}\n\n"

    report += "SECURITY ALERTS\n"
    report += "---------------\n\n"

    if not alerts:
        report += "No security alerts detected.\n"
        return report

    for alert in sorted_alerts:
        report += f"[{alert['severity']}] {alert['type'].upper()} DETECTED\n"
        report += f"Source IP: {alert['source_ip']}\n"

        if alert["type"] == "Brute Force":
            report += f"Failed Attempts: {alert['attempts']}\n"
            report += f"Time Window: {alert['time_window']:.0f} seconds\n"
            report += f"First Attempt: {alert['first_attempt'].strftime('%H:%M:%S')}\n"
            report += f"Last Attempt: {alert['last_attempt'].strftime('%H:%M:%S')}\n"

        elif alert["type"] == "Password Spraying":
            report += f"Accounts Targeted: {alert['accounts_targeted']}\n"
            report += f"Accounts: {', '.join(alert['accounts'])}\n"

        report += "\n"

    return report


detect_brute_force()
detect_password_spraying()

report = generate_report()

with open("reports/security_report.txt", "w") as report_file:
    report_file.write(report)