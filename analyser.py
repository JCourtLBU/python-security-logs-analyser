from datetime import datetime

log_info = {
    "login success": 0,
    "login failed": 0,
}

failed_by_ip = {}
failed_users_by_ip = {}
alerts = []

with open("logs/auth.log") as logfile:
    for line in logfile:
        date, time, event, ip, username = line.split()

        if event == "LOGIN_SUCCESS":
            log_info["login success"] += 1

        elif event == "LOGIN_FAILED":
            log_info["login failed"] += 1

            login_time = datetime.strptime(time, "%H:%M:%S")

            if ip in failed_by_ip:
                failed_by_ip[ip].append(login_time)
                failed_users_by_ip[ip].append(username)
            else:
                failed_by_ip[ip] = [login_time]
                failed_users_by_ip[ip] = [username]

def detect_brute_force():
    for ip, times in failed_by_ip.items():
        if len(times) >= 5:
            if len(times) >= 10:
                severity = "CRITICAL"
            else:
                severity = "HIGH"

            time_difference = times[-1] - times[0]
            seconds = time_difference.total_seconds()

            if seconds <= 60:
                alerts.append({
                    "type": "Brute Force",
                    "severity": severity,
                    "source_ip": ip,
                    "attempts": len(times),
                    "time_window": seconds,
                    "first_attempt": times[0],
                    "last_attempt": times[-1]
                })

def detect_password_spraying():
    for ip, usernames in failed_users_by_ip.items():
        unique_users = set(usernames)

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
    report += f"Login Failure Rate: {failure_rate:.1f}%\n"
    report += f"Security Alerts: {len(alerts)}\n\n"

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