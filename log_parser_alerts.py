import re
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# 1️⃣ Log Parsing
log_file = 'access.log'
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>[^ ]+) [^"]+" (?P<status>\d{3}) (?P<size>\d+) "(?P<useragent>[^"]*)"'
)

parsed_logs = []
with open(log_file, 'r') as file:
    for line in file:
        match = log_pattern.match(line)
        if match:
            parsed_logs.append(match.groupdict())

df = pd.DataFrame(parsed_logs)
df['datetime'] = pd.to_datetime(df['datetime'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')

# 2️⃣ Detection Logic
alerts = []

# Brute-force detection
failed_logins = df[df['status'] == '401'].groupby('ip').size()
for ip, count in failed_logins.items():
    if count > 5:
        alerts.append({
            'datetime': datetime.now(),
            'type': 'Brute-force',
            'ip': ip,
            'details': f'Failed logins: {count}'
        })

# SQLi detection
sqli_patterns = ["' OR '1'='1", 'UNION SELECT', 'OR 1=1', 'sleep(', 'benchmark(']
for pattern in sqli_patterns:
    suspicious = df[df['url'].str.contains(pattern, case=False, na=False)]
    for _, row in suspicious.iterrows():
        alerts.append({
            'datetime': datetime.now(),
            'type': 'SQLi',
            'ip': row['ip'],
            'details': f'SQLi pattern found: {pattern}'
        })

# Suspicious user-agent
suspicious_agents = ['sqlmap', 'curl', 'python', '']
for agent in suspicious_agents:
    suspicious = df[df['useragent'].str.contains(agent, case=False, na=False)]
    for _, row in suspicious.iterrows():
        alerts.append({
            'datetime': datetime.now(),
            'type': 'Suspicious User-Agent',
            'ip': row['ip'],
            'details': f'User-Agent: {row["useragent"]}'
        })

# High traffic from single IP
ip_counts = df.groupby('ip').size()
for ip, count in ip_counts.items():
    if count > 100:
        alerts.append({
            'datetime': datetime.now(),
            'type': 'High Traffic',
            'ip': ip,
            'details': f'Requests: {count}'
        })

# 3️⃣ Save alerts to CSV
alerts_df = pd.DataFrame(alerts)
alerts_df.to_csv('alerts.csv', index=False)
print("[+] Alerts saved to alerts.csv")

# 4️⃣ Email Alerts
def send_email_alert(subject, message, to_email):
    from_email = 'your_email@example.com'
    password = 'your_email_password'
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print(f"[+] Alert sent to {to_email}")
    except Exception as e:
        print(f"[-] Email error: {e}")

for alert in alerts:
    alert_msg = f"""
    [ALERT] {alert['type']} Detected!
    IP: {alert['ip']}
    Details: {alert['details']}
    """
    print(alert_msg)
    send_email_alert(
        subject=f"Security Alert: {alert['type']} Detected",
        message=alert_msg,
        to_email='recipient@example.com'
    )

print("\n[+] Log parsing and alerting complete.")

