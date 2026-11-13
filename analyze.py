import re
from collections import Counter, defaultdict

LOG = "logs/sample_auth.log"
THRESHOLD = 3   # failed attempts after which an IP is flagged

pattern = re.compile(r"(\w+\s+\d+\s[\d:]+).*?(Failed|Accepted) password for (?:invalid user )?(\S+) from (\S+)")

failed_ip = Counter()
failed_user = Counter()
history = defaultdict(list)
accepted = []

with open(LOG) as f:
    for line in f:
        m = pattern.search(line)
        if not m:
            continue
        time, result, user, ip = m.groups()
        history[ip].append(result)
        if result == "Failed":
            failed_ip[ip] += 1
            failed_user[user] += 1
        else:
            accepted.append((time, user, ip))

out = []
out.append("=== LINUX LOG ANALYSIS REPORT ===")
out.append(f"Log file analysed : {LOG}")
out.append(f"Total failed logins     : {sum(failed_ip.values())}")
out.append(f"Total successful logins : {len(accepted)}")
out.append("")
out.append("--- Failed logins per IP ---")
for ip, n in failed_ip.most_common():
    out.append(f"{ip:<18} {n}")
out.append("")
out.append("--- Most targeted usernames ---")
for u, n in failed_user.most_common():
    out.append(f"{u:<18} {n}")
out.append("")
out.append(f"--- SUSPICIOUS IPs (>= {THRESHOLD} failed attempts) ---")
for ip, n in failed_ip.most_common():
    if n >= THRESHOLD:
        out.append(f"[ALERT] {ip} made {n} failed attempts (possible brute force)")
out.append("")
out.append("--- Success after failures (check these) ---")
for ip, h in history.items():
    if "Failed" in h and "Accepted" in h and h.index("Failed") < h.index("Accepted"):
        out.append(f"[WARN] {ip} failed and then logged in successfully")

text = "\n".join(out)
print(text)
with open("reports/report.txt", "w") as r:
    r.write(text + "\n")
