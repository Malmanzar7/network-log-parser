import argparse
import re
from collections import defaultdict
from datetime import datetime, timedelta

# Regular expression to extract timestamp, username, and IP address from failed SSH attempts
LOG_PATTERN = re.compile(
    r"^(?P<time>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def parse_log(file_path):
    """Reads the log file and extracts failed login attempts."""
    events = []
    current_year = datetime.now().year
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            match = LOG_PATTERN.search(line)
            if match:
                # Convert log timestamp string into a datetime object
                time_str = match.group("time")
                timestamp = datetime.strptime(f"{current_year} {time_str}", "%Y %b %d %H:%M:%S")
                ip = match.group("ip")
                user = match.group("user")
                events.append((timestamp, ip, user))
                
    return events

def find_brute_force(events, threshold=10, window_seconds=60):
    """Detects IPs with 'threshold' or more failures within 'window_seconds'."""
    # Group all failed attempts by IP address
    attempts_by_ip = defaultdict(list)
    for timestamp, ip, user in events:
        attempts_by_ip[ip].append((timestamp, user))

    flagged_ips = {}
    time_window = timedelta(seconds=window_seconds)

    for ip, attempts in attempts_by_ip.items():
        attempts.sort(key=lambda x: x[0])  # Sort attempts chronologically
        
        # Check every attempt as a potential start of an attack window
        for start_idx in range(len(attempts)):
            start_time = attempts[start_idx][0]
            
            # Find all attempts that fall inside the time window
            in_window = [
                att for att in attempts 
                if start_time <= att[0] <= start_time + time_window
            ]
            
            if len(in_window) >= threshold:
                end_time = in_window[-1][0]
                users_tried = sorted({att[1] for att in in_window})
                
                # Store the attack details if it's the largest attempt count seen for this IP
                if ip not in flagged_ips or len(in_window) > flagged_ips[ip]['count']:
                    flagged_ips[ip] = {
                        "start": start_time,
                        "end": end_time,
                        "count": len(in_window),
                        "users": users_tried
                    }

    return flagged_ips

def print_results(flagged_ips, total_failures):
    """Prints a clear summary report."""
    print(f"\nTotal failed login attempts found: {total_failures}")
    print(f"Flagged suspicious IPs: {len(flagged_ips)}\n")

    if not flagged_ips:
        print("No brute-force activity detected.")
        return

    for ip, info in flagged_ips.items():
        print(f"[ALERT] Suspicious IP: {ip}")
        print(f"   Failed Attempts : {info['count']}")
        print(f"   Time Frame      : {info['start']} to {info['end']}")
        print(f"   Usernames Tried : {', '.join(info['users'])}\n")

def main():
    parser = argparse.ArgumentParser(description="SSH Brute-Force Log Parser")
    parser.add_argument("logfile", help="Path to auth.log file")
    parser.add_argument("--threshold", type=int, default=10, help="Min failed attempts to trigger alert")
    parser.add_argument("--window", type=int, default=60, help="Time window size in seconds")
    
    args = parser.parse_args()

    events = parse_log(args.logfile)
    flagged = find_brute_force(events, threshold=args.threshold, window_seconds=args.window)
    print_results(flagged, total_failures=len(events))

if __name__ == "__main__":
    main()