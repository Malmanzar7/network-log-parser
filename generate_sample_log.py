import argparse
import random
from datetime import datetime, timedelta

def main():
    parser = argparse.ArgumentParser(description="Generate mock auth.log file")
    parser.add_argument("--output", default="sample_auth.log", help="Output filename")
    args = parser.parse_args()

    normal_users = ["deploy", "ubuntu", "git", "backup"]
    normal_ips = ["203.0.113.10", "203.0.113.42", "198.51.100.7"]
    
    attacker_ip = "45.33.12.89"
    attacker_users = ["root", "admin", "test", "oracle", "postgres", "guest", "pi"]

    now = datetime.now() - timedelta(hours=1)
    lines = []

    # 1. Normal user activity (scattered over time)
    for _ in range(12):
        now += timedelta(seconds=random.randint(20, 90))
        ip = random.choice(normal_ips)
        user = random.choice(normal_users)
        
        # 80% chance of success, 20% chance of standard user password error
        if random.random() < 0.8:
            lines.append(f"{now.strftime('%b %d %H:%M:%S')} webserver01 sshd[1234]: Accepted password for {user} from {ip} port 45210 ssh2\n")
        else:
            lines.append(f"{now.strftime('%b %d %H:%M:%S')} webserver01 sshd[1234]: Failed password for {user} from {ip} port 45210 ssh2\n")

    # 2. Simulated Brute-Force Attack (rapid failures within seconds)
    now += timedelta(seconds=60)
    for _ in range(15):
        now += timedelta(seconds=2)
        user = random.choice(attacker_users)
        lines.append(f"{now.strftime('%b %d %H:%M:%S')} webserver01 sshd[1234]: Failed password for invalid user {user} from {attacker_ip} port 50112 ssh2\n")

    # Save to file
    with open(args.output, "w") as file:
        file.writelines(lines)

    print(f"Sample log generated: {args.output}")

if __name__ == "__main__":
    main()