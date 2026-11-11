import random
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from minisiem.engine import Rule, load_rules, matches, parse_window, run
from minisiem.parsers import Event, parse_auth_line, parse_windows_record
from minisiem.samples import make_auth_log, make_windows

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
T0 = datetime(2026, 11, 10, 3, 0, 0)


def ev(event_type="logon_failure", sec=0, **kw):
    return Event(timestamp=T0 + timedelta(seconds=sec), host=kw.pop("host", "web01"),
                 source=kw.pop("source", "linux_auth"), event_type=event_type, **kw)


# ---------- парсеры ----------

def test_parse_ssh_failed_invalid_user():
    e = parse_auth_line("Nov 10 03:14:15 web01 sshd[5200]: Failed password for invalid user admin from 203.0.113.77 port 51022 ssh2", 2026)
    assert (e.event_type, e.user, e.src_ip, e.host) == ("logon_failure", "admin", "203.0.113.77", "web01")
    assert e.extra["invalid_user"] is True
    assert e.timestamp == datetime(2026, 11, 10, 3, 14, 15)


def test_parse_single_digit_day():
    e = parse_auth_line("Nov  9 08:00:01 web01 sshd[1]: Accepted publickey for ivanov from 10.0.12.11 port 50000 ssh2", 2026)
    assert e.event_type == "logon_success" and e.timestamp.day == 9


def test_parse_sudo():
    e = parse_auth_line("Nov 10 03:17:26 web01 sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash", 2026)
    assert e.event_type == "sudo" and e.user == "deploy" and e.command_line == "/bin/bash"
    assert e.extra["target_user"] == "root"


def test_unrelated_line_is_ignored():
    assert parse_auth_line("Nov 10 03:00:00 web01 CRON[99]: pam_unix(cron:session): session opened", 2026) is None


def test_parse_windows_sysmon_process():
    e = parse_windows_record({"TimeCreated": "2026-11-10T22:46:45.000Z", "EventID": 1, "Computer": "WS1",
                              "Provider": "Microsoft-Windows-Sysmon", "Image": "C:\\x\\powershell.exe",
                              "CommandLine": "powershell -enc AAA", "User": "CORP\\buh"})
    assert e.event_type == "process_creation" and e.user == "CORP\\buh"


# ---------- условия ----------

@pytest.mark.parametrize("cond,expected", [
    ({"event_type": "LOGON_FAILURE"}, True),
    ({"user|in": ["root", "admin"]}, True),
    ({"src_ip|startswith": "203.0.113."}, True),
    ({"user|re": "^adm"}, True),
    ({"user": "admin", "exclude": {"src_ip|startswith": "203."}}, False),
    ({"user|contains": ["oot", "xyz"]}, False),
])
def test_matches(cond, expected):
    assert matches(ev(user="admin", src_ip="203.0.113.5"), cond) is expected


def test_parse_window():
    assert parse_window("90s") == timedelta(seconds=90)
    assert parse_window("2h") == timedelta(hours=2)
    with pytest.raises(ValueError):
        parse_window("5 minutes")


# ---------- движок ----------

BRUTE = Rule.from_dict({"id": "B", "title": "brute", "severity": "high", "type": "threshold", "mitre": ["T1110"],
                        "condition": {"event_type": "logon_failure"},
                        "threshold": {"group_by": ["src_ip"], "count": 5, "window": "2m"}})


def test_threshold_fires_once_per_attack():
    events = [ev(sec=i * 5, user="root", src_ip="203.0.113.1") for i in range(20)]
    alerts = run([BRUTE], events)
    assert len(alerts) == 1 and alerts[0].key == {"src_ip": "203.0.113.1"}


def test_threshold_respects_window():
    events = [ev(sec=i * 60, user="root", src_ip="203.0.113.1") for i in range(5)]  # 5 попыток за 4 минуты
    assert run([BRUTE], events) == []


def test_threshold_groups_by_ip():
    events = [ev(sec=i, user="root", src_ip=f"203.0.113.{i % 5}") for i in range(20)]  # по 4 с каждого IP
    assert run([BRUTE], events) == []


def test_sequence_success_after_brute_force():
    seq = Rule.from_dict({"id": "S", "title": "seq", "severity": "critical", "type": "sequence", "mitre": [],
                          "sequence": {"after": "B", "join_on": "src_ip", "within": "10m"},
                          "condition": {"event_type": "logon_success"}})
    events = [ev(sec=i * 5, user="deploy", src_ip="203.0.113.1") for i in range(6)]
    events.append(ev("logon_success", sec=60, user="deploy", src_ip="203.0.113.1"))
    events.append(ev("logon_success", sec=61, user="ivanov", src_ip="10.0.12.11"))  # другой IP — не алерт
    alerts = [a for a in run([BRUTE, seq], events) if a.rule_id == "S"]
    assert len(alerts) == 1 and alerts[0].key["user"] == "deploy"


# ---------- правила из репозитория ----------

def test_bundled_rules_load_and_have_mitre():
    rules = load_rules(RULES_DIR)
    assert len(rules) >= 10
    assert all(r.mitre for r in rules)


def test_bundled_rules_detect_full_attack_chain():
    rng, day = random.Random(1), datetime(2026, 11, 10)
    events = [parse_auth_line(line, 2026) for _, line in make_auth_log(rng, day)]
    events += [parse_windows_record(r) for _, r in make_windows(rng, day)]
    events = sorted((e for e in events if e), key=lambda e: e.timestamp)
    fired = {a.rule_id for a in run(load_rules(RULES_DIR), events)}
    assert fired == {r.id for r in load_rules(RULES_DIR)}


def test_no_alerts_on_background_noise():
    """Фоновая активность (включая редкие опечатки в пароле) не должна давать алертов."""
    rng, day = random.Random(3), datetime(2026, 11, 10)
    noise = [parse_auth_line(line, 2026) for ts, line in make_auth_log(rng, day) if 8 <= ts.hour < 21]
    noise += [parse_windows_record(r) for ts, r in make_windows(rng, day) if 8 <= ts.hour < 21]
    events = sorted((e for e in noise if e), key=lambda e: e.timestamp)
    assert run(load_rules(RULES_DIR), events) == []


def test_report_escapes_log_content():
    """Строки журналов контролирует атакующий — в HTML-отчёте они должны экранироваться (XSS)."""
    from minisiem.cli import build_report
    rules = load_rules(RULES_DIR)
    e = parse_auth_line('Nov 10 03:00:00 web01 useradd[1]: new user: name=<script>alert(1)</script>, UID=1005', 2026)
    html = build_report(run(rules, [e]), [e], rules)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
