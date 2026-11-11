"""Парсеры журналов: приводят разные источники к единой схеме события.

Поддерживаются:
  * Linux auth.log / secure (sshd, sudo, useradd)
  * события Windows в JSON Lines — например, выгрузка
    Get-WinEvent ... | Select-Object ... | ConvertTo-Json -Compress
    (Security 4624/4625/4688/4720/4732/1102 и Sysmon EventID 1)
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator


@dataclass
class Event:
    timestamp: datetime
    host: str
    source: str            # linux_auth | windows
    event_type: str        # logon_failure, logon_success, sudo, user_created, process_creation, ...
    user: str = ""
    src_ip: str = ""
    process: str = ""
    command_line: str = ""
    event_id: int | None = None
    extra: dict = field(default_factory=dict)
    raw: str = ""

    def get(self, name: str):
        """Доступ к полю по имени из правила; extra.* — вложенные поля."""
        if name.startswith("extra."):
            return self.extra.get(name[6:], "")
        return getattr(self, name, "")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


# ---------- Linux auth.log ----------

SYSLOG_RE = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<proc>[\w\-/]+)(?:\[\d+\])?: (?P<msg>.*)$")
SSH_FAIL_RE = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
SSH_OK_RE = re.compile(r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
SUDO_RE = re.compile(r"^\s*(?P<user>\S+) : .*?USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$")
USERADD_RE = re.compile(r"new user: name=(?P<user>[^,]+)")


def parse_auth_line(line: str, year: int) -> Event | None:
    m = SYSLOG_RE.match(line.rstrip("\n"))
    if not m:
        return None
    ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
    host, proc, msg = m["host"], m["proc"], m["msg"]
    base = {"timestamp": ts, "host": host, "source": "linux_auth", "process": proc, "raw": line.strip()}

    if proc == "sshd":
        if fm := SSH_FAIL_RE.search(msg):
            return Event(event_type="logon_failure", user=fm["user"], src_ip=fm["ip"],
                         extra={"invalid_user": "invalid user" in msg}, **base)
        if om := SSH_OK_RE.search(msg):
            return Event(event_type="logon_success", user=om["user"], src_ip=om["ip"],
                         extra={"method": om["method"]}, **base)
    elif proc == "sudo":
        if sm := SUDO_RE.match(msg):
            return Event(event_type="sudo", user=sm["user"], command_line=sm["cmd"].strip(),
                         extra={"target_user": sm["target"]}, **base)
    elif proc == "useradd":
        if um := USERADD_RE.search(msg):
            return Event(event_type="user_created", user=um["user"], **base)
    return None


def parse_auth_log(path: Path, year: int | None = None) -> Iterator[Event]:
    year = year or datetime.now().year
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if ev := parse_auth_line(line, year):
                yield ev


# ---------- Windows JSON Lines ----------

WIN_EVENT_TYPES = {
    4624: "logon_success",
    4625: "logon_failure",
    4688: "process_creation",
    4720: "user_created",
    4732: "group_member_added",
    1102: "log_cleared",
}


def parse_windows_record(rec: dict) -> Event | None:
    eid = int(rec.get("EventID", 0))
    provider = rec.get("Provider", "")
    if eid == 1 and "Sysmon" in provider:
        event_type = "process_creation"
    else:
        event_type = WIN_EVENT_TYPES.get(eid)
    if not event_type:
        return None

    ts = datetime.fromisoformat(rec["TimeCreated"].replace("Z", "+00:00")).replace(tzinfo=None)
    user = rec.get("TargetUserName") or rec.get("User") or rec.get("SubjectUserName") or ""
    return Event(
        timestamp=ts,
        host=rec.get("Computer", ""),
        source="windows",
        event_type=event_type,
        user=user,
        src_ip=rec.get("IpAddress", "") if rec.get("IpAddress") not in ("-", None) else "",
        process=rec.get("Image") or rec.get("NewProcessName") or "",
        command_line=rec.get("CommandLine", ""),
        event_id=eid,
        extra={k: v for k, v in rec.items() if k in ("LogonType", "MemberName", "TargetSid", "ParentImage", "GroupName")},
        raw=json.dumps(rec, ensure_ascii=False),
    )


def parse_windows_jsonl(path: Path) -> Iterator[Event]:
    # utf-8-sig: PowerShell 5 (Out-File -Encoding utf8) добавляет BOM
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line and (ev := parse_windows_record(json.loads(line))):
                yield ev


def load_events(paths: list[Path], year: int | None = None) -> list[Event]:
    """Загрузить события из файлов; формат определяется по расширению (.jsonl/.json — Windows)."""
    events: list[Event] = []
    for p in paths:
        if p.suffix in (".jsonl", ".json"):
            events.extend(parse_windows_jsonl(p))
        else:
            events.extend(parse_auth_log(p, year))
    return sorted(events, key=lambda e: e.timestamp)
