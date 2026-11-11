"""Движок корреляции: загружает YAML-правила и прогоняет по ним поток событий.

Типы правил:
  match      — одно событие удовлетворяет условию
  threshold  — N событий (или N разных значений поля) за окно времени с группировкой
  sequence   — после алерта другого правила по тому же ключу происходит событие-условие

Синтаксис условий (все пункты через И, внутри списка — ИЛИ):
  field: value               равенство (без учёта регистра)
  field|contains: [a, b]     подстрока
  field|startswith / endswith
  field|re: 'regex'
  field|in: [a, b]
  exclude: {...}             те же условия, событие НЕ должно им соответствовать
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from .parsers import Event

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def parse_window(text: str) -> timedelta:
    m = re.fullmatch(r"(\d+)\s*([smhd])", str(text).strip())
    if not m:
        raise ValueError(f"Неверный формат окна: {text!r} (пример: 30s, 5m, 1h)")
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    return timedelta(**{units[m[2]]: int(m[1])})


def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


def _check(event: Event, key: str, expected) -> bool:
    name, _, op = key.partition("|")
    actual = event.get(name)
    actual_s = str(actual).lower() if actual is not None else ""
    values = [str(v).lower() for v in _as_list(expected)]

    if op == "":
        if isinstance(expected, bool):
            return actual is expected
        if isinstance(expected, int) and not isinstance(expected, bool):
            return actual == expected
        return actual_s in values
    if op == "contains":
        return any(v in actual_s for v in values)
    if op == "startswith":
        return any(actual_s.startswith(v) for v in values)
    if op == "endswith":
        return any(actual_s.endswith(v) for v in values)
    if op == "in":
        return actual_s in values
    if op == "re":
        return any(re.search(v, str(actual or ""), re.IGNORECASE) for v in _as_list(expected))
    raise ValueError(f"Неизвестный модификатор: {op}")


def matches(event: Event, condition: dict | None) -> bool:
    if not condition:
        return True
    cond = dict(condition)
    exclude = cond.pop("exclude", None)
    if not all(_check(event, k, v) for k, v in cond.items()):
        return False
    if exclude and any(_check(event, k, v) for k, v in exclude.items()):
        return False
    return True


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    type: str
    mitre: list[str]
    description: str = ""
    condition: dict = field(default_factory=dict)
    threshold: dict = field(default_factory=dict)
    sequence: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        rule = cls(id=d["id"], title=d["title"], severity=d.get("severity", "medium"), type=d.get("type", "match"),
                   mitre=_as_list(d.get("mitre", [])), description=d.get("description", ""),
                   condition=d.get("condition", {}), threshold=d.get("threshold", {}), sequence=d.get("sequence", {}))
        if rule.type not in ("match", "threshold", "sequence"):
            raise ValueError(f"{rule.id}: неизвестный тип правила {rule.type}")
        if rule.severity not in SEVERITY_ORDER:
            raise ValueError(f"{rule.id}: неизвестная критичность {rule.severity}")
        return rule


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    mitre: list[str]
    first_seen: datetime
    last_seen: datetime
    host: str
    key: dict
    count: int
    description: str
    evidence: list[str]

    def to_dict(self) -> dict:
        return {"rule_id": self.rule_id, "title": self.title, "severity": self.severity, "mitre": self.mitre,
                "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
                "host": self.host, "key": self.key, "count": self.count,
                "description": self.description, "evidence": self.evidence}


def load_rules(rules_dir: Path) -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(rules_dir.glob("*.y*ml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if doc:
                rules.append(Rule.from_dict(doc))
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("Повторяющиеся id правил")
    return rules


def _alert(rule: Rule, events: list[Event], key: dict) -> Alert:
    return Alert(rule_id=rule.id, title=rule.title, severity=rule.severity, mitre=rule.mitre,
                 first_seen=events[0].timestamp, last_seen=events[-1].timestamp, host=events[-1].host,
                 key=key, count=len(events), description=rule.description,
                 evidence=[e.raw for e in events[:10]])


def _run_match(rule: Rule, events: list[Event]) -> list[Alert]:
    return [_alert(rule, [e], {"user": e.user, "src_ip": e.src_ip} if (e.user or e.src_ip) else {})
            for e in events if matches(e, rule.condition)]


def _run_threshold(rule: Rule, events: list[Event]) -> list[Alert]:
    group_by = _as_list(rule.threshold.get("group_by", []))
    need = int(rule.threshold["count"])
    window = parse_window(rule.threshold["window"])
    distinct = rule.threshold.get("distinct")

    buckets: dict[tuple, deque[Event]] = defaultdict(deque)
    cooldown: dict[tuple, datetime] = {}
    alerts: list[Alert] = []

    for e in events:
        if not matches(e, rule.condition):
            continue
        key = tuple(e.get(f) for f in group_by)
        q = buckets[key]
        q.append(e)
        while q and e.timestamp - q[0].timestamp > window:
            q.popleft()
        value = len({x.get(distinct) for x in q}) if distinct else len(q)
        if value >= need and (key not in cooldown or e.timestamp > cooldown[key]):
            alerts.append(_alert(rule, list(q), dict(zip(group_by, key))))
            cooldown[key] = e.timestamp + window  # не дублировать алерт по той же атаке
    return alerts


def _run_sequence(rule: Rule, events: list[Event], prior: dict[str, list[Alert]]) -> list[Alert]:
    after = prior.get(rule.sequence["after"], [])
    join_on = rule.sequence["join_on"]
    within = parse_window(rule.sequence["within"])
    alerts: list[Alert] = []
    for a in after:
        anchor = a.key.get(join_on)
        for e in events:
            if (e.get(join_on) == anchor and a.last_seen <= e.timestamp <= a.last_seen + within
                    and matches(e, rule.condition)):
                alert = _alert(rule, [e], {join_on: anchor, "user": e.user})
                alert.first_seen = a.first_seen
                alert.count = a.count + 1
                alert.evidence = [f"[после {a.rule_id}: {a.count} событий]"] + alert.evidence
                alerts.append(alert)
                break
    return alerts


def run(rules: list[Rule], events: list[Event]) -> list[Alert]:
    """Прогнать события через все правила. sequence-правила выполняются после остальных."""
    results: dict[str, list[Alert]] = {}
    for rule in sorted(rules, key=lambda r: r.type == "sequence"):
        if rule.type == "match":
            results[rule.id] = _run_match(rule, events)
        elif rule.type == "threshold":
            results[rule.id] = _run_threshold(rule, events)
        else:
            results[rule.id] = _run_sequence(rule, events, results)
    all_alerts = [a for lst in results.values() for a in lst]
    return sorted(all_alerts, key=lambda a: (a.first_seen, a.last_seen))
