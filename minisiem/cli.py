"""mini-SIEM: python -m minisiem.cli samples/auth.log samples/windows_events.jsonl"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from jinja2 import Template

from .engine import SEVERITY_ORDER, load_rules, run
from .parsers import load_events

COLORS = {"critical": "#8e1b1b", "high": "#d9480f", "medium": "#e8a317", "low": "#5c7cfa"}

TEMPLATE = Template("""<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8"><title>mini-SIEM — отчёт</title>
<style>
body{font-family:system-ui,sans-serif;margin:32px;color:#222;max-width:1150px}
table{border-collapse:collapse;margin:10px 0 24px;font-size:13.5px;width:100%}
th,td{border:1px solid #ddd;padding:6px 9px;text-align:left;vertical-align:top}
th{background:#f3f3f3} .sev{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}
.cards{display:flex;gap:14px;margin:16px 0}.card{border:1px solid #ddd;border-radius:8px;padding:12px 18px;min-width:110px}
.card b{font-size:26px;display:block} code{font-size:12px;word-break:break-all;color:#444}
details summary{cursor:pointer;color:#555}
</style></head><body>
<h1>mini-SIEM — отчёт по инцидентам</h1>
<p style="color:#666">Сформирован {{ generated }} · событий: {{ n_events }} · правил: {{ n_rules }} · источники: {{ sources }}</p>
<div class="cards">
{% for sev in ["critical","high","medium","low"] %}<div class="card" style="border-left:5px solid {{ colors[sev] }}"><b>{{ by_sev.get(sev,0) }}</b>{{ sev }}</div>{% endfor %}
</div>

<h2>Хронология алертов</h2>
<table><tr><th>Время</th><th>Критичность</th><th>Правило</th><th>Хост</th><th>Ключ</th><th>Событий</th><th>MITRE ATT&CK</th></tr>
{% for a in alerts %}<tr><td>{{ a.first_seen.strftime("%d.%m %H:%M:%S") }}</td>
<td><span class="sev" style="background:{{ colors[a.severity] }}">{{ a.severity }}</span></td>
<td><b>{{ a.rule_id }}</b> {{ a.title }}<details><summary>доказательства</summary>{% for e in a.evidence %}<code>{{ e }}</code><br>{% endfor %}</details></td>
<td>{{ a.host }}</td><td>{% for k,v in a.key.items() if v %}{{ k }}={{ v }}<br>{% endfor %}</td><td>{{ a.count }}</td>
<td>{% for t in a.mitre %}<a href="https://attack.mitre.org/techniques/{{ t.replace('.', '/') }}/">{{ t }}</a> {% endfor %}</td></tr>{% endfor %}
</table>

<h2>Покрытие MITRE ATT&CK</h2>
<table><tr><th>Техника</th><th>Правила</th><th>Сработало</th></tr>
{% for t, row in coverage %}<tr><td><a href="https://attack.mitre.org/techniques/{{ t.replace('.', '/') }}/">{{ t }}</a></td>
<td>{{ row.rules|join(", ") }}</td><td>{{ "✔ " ~ row.hits if row.hits else "—" }}</td></tr>{% endfor %}
</table>
</body></html>""", autoescape=True)


def build_report(alerts, events, rules) -> str:
    coverage: dict[str, dict] = {}
    for r in rules:
        for t in r.mitre:
            coverage.setdefault(t, {"rules": [], "hits": 0})["rules"].append(r.id)
    for a in alerts:
        for t in a.mitre:
            coverage[t]["hits"] += 1
    return TEMPLATE.render(
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"), n_events=len(events), n_rules=len(rules),
        sources=", ".join(sorted({e.source for e in events})), alerts=alerts, colors=COLORS,
        by_sev=Counter(a.severity for a in alerts), coverage=sorted(coverage.items()),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="mini-SIEM: корреляция событий безопасности")
    parser.add_argument("logs", nargs="+", type=Path, help="auth.log и/или *.jsonl с событиями Windows")
    parser.add_argument("-r", "--rules", type=Path, default=Path(__file__).resolve().parent.parent / "rules")
    parser.add_argument("-o", "--out-dir", type=Path, default=Path("out"))
    parser.add_argument("--year", type=int, help="год для auth.log (в syslog его нет)")
    parser.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low")
    args = parser.parse_args()

    rules = load_rules(args.rules)
    events = load_events(args.logs, args.year)
    alerts = [a for a in run(rules, events) if SEVERITY_ORDER[a.severity] >= SEVERITY_ORDER[args.min_severity]]

    args.out_dir.mkdir(parents=True, exist_ok=True)
    with open(args.out_dir / "alerts.jsonl", "w", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a.to_dict(), ensure_ascii=False) + "\n")
    (args.out_dir / "report.html").write_text(build_report(alerts, events, rules), encoding="utf-8")

    print(f"Событий: {len(events)} | правил: {len(rules)} | алертов: {len(alerts)}\n")
    for a in alerts:
        key = " ".join(f"{k}={v}" for k, v in a.key.items() if v)
        print(f"{a.first_seen:%d.%m %H:%M:%S}  {a.severity.upper():8} {a.rule_id}  {a.title}  [{a.host}] {key}  ({', '.join(a.mitre)})")
    print(f"\nОтчёт: {args.out_dir / 'report.html'}, алерты: {args.out_dir / 'alerts.jsonl'}")


if __name__ == "__main__":
    main()
