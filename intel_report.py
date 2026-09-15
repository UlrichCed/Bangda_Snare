#!/usr/bin/env python3
"""Rapport SOC périodique — agrège logs/honeypot.jsonl en Markdown.

Usage:
    python intel_report.py --since 24h
    python intel_report.py --since all
    python intel_report.py --since 7d --log logs/honeypot.jsonl --out report.md

Conçu pour être lancé en cron (digest quotidien/hebdomadaire). Ne lève
jamais d'exception sur un fichier de log absent ou vide : produit un
rapport minimal indiquant l'absence de données.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from atlas_mapping import map_signals

_SINCE_RE = re.compile(r"^(\d+)([hd])$")


def parse_since(value: str) -> Optional[datetime]:
    if value == "all":
        return None
    m = _SINCE_RE.match(value)
    if not m:
        raise ValueError(f"Format --since invalide: {value!r} (attendu: 'all', '24h', '7d', ...)")
    amount, unit = int(m.group(1)), m.group(2)
    delta = timedelta(hours=amount) if unit == "h" else timedelta(days=amount)
    return datetime.now(timezone.utc) - delta


def load_events(log_path: str, since: Optional[datetime]) -> list[dict]:
    if not os.path.exists(log_path):
        return []
    events = []
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since is not None:
                ts = record.get("timestamp")
                try:
                    ts_dt = datetime.fromisoformat(ts)
                except (TypeError, ValueError):
                    continue
                if ts_dt < since:
                    continue
            events.append(record)
    return events


def build_report(events: list[dict]) -> str:
    lines = []
    lines.append("# Rapport de renseignement — Honeypot HTTP/API")
    lines.append("")
    lines.append(f"Généré le {datetime.now(timezone.utc).isoformat()} UTC.")
    lines.append(f"Évènements analysés : {len(events)}")
    lines.append("")

    if not events:
        lines.append("Aucune activité sur la période sélectionnée.")
        return "\n".join(lines) + "\n"

    sessions: dict[str, dict] = {}
    ip_counter: Counter = Counter()
    tactic_counter: Counter = Counter()
    confessions: list[dict] = []

    for ev in events:
        etype = ev.get("event_type")
        session_id = ev.get("session_id")
        ip = ev.get("ip")
        if ip:
            ip_counter[ip] += 1

        if etype == "request":
            if session_id:
                s = sessions.setdefault(
                    session_id,
                    {"ip": ip, "max_score": 0, "mode": "normal", "signals": set(), "requests": 0},
                )
                s["max_score"] = max(s["max_score"], ev.get("score", 0))
                s["mode"] = ev.get("mode", s["mode"])
                s["requests"] += 1
                for sig in ev.get("signals", []):
                    s["signals"].add(sig)
            for sig in ev.get("signals", []):
                for mapped in map_signals([sig]):
                    tactic_counter[mapped["tactic"]] += 1

        elif etype == "confession":
            confessions.append(ev)

    confirmed_agents = {
        sid: s for sid, s in sessions.items() if s["mode"] in ("deflect", "confess")
    }

    lines.append("## Sessions confirmées comme agents IA")
    lines.append("")
    if confirmed_agents:
        lines.append("| Session | IP | Score max | Mode | Requêtes | Signaux |")
        lines.append("|---|---|---|---|---|---|")
        for sid, s in sorted(confirmed_agents.items(), key=lambda kv: -kv[1]["max_score"]):
            signals_str = ", ".join(sorted(s["signals"])) or "-"
            lines.append(
                f"| `{sid[:12]}` | {s['ip'] or '-'} | {s['max_score']} | {s['mode']} | "
                f"{s['requests']} | {signals_str} |"
            )
    else:
        lines.append("Aucune session n'a atteint le seuil de déroutage sur cette période.")
    lines.append("")

    lines.append("## IPs les plus actives")
    lines.append("")
    if ip_counter:
        lines.append("| IP | Évènements |")
        lines.append("|---|---|")
        for ip, count in ip_counter.most_common(10):
            lines.append(f"| {ip} | {count} |")
    else:
        lines.append("Aucune IP enregistrée.")
    lines.append("")

    lines.append("## Tactiques ATLAS observées")
    lines.append("")
    if tactic_counter:
        lines.append("| Tactique | Occurrences |")
        lines.append("|---|---|")
        for tactic, count in tactic_counter.most_common():
            lines.append(f"| {tactic} | {count} |")
    else:
        lines.append("Aucun signal mappé sur cette période.")
    lines.append("")

    lines.append("## Aveux capturés (déclaratifs, non vérifiés)")
    lines.append("")
    if confessions:
        for c in confessions:
            sid = c.get("session_id", "?")
            ip = c.get("ip", "?")
            declared = c.get("confession", {})
            analysis = c.get("analysis")
            lines.append(f"### Session `{sid[:12]}` — IP {ip}")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(declared, ensure_ascii=False, indent=2))
            lines.append("```")
            if analysis:
                lines.append("")
                lines.append("Analyse (assistée, si activée) :")
                lines.append("```json")
                lines.append(json.dumps(analysis, ensure_ascii=False, indent=2))
                lines.append("```")
            lines.append("")
    else:
        lines.append("Aucune auto-dénonciation capturée sur cette période.")
    lines.append("")

    lines.append(
        "> **Note** : les aveux ci-dessus sont des déclarations non vérifiées "
        "fournies par le client suspecté. À traiter comme piste de "
        "renseignement, jamais comme preuve en soi."
    )

    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default="24h", help="'all', '24h', '7d', etc.")
    parser.add_argument("--log", default="logs/honeypot.jsonl", help="Chemin du log JSONL.")
    parser.add_argument("--out", default=None, help="Fichier de sortie (défaut: stdout).")
    args = parser.parse_args(argv)

    try:
        since = parse_since(args.since)
    except ValueError as exc:
        print(f"Erreur: {exc}", file=sys.stderr)
        return 1

    events = load_events(args.log, since)
    report = build_report(events)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report)
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
