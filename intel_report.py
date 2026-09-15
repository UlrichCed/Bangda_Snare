#!/usr/bin/env python3
"""Rapport SOC périodique : agrège logs/honeypot.jsonl en Markdown.

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

from atlas_mapping import assess_injection_tier, map_signals
from detector import DISCRIMINATING_SIGNALS

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


def _build_campaigns(events: list[dict]) -> dict:
    """Reconstitue les campagnes depuis les rattachements journalisés.

    Union-find, pour que A-B puis B-C forment bien un seul groupe. Seuls
    les groupes de plus d'une session sont retournés.
    """
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(a: str, b: str) -> None:
        root_a, root_b = find(a), find(b)
        if root_a != root_b:
            parent[root_b] = root_a

    for event in events:
        session_id = event.get("session_id")
        for linked in event.get("linked_sessions") or []:
            if session_id and linked:
                union(session_id, linked)

    grouped: dict[str, set] = {}
    for node in parent:
        grouped.setdefault(find(node), set()).add(node)
    return {root: members for root, members in grouped.items() if len(members) > 1}


def build_report(events: list[dict]) -> str:
    lines = []
    lines.append("# Rapport de renseignement : Honeypot HTTP/API")
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
    tool_invocations: list[dict] = []

    def session_slot(session_id, ip):
        return sessions.setdefault(
            session_id,
            {
                "ip": ip,
                "max_score": 0,
                "mode": "normal",
                "tier": "observe",
                "signals": set(),
                "requests": 0,
                "user_agents": set(),
            },
        )

    for ev in events:
        etype = ev.get("event_type")
        session_id = ev.get("session_id")
        ip = ev.get("ip")
        if ip:
            ip_counter[ip] += 1

        if etype == "request":
            if session_id:
                s = session_slot(session_id, ip)
                s["max_score"] = max(s["max_score"], ev.get("score", 0))
                s["mode"] = ev.get("mode", s["mode"])
                s["tier"] = ev.get("tier", s["tier"])
                s["requests"] += 1
                s["signals"].update(ev.get("signals", []))
                if ev.get("user_agent"):
                    s["user_agents"].add(ev["user_agent"])
            for sig in ev.get("signals", []):
                for mapped in map_signals([sig]):
                    tactic_counter[mapped["tactic"]] += 1

        elif etype == "confession":
            confessions.append(ev)

        elif etype == "tool_invocation":
            tool_invocations.append(ev)
            if session_id:
                s = session_slot(session_id, ip)
                s["signals"].add("tool_schema_invoked")
                s["max_score"] = max(s["max_score"], ev.get("score", 0))

    confirmed_agents = {
        sid: s for sid, s in sessions.items() if s["mode"] in ("deflect", "confess")
    }

    # Un agent est *confirmé* par un signal discriminant, pas par un score.
    proven_agents = {
        sid: s for sid, s in sessions.items() if s["signals"] & DISCRIMINATING_SIGNALS
    }

    lines.append("## Agents IA confirmés (signal discriminant observé)")
    lines.append("")
    if proven_agents:
        lines.append("| Session | IP | Score | Palier | Requêtes | Preuves |")
        lines.append("|---|---|---|---|---|---|")
        for sid, s in sorted(proven_agents.items(), key=lambda kv: -kv[1]["max_score"]):
            proofs = ", ".join(sorted(s["signals"] & DISCRIMINATING_SIGNALS))
            lines.append(
                f"| `{sid[:12]}` | {s['ip'] or '-'} | {s['max_score']} | {s['tier']} | "
                f"{s['requests']} | {proofs} |"
            )
    else:
        lines.append(
            "Aucun signal discriminant observé : rien ne prouve le passage d'un agent IA "
            "sur cette période."
        )
    lines.append("")

    lines.append("## Sessions déroutées (suspectes, non confirmées)")
    lines.append("")
    suspect_only = {
        sid: s
        for sid, s in confirmed_agents.items()
        if sid not in proven_agents
    }
    if suspect_only:
        lines.append("| Session | IP | Score max | Palier | Requêtes | Signaux |")
        lines.append("|---|---|---|---|---|---|")
        for sid, s in sorted(suspect_only.items(), key=lambda kv: -kv[1]["max_score"]):
            signals_str = ", ".join(sorted(s["signals"])) or "-"
            lines.append(
                f"| `{sid[:12]}` | {s['ip'] or '-'} | {s['max_score']} | {s['tier']} | "
                f"{s['requests']} | {signals_str} |"
            )
    else:
        lines.append("Aucune.")
    lines.append("")

    campaigns = _build_campaigns(events)
    if campaigns:
        lines.append("## Campagnes (identités reliées)")
        lines.append("")
        lines.append(
            "Sessions reliées par le rejeu d'un piège servi à une autre "
            "identité. La valeur rejouée étant imprévisible, elle n'a pas pu "
            "circuler autrement : le même opérateur est derrière les deux. "
            "C'est ce qui défait la rotation d'IP et de user-agent."
        )
        lines.append("")
        for index, (_root, members) in enumerate(sorted(campaigns.items()), start=1):
            ips = sorted({sessions[s]["ip"] for s in members if s in sessions and sessions[s]["ip"]})
            agents = sorted(
                {ua for s in members if s in sessions for ua in sessions[s]["user_agents"]}
            )
            lines.append(f"- **Campagne {index}** : {len(members)} sessions")
            lines.append(f"  - sessions : {', '.join(f'`{s[:12]}`' for s in sorted(members))}")
            lines.append(f"  - IPs : {', '.join(ips) or '-'}")
            lines.append(f"  - user-agents : {', '.join(a[:48] for a in agents) or '-'}")
        lines.append("")

    if tool_invocations:
        lines.append("## Invocations du faux outil")
        lines.append("")
        lines.append(
            "Atteindre cet endpoint suppose d'avoir lu un schéma d'outil dans une "
            "réponse et décidé de l'invoquer : comportement d'agent outillé. Les "
            "arguments renseignent directement sur l'intention."
        )
        lines.append("")
        for ev in tool_invocations[:20]:
            invented = ev.get("hallucinated_parameters") or []
            lines.append(
                f"- `{(ev.get('session_id') or '?')[:12]}` depuis {ev.get('ip', '?')} : "
                f"`{json.dumps(ev.get('arguments', {}), ensure_ascii=False)}`"
                + (f" (paramètres inventés : {', '.join(invented)})" if invented else "")
            )
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
            lines.append(f"### Session `{sid[:12]}` : IP {ip}")
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


def build_iocs(events: list[dict]) -> dict:
    """Indicateurs exploitables, restreints aux agents effectivement prouvés.

    On n'exporte que les sessions portant un signal discriminant : diffuser
    des IPs simplement « suspectes » produirait des blocages à tort chez
    ceux qui consomment le flux.
    """
    sessions: dict[str, dict] = {}
    for ev in events:
        sid = ev.get("session_id")
        if not sid:
            continue
        slot = sessions.setdefault(sid, {"ips": set(), "user_agents": set(), "signals": set()})
        if ev.get("ip"):
            slot["ips"].add(ev["ip"])
        if ev.get("user_agent"):
            slot["user_agents"].add(ev["user_agent"])
        slot["signals"].update(ev.get("signals", []))
        if ev.get("event_type") == "tool_invocation":
            slot["signals"].add("tool_schema_invoked")

    confirmed = {
        sid: slot for sid, slot in sessions.items() if slot["signals"] & DISCRIMINATING_SIGNALS
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "confidence": "confirmed_ai_agent",
        "note": (
            "Sessions portant au moins un signal discriminant (traitement "
            "avéré du contenu servi). Renseignement, non probatoire."
        ),
        "indicators": [
            {
                "session_id": sid,
                "ip_addresses": sorted(slot["ips"]),
                "user_agents": sorted(slot["user_agents"]),
                "evidence": sorted(slot["signals"] & DISCRIMINATING_SIGNALS),
            }
            for sid, slot in sorted(confirmed.items())
        ],
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default="24h", help="'all', '24h', '7d', etc.")
    parser.add_argument("--log", default="logs/honeypot.jsonl", help="Chemin du log JSONL.")
    parser.add_argument("--out", default=None, help="Fichier de sortie (défaut: stdout).")
    parser.add_argument(
        "--ioc-out",
        default=None,
        help="Écrit en plus les indicateurs (JSON) des agents confirmés.",
    )
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

    if args.ioc_out:
        with open(args.ioc_out, "w", encoding="utf-8") as fh:
            json.dump(build_iocs(events), fh, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
