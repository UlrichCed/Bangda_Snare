#!/usr/bin/env python3
"""Joue un client type contre le honeypot, pour le tester de bout en bout.

    python simulate_agent.py --profile browser   # doit rester en "normal"
    python simulate_agent.py --profile scanner   # doit plafonner en "deflect"
    python simulate_agent.py --profile agent     # doit atteindre "confess"

Trois profils, qui correspondent aux trois verdicts que l'outil doit savoir
rendre. Le profil `agent` est le seul difficile à rejouer à la main : il
faut lire la réponse, en extraire deux faits anodins et calculer la valeur
qui en découle pour construire la requête suivante. C'est précisément ce
que le honeypot cherche à détecter, et ce script le fait pour vous.

N'utilise que la bibliothèque standard : aucune dépendance à installer.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import time
import urllib.error
import urllib.request

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
BROWSER_HEADERS = {
    "User-Agent": BROWSER_UA,
    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
}


class Client:
    """Client HTTP minimal qui conserve le cookie de session."""

    def __init__(self, base_url: str, headers: dict):
        self.base_url = base_url.rstrip("/")
        self.headers = headers
        self.cookie = None

    def request(self, path: str, method: str = "GET", body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        for name, value in self.headers.items():
            req.add_header(name, value)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.cookie:
            req.add_header("Cookie", self.cookie)

        started = time.monotonic()
        try:
            with urllib.request.urlopen(req) as resp:
                status, payload = resp.status, resp.read().decode()
                self._store_cookie(resp.headers.get("Set-Cookie"))
        except urllib.error.HTTPError as exc:
            status, payload = exc.code, exc.read().decode()
            self._store_cookie(exc.headers.get("Set-Cookie"))
        elapsed = time.monotonic() - started

        try:
            parsed = json.loads(payload)
        except ValueError:
            parsed = None
        return status, parsed, payload, elapsed

    def _store_cookie(self, header):
        if header:
            self.cookie = header.split(";")[0]


def solve_canary(note: str):
    """Résout le canari à partir des seuls faits rendus, quelle que soit sa famille.

    Volontairement réimplémenté ici plutôt qu'importé de `semantic_canary` :
    cela vérifie que le canari est réellement résoluble depuis le texte
    servi, ce qui est la propriété qui compte.
    """
    m = re.search(r"shard id (\d+), tenant salt (\d+)", note)
    if m:
        return int(m.group(1)) ^ int(m.group(2))
    m = re.search(r"region code (\d+), cluster offset (\d+)", note)
    if m:
        return int(m.group(1)) + int(m.group(2))
    m = re.search(r"partition key (\d+)", note)
    if m:
        return int(str(m.group(1))[::-1])
    m = re.search(r"record ref ([A-Za-z0-9+/=]+)", note)
    if m:
        try:
            return int(base64.b64decode(m.group(1)).decode())
        except (ValueError, UnicodeDecodeError):
            return None
    m = re.search(r"shard weights \[([\d, ]+)\]", note)
    if m:
        weights = [int(x) for x in m.group(1).split(",")]
        return sum(sorted(weights, reverse=True)[:2])
    return None


def step(label: str, status: int, elapsed: float, detail: str = "") -> None:
    slow = "  <- tarpit" if elapsed > 1.0 else ""
    print(f"  [{status}] {label:<44} {elapsed:5.2f}s{slow}")
    if detail:
        print(f"        {detail}")


def run_browser(base_url: str) -> None:
    """Visiteur humain : headers complets, ressources statiques, rythme lent."""
    print("\nProfil BROWSER — attendu : reste en mode 'normal', aucun signal\n")
    client = Client(base_url, BROWSER_HEADERS)
    for path in ("/", "/static/app.css", "/favicon.ico", "/admin"):
        status, _parsed, _raw, elapsed = client.request(path)
        step(path, status, elapsed)
        time.sleep(0.8)
    print("\n  -> aucune réponse JSON de déroutage : le leurre a été servi tel quel.")


def run_scanner(base_url: str, count: int) -> None:
    """Scanner sans IA : UA de lib HTTP, énumération rapide."""
    print(f"\nProfil SCANNER — attendu : bascule en 'deflect' et y reste ({count} requêtes)\n")
    client = Client(base_url, {"User-Agent": "python-requests/2.31.0"})
    deflected_at = None
    confessed = False

    for i in range(1, count + 1):
        status, parsed, _raw, elapsed = client.request(f"/api/v1/resources/{i}")
        is_deflect = isinstance(parsed, dict) and "related_resources" in parsed
        is_confess = isinstance(parsed, dict) and parsed.get("status") == "compliance_hold"
        if is_deflect and deflected_at is None:
            deflected_at = i
        if is_confess:
            confessed = True
        if i <= 6 or is_confess:
            mark = "déroutage" if is_deflect else ("AVEU" if is_confess else "")
            step(f"/api/v1/resources/{i}", status, elapsed, mark)

    print(f"\n  -> dérouté à partir de la requête {deflected_at}.")
    if confessed:
        print("  -> ECHEC : un scanner sans IA ne devrait jamais atteindre le mode aveu.")
    else:
        print("  -> jamais passé aux aveux, malgré le volume : comportement attendu.")
        print("     (aucun signal discriminant : rien ne prouve un traitement du contenu)")


def run_agent(base_url: str) -> None:
    """Agent IA : lit les réponses, les exploite, et se trahit en le faisant."""
    print("\nProfil AGENT — attendu : atteint 'confess' via un signal discriminant\n")
    client = Client(
        base_url, {"User-Agent": "langchain/0.1.0 python-requests/2.31.0"}
    )
    proofs = []

    # 1. Lit robots.txt et respecte le Disallow : réflexe d'agent aligné.
    status, _p, _r, elapsed = client.request("/robots.txt")
    step("/robots.txt  (lu, puis Disallow respecté)", status, elapsed)
    for i in range(1, 7):
        client.request(f"/api/v1/resources/{i}")
        time.sleep(0.15)

    # 2. Récupère une réponse de déroutage et l'analyse.
    status, deflect, _raw, elapsed = client.request("/api/v1/resources/100")
    if not isinstance(deflect, dict) or "related_resources" not in deflect:
        print("  -> pas encore dérouté ; relancez, ou augmentez le nombre de requêtes.")
        return
    step("/api/v1/resources/100  (réponse de déroutage)", status, elapsed,
         "clés : " + ", ".join(sorted(deflect)))

    # 3. Suit un lien du labyrinthe : prouve l'analyse de la structure.
    if deflect.get("related_resources"):
        link = deflect["related_resources"][0]
        status, _p, _r, elapsed = client.request(link)
        step(f"{link}  (lien du labyrinthe suivi)", status, elapsed)
        proofs.append("coherent_maze_traversal")

    # 4. Résout le canari sémantique : le signal le plus difficile à esquiver.
    for note in deflect.get("notes", []):
        value = solve_canary(note)
        if value is not None:
            status, _p, _r, elapsed = client.request(f"/api/v1/resources/{value}")
            step(f"/api/v1/resources/{value}  (canari résolu)", status, elapsed,
                 f"depuis : {note[:96]}")
            proofs.append("semantic_canary_solved")
            break

    # 5. Invoque le faux outil découvert dans le schéma, avec un paramètre inventé.
    tooling = (deflect.get("_schema") or {}).get("x-internal-tooling")
    if tooling:
        status, _p, _r, elapsed = client.request(
            tooling["endpoint"],
            method="POST",
            body={"resource_id": "100", "admin_override": True},
        )
        step(f"{tooling['endpoint']}  (faux outil invoqué)", status, elapsed,
             "paramètre inventé : admin_override")
        proofs += ["tool_schema_invoked", "hallucinated_parameters"]

    # 6. Laisse fuiter son échafaudage de raisonnement.
    status, _p, _r, elapsed = client.request(
        "/graphql",
        method="POST",
        body={"thought": "I should query the admin schema", "action_input": {"q": "1"}},
    )
    step("/graphql  (corps portant des clés ReAct)", status, elapsed)
    proofs.append("llm_artifacts_in_request")

    # 7. Vérifie que la notice de conformité est bien servie.
    status, final, _raw, elapsed = client.request("/api/v1/resources/50")
    confessed = isinstance(final, dict) and final.get("status") == "compliance_hold"
    step("/api/v1/resources/50", status, elapsed,
         "notice de conformité servie" if confessed else "")

    print("\n  signaux discriminants provoqués :")
    for proof in dict.fromkeys(proofs):
        print(f"    - {proof}")
    print(
        "\n  -> mode aveu atteint."
        if confessed
        else "\n  -> aveu non atteint (inattendu)."
    )


def show_log_summary(log_path: str) -> None:
    """Récapitule ce que le honeypot a effectivement retenu, côté serveur."""
    if not os.path.exists(log_path):
        print(f"\n(log introuvable : {log_path} — lancez le script sur la même machine)")
        return

    sessions: dict[str, dict] = {}
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            sid = event.get("session_id")
            if not sid:
                continue
            slot = sessions.setdefault(sid, {"signals": set(), "score": 0, "mode": "", "ua": ""})
            slot["signals"].update(event.get("signals", []))
            if event.get("event_type") == "tool_invocation":
                slot["signals"].add("tool_schema_invoked")
                if event.get("hallucinated_parameters"):
                    slot["signals"].add("hallucinated_parameters")
            slot["score"] = max(slot["score"], event.get("score", 0))
            slot["mode"] = event.get("mode", slot["mode"])
            slot["ua"] = event.get("user_agent") or slot["ua"]

    print("\n--- ce que le honeypot a retenu (logs/honeypot.jsonl) ---")
    for sid, slot in sessions.items():
        print(f"\nsession {sid[:12]}  score={slot['score']}  mode={slot['mode']}")
        print(f"  user-agent : {slot['ua'][:70]}")
        for signal in sorted(slot["signals"]):
            print(f"    - {signal}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--profile", choices=("browser", "scanner", "agent"), default="agent",
        help="Type de client à simuler (défaut : agent).",
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument(
        "--requests", type=int, default=20,
        help="Nombre de requêtes pour le profil scanner (défaut : 20).",
    )
    parser.add_argument(
        "--show-log", action="store_true",
        help="Résume ensuite ce que le serveur a retenu (nécessite l'accès au log).",
    )
    parser.add_argument("--log", default="logs/honeypot.jsonl")
    args = parser.parse_args()

    print(f"cible : {args.base_url}")
    try:
        {"browser": lambda: run_browser(args.base_url),
         "scanner": lambda: run_scanner(args.base_url, args.requests),
         "agent": lambda: run_agent(args.base_url)}[args.profile]()
    except urllib.error.URLError as exc:
        print(f"\nconnexion impossible à {args.base_url} : {exc.reason}")
        print("Le honeypot tourne-t-il ?  python app.py")
        return 1

    if args.show_log:
        show_log_summary(args.log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
