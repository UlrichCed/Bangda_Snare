"""Logging JSON structuré pour le honeypot.

Chaque évènement est écrit comme une ligne JSON (JSONL) dans le fichier
configuré (`logging.file`). Le format JSONL permet un traitement en
streaming par `intel_report.py` sans jamais charger tout le fichier en
mémoire.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any


_write_lock = threading.Lock()
_configured = False
_log_path = "logs/honeypot.jsonl"


def setup_logging(config: dict) -> None:
    """Initialise le chemin de log et s'assure que le dossier existe.

    Idempotent : peut être appelé plusieurs fois sans effet de bord.
    """
    global _configured, _log_path
    _log_path = config.get("logging", {}).get("file", "logs/honeypot.jsonl")
    os.makedirs(os.path.dirname(_log_path) or ".", exist_ok=True)
    if not _configured:
        # Rotation défensive : évite une croissance illimitée si l'outil de
        # rotation externe (logrotate, etc.) n'est pas encore en place.
        handler = RotatingFileHandler(
            _log_path, maxBytes=50 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        root = logging.getLogger("honeypot.rotation")
        root.setLevel(logging.INFO)
        root.addHandler(handler)
        _configured = True


def log_event(event_type: str, **fields: Any) -> None:
    """Écrit un évènement structuré en une ligne JSON.

    Ajoute automatiquement `timestamp` (UTC ISO 8601) et `event_type`.
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        **fields,
    }
    line = json.dumps(record, ensure_ascii=False, default=str)
    with _write_lock:
        os.makedirs(os.path.dirname(_log_path) or ".", exist_ok=True)
        with open(_log_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def get_log_path() -> str:
    return _log_path
