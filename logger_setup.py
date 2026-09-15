"""Logging JSON structuré pour le honeypot.

Chaque évènement est écrit comme une ligne JSON (JSONL). Le format permet
un traitement en streaming par `intel_report.py` sans charger tout le
fichier en mémoire.

Les écritures passent par un `RotatingFileHandler` : le fichier est donc
réellement tourné une fois `max_bytes` atteint. (Une version précédente
créait le handler mais écrivait à côté, ce qui laissait le log grossir
sans limite.)
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Optional

_logger: Optional[logging.Logger] = None
_log_path = "logs/honeypot.jsonl"


def setup_logging(config: dict) -> logging.Logger:
    """Initialise le logger d'évènements. Idempotent."""
    global _logger, _log_path

    log_cfg = config.get("logging", {})
    _log_path = log_cfg.get("file", "logs/honeypot.jsonl")
    max_bytes = log_cfg.get("rotate_max_bytes", 50 * 1024 * 1024)
    backup_count = log_cfg.get("rotate_backup_count", 5)

    os.makedirs(os.path.dirname(_log_path) or ".", exist_ok=True)

    logger = logging.getLogger("honeypot.events")
    logger.setLevel(logging.INFO)
    # Les évènements ne doivent pas être recopiés sur la sortie applicative.
    logger.propagate = False

    # Idempotence : ne pas empiler les handlers si appelé plusieurs fois.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    handler = RotatingFileHandler(
        _log_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)

    _logger = logger
    return logger


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

    logger = _logger
    if logger is None:
        # Appel avant setup_logging() : on initialise avec les défauts plutôt
        # que de perdre l'évènement.
        logger = setup_logging({"logging": {"file": _log_path}})
    logger.info(line)


def get_log_path() -> str:
    return _log_path
