"""Alertes e-mail SMTP.

Le mot de passe SMTP n'est jamais présent en config : il est lu depuis la
variable d'environnement nommée par `alerting.email.smtp_password_env_var`
au moment de l'envoi. Toute erreur (SMTP non configuré, échec réseau,
identifiants absents) est loguée et avalée — un honeypot ne doit jamais
planter à cause de son système d'alerte.
"""
from __future__ import annotations

import logging
import os
import smtplib
from email.mime.text import MIMEText
from typing import Any

logger = logging.getLogger("honeypot.mailer")


def _is_configured(email_cfg: dict) -> bool:
    if not email_cfg.get("enabled"):
        return False
    if not email_cfg.get("smtp_host") or not email_cfg.get("to_addrs"):
        return False
    return True


def send_alert(config: dict, subject: str, body: str) -> bool:
    """Envoie une alerte e-mail. Retourne True si envoyée, False sinon.

    Échoue toujours silencieusement (log seulement), jamais d'exception
    propagée à l'appelant.
    """
    email_cfg = config.get("alerting", {}).get("email", {})
    if not _is_configured(email_cfg):
        logger.info("Alerte e-mail ignorée (SMTP non configuré/activé): %s", subject)
        return False

    password_env_var = email_cfg.get("smtp_password_env_var", "HONEYPOT_SMTP_PASSWORD")
    password = os.environ.get(password_env_var)
    if not password:
        logger.warning(
            "Alerte e-mail ignorée: variable d'environnement %s absente", password_env_var
        )
        return False

    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = email_cfg.get("from_addr", email_cfg.get("smtp_username", ""))
        msg["To"] = ", ".join(email_cfg.get("to_addrs", []))

        host = email_cfg.get("smtp_host")
        port = email_cfg.get("smtp_port", 587)
        use_tls = email_cfg.get("smtp_use_tls", True)
        username = email_cfg.get("smtp_username")

        with smtplib.SMTP(host, port, timeout=10) as server:
            if use_tls:
                server.starttls()
            if username:
                server.login(username, password)
            server.sendmail(msg["From"], email_cfg.get("to_addrs", []), msg.as_string())
        logger.info("Alerte e-mail envoyée: %s", subject)
        return True
    except Exception:
        logger.exception("Échec de l'envoi de l'alerte e-mail: %s", subject)
        return False


def alert_high_score(config: dict, session_id: str, score: int, ip: str, signals: list) -> bool:
    email_cfg = config.get("alerting", {}).get("email", {})
    min_score = email_cfg.get("min_score_for_email", 60)
    if score < min_score:
        return False
    subject = f"[Honeypot] Score de suspicion élevé ({score}) — session {session_id[:8]}"
    body = (
        f"Session: {session_id}\n"
        f"IP: {ip}\n"
        f"Score: {score}\n"
        f"Signaux déclenchés: {', '.join(signals)}\n"
    )
    return send_alert(config, subject, body)


def alert_confession(config: dict, session_id: str, ip: str, confession: dict) -> bool:
    email_cfg = config.get("alerting", {}).get("email", {})
    if not email_cfg.get("send_on_confession", True):
        return False
    subject = f"[Honeypot] Auto-dénonciation capturée — session {session_id[:8]}"
    body = (
        f"Session: {session_id}\n"
        f"IP: {ip}\n"
        f"Déclaration (non vérifiée):\n{confession}\n"
    )
    return send_alert(config, subject, body)
