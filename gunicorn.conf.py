"""Configuration gunicorn pour le honeypot.

Les workers **gevent** ne sont pas un détail de perf : le tarpit endort
volontairement la requête jusqu'à `deflection.tarpit_max_delay`. Avec des
workers `sync`, chaque client ralenti immobilise un worker entier et
quelques connexions suffisent à saturer le honeypot avec son propre
tarpit. gevent rend ces attentes coopératives (il patche `time.sleep`),
ce qui permet de tenir des milliers de connexions ralenties par worker.

Lancement :
    gunicorn -c gunicorn.conf.py app:app
"""
import os

bind = os.environ.get("HONEYPOT_BIND", "0.0.0.0:8080")

worker_class = "gevent"

# UN SEUL worker, volontairement. L'état des sessions vit dans la mémoire du
# process : avec plusieurs workers, les requêtes d'une même session sont
# réparties entre processus et chacun n'en voit qu'une fraction : le score
# se fragmente et les seuils ne sont jamais atteints. La concurrence vient
# ici de gevent (worker_connections), pas du nombre de workers.
# Pour passer à plusieurs workers (ou plusieurs machines), il faudrait
# d'abord sortir l'état de SessionTracker vers un store partagé.
workers = int(os.environ.get("HONEYPOT_WORKERS", "1"))
worker_connections = int(os.environ.get("HONEYPOT_WORKER_CONNECTIONS", "1000"))

# Doit rester nettement supérieur à tarpit_max_delay, sinon gunicorn tue les
# requêtes que le tarpit est justement en train de faire traîner.
timeout = int(os.environ.get("HONEYPOT_TIMEOUT", "60"))
graceful_timeout = 30
keepalive = 5

# Les évènements métier vont dans logs/honeypot.jsonl ; ici on ne garde que
# les logs techniques, sur stdout/stderr pour le collecteur du conteneur.
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("HONEYPOT_LOG_LEVEL", "info")

# L'état des sessions est en mémoire process : le recyclage automatique de
# workers le jetterait en cours de route. On le laisse donc désactivé.
max_requests = 0

proc_name = "ai-honeypot"
