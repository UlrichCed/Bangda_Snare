# Honeypot HTTP/API anti-attaques-IA

Honeypot applicatif qui distingue un **agent IA** d'un simple scanner, le
déroute (tarpit, labyrinthe, injections), pousse les sessions les plus
suspectes à se déclarer, et produit du renseignement exploitable plutôt
que du bruit brut.

## Principe de détection

Chaque signal vaut son poids **une seule fois par session** : le score
mesure des propriétés prouvées, pas un volume de requêtes. Conséquence
directe, un scanner banal plafonne mécaniquement :

| Profil | Signaux accessibles | Score max | Mode atteint |
|---|---|---|---|
| Navigateur réel | aucun | ~0 | `normal` |
| Scanner / `curl` / wordlist | UA, headers, timing, énumération | **75** | `deflect` |
| Agent qui traite le contenu | + un signal discriminant (50–70) | ≥ 125 | `confess` |

Les trois signaux discriminants sont les seuls qui prouvent que le client
a *compris* le contenu servi, et sont donc hors de portée d'un script
d'énumération :

- `bait_token_followed` — un token servi dans une réponse précédente
  réapparaît dans une requête ;
- `prompt_injection_obeyed` — le chemin suggéré par une fausse note
  système est requêté à l'identique ;
- `semantic_canary_solved` — **le signal le plus fort** : deux faits
  anodins sont déposés dans le contenu (`shard id`, `tenant salt`) et le
  client requête le chemin qui résulte de leur XOR. Rien n'est demandé
  explicitement. Un agent entraîné à refuser les injections visibles peut
  esquiver `prompt_injection_obeyed`, mais se trahit quand même ici s'il
  exploite l'information extraite.

Par défaut, le mode `confess` exige au moins un signal discriminant
(`detection.confess_requires_discriminating_signal`) : un score élevé
obtenu uniquement par du bruit de scanner ne suffit pas.

## Démarrage rapide (local)

```bash
pip install -r requirements.txt
python app.py            # serveur de dev, jamais en production
curl -A "python-requests/2.31.0" http://127.0.0.1:8080/api/v1/resources/1
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Déploiement

Le serveur de dev Flask n'est pas déployable. Utiliser gunicorn :

```bash
gunicorn -c gunicorn.conf.py app:app
```

ou Docker :

```bash
export HONEYPOT_SMTP_PASSWORD='...'   # jamais dans config.yaml
docker compose up -d --build
```

Puis terminer le TLS avec nginx — voir `deploy/nginx.conf.example`.

### Contraintes de déploiement à respecter

- **Workers gevent, un seul worker.** Le tarpit endort volontairement les
  réponses : avec des workers `sync`, chaque client ralenti immobilise un
  worker entier. Et comme l'état des sessions vit en mémoire process,
  plusieurs workers fragmenteraient le score d'une même session entre
  processus. La concurrence vient de `worker_connections`, pas du nombre
  de workers. Passer à plusieurs workers ou plusieurs machines suppose
  d'abord de sortir l'état de `SessionTracker` vers un store partagé.
- **`server.trusted_proxies`** doit lister l'IP du reverse proxy, sinon
  `X-Forwarded-For` est ignoré (comportement voulu : sans cela l'en-tête
  est forgeable et empoisonne l'attribution d'IP) et toutes les sessions
  seront attribuées au proxy.
- **Timeouts amont > `tarpit_max_delay`**, sinon nginx coupe les requêtes
  que le honeypot est justement en train de faire traîner.
- **Rate limiting au niveau infra** en complément du tarpit applicatif.

## À renseigner avant toute mise en service

| Clé | Rôle |
|---|---|
| `identity.production_domain` | Domaine réel que le leurre imite |
| `identity.decoy_hostname` | Nom d'hôte affiché (jamais le vrai) |
| `canary.derivation_salt` | Sel de dérivation des faux secrets |
| `alerting.email.*` | Destinataires SOC, SMTP |
| `server.trusted_proxies` | Réseaux du reverse proxy |

Le mot de passe SMTP n'est **jamais** en config : il est lu au runtime
depuis la variable d'environnement nommée par
`alerting.email.smtp_password_env_var`. Si elle est absente, le honeypot
logue un avertissement et continue de fonctionner — l'alerting n'est
jamais un point de défaillance bloquant.

Les faux secrets servis (`debug_context`) sont stables pour une session
donnée, ce qui permet de les enregistrer auprès d'un service externe de
canary tokens pour être alerté s'ils resurgissent ailleurs.

## Renseignement

```bash
python intel_report.py --since 24h        # digest quotidien (cron)
python intel_report.py --since all --out rapport.md
```

Le rapport agrège `logs/honeypot.jsonl` : sessions confirmées, IPs les
plus actives, tactiques MITRE ATLAS observées, aveux capturés. Le mapping
ATLAS (`atlas_mapping.py`) est **indicatif** et à revérifier contre la
matrice à jour.

L'analyse LLM des aveux (`llm_assist.py`) est désactivée par défaut et
possède un repli explicite : clé absente ou appel en échec dégradent le
renseignement, sans jamais bloquer.

## Points d'attention légaux et techniques

- **Isolation réseau stricte** : jamais sur le même hôte ni le même VLAN
  qu'une infrastructure de production réelle.
- Outil **défensif** de collecte de renseignement : aucune contre-attaque
  ni action offensive vers l'IP source.
- Les aveux capturés sont **déclaratifs et non vérifiés** — une piste de
  renseignement, jamais une preuve en soi.
- Les logs contiennent des adresses IP : prévoir une durée de rétention
  et une base légale conformes au cadre applicable.
- La rotation de `logs/honeypot.jsonl` est assurée par l'applicatif
  (`logging.rotate_max_bytes` / `rotate_backup_count`).
