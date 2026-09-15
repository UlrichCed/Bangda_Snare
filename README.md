# Honeypot HTTP/API anti-attaques-IA

Honeypot applicatif qui distingue un **agent IA** d'un simple scanner, le
déroute (tarpit, labyrinthe, injections), pousse les sessions les plus
suspectes à se déclarer, et produit du renseignement exploitable plutôt
que du bruit brut.

## Principe de détection

Chaque signal vaut son poids **une seule fois par session** : le score
mesure des propriétés prouvées, pas un volume de requêtes. Les signaux
sont séparés en deux familles, et c'est cette séparation qui porte toute
la valeur de l'outil.

**Signaux comportementaux** — reproductibles par un outillage non-IA (UA,
headers manquants, cadence, énumération, robots.txt, signature de
latence). Ils ne concluent jamais : quelle que soit leur accumulation, le
mode aveu reste fermé.

**Signaux discriminants** — ils exigent que le client ait *traité* le
contenu servi ou se comporte en agent outillé. Hors de portée d'un script
d'énumération :

| Signal | Ce qu'il prouve | Poids |
|---|---|---|
| `coherent_maze_traversal` | a analysé la structure de la réponse pour en suivre un lien | 40 |
| `llm_artifacts_in_request` | laisse fuiter son échafaudage (clés ReAct, markdown, langue naturelle) | 45 |
| `bait_token_followed` | rejoue un token servi dans une réponse précédente | 50 |
| `hallucinated_parameters` | invente des champs jamais annoncés dans le schéma | 55 |
| `prompt_injection_obeyed` | obéit à une instruction injectée dans le contenu | 60 |
| `semantic_canary_solved` | a compris le contenu au point d'en dériver une valeur | 70 |
| `tool_schema_invoked` | découvre un outil dans une réponse et l'invoque | 75 |

Mesuré en conditions réelles :

| Profil | Score | Confirmé agent ? |
|---|---|---|
| Navigateur réel | ~0 | non |
| Scanner, **3000 chemins énumérés** | **75** | **non** |
| Agent qui traite le contenu | 400+ | oui |

Le mode `confess` exige au moins un signal discriminant
(`detection.confess_requires_discriminating_signal`). C'est l'invariant
central, couvert par un test dédié : aucune accumulation de bruit ne peut
y mener.

## Arsenal — quelles faiblesses des agents sont exploitées

Tout se joue **dans nos propres réponses**. Aucun piège ne demande au
client d'exécuter quoi que ce soit sur sa machine ni d'agir vers un
tiers : les chemins suggérés pointent tous vers le honeypot. C'est une
contrainte de conception, vérifiée par un test.

**Faux schéma d'outil** (`ai_traps.py`) — les réponses embarquent une
définition d'outil au format qu'un agent outillé (MCP, function calling,
plugin OpenAPI) auto-découvre. Un humain ne la voit pas, un scanner
l'ignore : l'invocation est donc un signal quasi sans faux positif. Les
arguments envoyés renseignent directement sur l'intention, et tout
paramètre absent du schéma annoncé est une invention du modèle.

**Canaris sémantiques** (`semantic_canary.py`) — cinq familles de calcul
tirées au hasard (XOR, somme, inversion de chiffres, base64, sélection +
arithmétique). Deux faits anodins sont déposés, jamais d'instruction : on
mesure la compréhension, pas l'obéissance. Un agent entraîné à refuser
les injections explicites esquive `prompt_injection_obeyed` mais se
trahit ici s'il exploite l'information lue. Deux gardes protègent le
signal : le résultat n'apparaît jamais dans le texte rendu, et reste
hors de la plage qu'une énumération atteint.

**Échelle d'injections** — quatre paliers d'explicitation croissante, sur
quatre chemins distincts : donnée inerte, commentaire de debug,
instruction système, ton d'autorité. Le palier auquel un agent cède
*mesure la solidité de ses garde-fous*, et cette lecture figure au
rapport.

**Piège robots.txt** — les deux comportements opposés sont informatifs :
aller droit au chemin interdit trahit un scanner qui s'en sert comme
d'une carte ; le respecter en continuant ailleurs trahit un agent
entraîné aux conventions. L'alignement devient un signal.

**Empreinte comportementale** (`behavioral.py`) — clés d'échafaudage
ReAct dans les corps JSON, markdown et langue naturelle dans les
paramètres, formules d'assistant, et cadence dominée par le temps
d'inférence (ni les millisecondes d'un script, ni l'irrégularité d'un
humain).

**Escalade de containment** (`containment.py`) — cinq paliers, de
`observe` à `quarantine`. Aux paliers élevés, les réponses embarquent de
l'attrition de contexte : du remplissage plausible qui consomme la
fenêtre de contexte et le budget de tokens de l'agent. C'est une mesure
d'usure **strictement bornée** (`max_filler_bytes`, plafond dur interne
de 256 Kio) — délibérément pas une bombe de décompression ni une
tentative d'endommager le client.

## Démarrage rapide (local)

```bash
pip install -r requirements.txt
python app.py            # serveur de dev, jamais en production
curl -A "python-requests/2.31.0" http://127.0.0.1:8080/api/v1/resources/1
```

## Tester le honeypot

### Suite automatisée

```bash
pip install -r requirements-dev.txt
pytest
```

100 tests, ~1,5 s. Ils couvrent notamment l'invariant central (aucune
accumulation de signaux comportementaux ne peut confirmer un agent) et
une régression par correctif passé.

### Simuler un client contre une instance qui tourne

Lancez le honeypot dans un terminal, puis jouez les trois profils. Ils
correspondent aux trois verdicts que l'outil doit savoir rendre :

```bash
python app.py                                    # terminal 1

python simulate_agent.py --profile browser       # terminal 2
python simulate_agent.py --profile scanner --requests 25
python simulate_agent.py --profile agent --show-log
```

Le script n'utilise que la bibliothèque standard. Résultat attendu :

| Profil | Score | Mode | Ce qui se passe |
|---|---|---|---|
| `browser` | 0 | `normal` | headers complets, ressources statiques : le leurre est servi tel quel |
| `scanner` | **75** | `deflect` | dérouté vers la 4ᵉ requête, puis **plafonne** — jamais d'aveu |
| `agent` | ~390 | `confess` | résout le canari, suit le labyrinthe, invoque le faux outil |

Le profil `agent` est le seul difficile à rejouer à la main : il lit la
réponse, en extrait deux faits anodins et calcule la valeur qui en
découle pour construire sa requête suivante — exactement ce que le
honeypot cherche à détecter. `--show-log` affiche ensuite ce que le
serveur a réellement retenu pour chaque session.

Le contraste entre les lignes `scanner` et `agent` est le test qui
compte : c'est lui qui montre que l'outil distingue un agent IA d'un
simple script, et pas seulement « un navigateur d'un non-navigateur ».

### À la main

```bash
# Visiteur normal : reste en mode normal
curl -A "Mozilla/5.0 (Macintosh) Chrome/120" \
     -H "Accept-Language: fr-FR" -H "Accept-Encoding: gzip" \
     http://127.0.0.1:8080/

# Quelques requêtes en UA de lib HTTP suffisent à déclencher le déroutage
for i in $(seq 1 6); do
  curl -s -b /tmp/c -c /tmp/c -A "python-requests/2.31.0" \
       http://127.0.0.1:8080/api/v1/resources/$i | head -c 200; echo
done
```

Les réponses de déroutage arrivent ralenties (tarpit) et contiennent le
labyrinthe, l'échelle d'injections, le canari et le faux schéma d'outil.

### Inspecter ce qui a été observé

```bash
tail -f logs/honeypot.jsonl | python -m json.tool --json-lines
python intel_report.py --since all
python intel_report.py --since all --ioc-out iocs.json
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
| `ai_traps.tool_exec_path` | Chemin du faux outil (changer le rend moins reconnaissable) |
| `ai_traps.robots_disallow_path` | Chemin interdit servant de piège robots.txt |
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
python intel_report.py --since 7d --ioc-out iocs.json
```

Le rapport agrège `logs/honeypot.jsonl` et sépare les **agents confirmés**
(au moins un signal discriminant) des sessions simplement suspectes — la
distinction qui évite de diffuser du bruit au SOC. Il détaille aussi les
invocations du faux outil et leurs arguments, les IPs les plus actives,
les tactiques MITRE ATLAS observées et les aveux capturés.

`--ioc-out` exporte les indicateurs au format JSON, **restreints aux
agents prouvés** : diffuser des IPs simplement suspectes produirait des
blocages à tort chez ceux qui consomment le flux.

Le mapping ATLAS (`atlas_mapping.py`) est **indicatif** et à revérifier
contre la matrice à jour.

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
