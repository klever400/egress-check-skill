# egress-check-skill

Implémentation minimale d'un **skill d'agent** pour le troubleshooting réseau.

**Question à laquelle il répond :** pendant un incident, les demandes d'une passerelle (ex. GW-1) vers un service (ex. AUTH-1) **sortent-elles de la passerelle**, et obtiennent-elles une réponse ?

## Principe

Le skill est **déterministe** : il filtre, compte et corrèle des paquets, sans appel à un LLM. L'agent décide quand l'appeler et interprète le résultat. Cela le rend reproductible et testable.

1. **Contrôle de la qualité des données** : la capture couvre-t-elle la fenêtre ? Contient-elle du trafic de la passerelle ? Y a-t-il des timeouts à corréler ? Sinon → `INSUFFICIENT_DATA`, avec la raison et les données nécessaires.
2. **Filtrage** du trafic passerelle ⇄ service.
3. **Corrélation** de chaque timeout avec un envoi réel (± 2 s).
4. **Verdict** : `NO_REQUESTS_LEAVE`, `NO_RESPONSE`, `REJECTED` ou `INCONCLUSIVE`, avec les preuves et l'hypothèse renforcée / affaiblie.

Point clé : ne voir aucune demande vers le service n'est une preuve que si l'on voit par ailleurs du trafic de la passerelle. Sinon, c'est une absence de données, pas une absence d'envoi.

## Lancer les tests

```bash
pip install pytest
pytest -v
```

| Test | Situation | Verdict attendu |
|---|---|---|
| Cas probant | 40 demandes sortent de GW-1, aucune réponse d'AUTH-1 | `NO_RESPONSE` |
| Données insuffisantes | Capture sans aucun trafic de GW-1 (mauvaise interface) | `INSUFFICIENT_DATA` |
| Bonus | Trafic de GW-1 présent, mais aucune demande vers AUTH-1 | `NO_REQUESTS_LEAVE` |

## Limites

- **Données simulées** : les paquets sont décrits à la main (heure, source, destination, port, type). Une version réelle lirait une capture PCAP (par exemple avec `tshark` ou `scapy`) avant d'appliquer la même logique.
- Le skill ne localise pas **où**, après la passerelle, les paquets sont perdus.