"""Skill d'agent : check_egress_to_service.

Question unique : pendant l'incident, les demandes de la passerelle (ex. GW-1)
vers le service (ex. AUTH-1) sortent-elles de la passerelle, et obtiennent-elles
une réponse ?

Le skill est déterministe (filtrer, compter, corréler) : il ne fait appel à aucun
LLM. L'agent décide quand l'appeler et interprète son résultat.

Format d'un paquet (données simulées) :
    {"t": "10:03:12", "src": "10.0.1.1", "dst": "10.0.9.9", "port": 3868,
     "kind": "request" | "reply" | "refusal" | "other"}
"""

from datetime import datetime


def _ts(hhmmss):
    """Convertit 'HH:MM:SS' en datetime (seule l'heure compte ici)."""
    return datetime.strptime(hhmmss, "%H:%M:%S")


def _insufficient(reason, needed):
    return {"verdict": "INSUFFICIENT_DATA", "reason": reason, "needed": needed}


def check_egress_to_service(packets, capture, window, source_ip, target_ip,
                            target_port, timeout_events, tolerance_s=2):
    cap_start, cap_end = _ts(capture[0]), _ts(capture[1])
    win_start, win_end = _ts(window[0]), _ts(window[1])
    in_window = [p for p in packets if win_start <= _ts(p["t"]) <= win_end]

    # 1. Contrôler la qualité des données AVANT toute conclusion
    if cap_start > win_start or cap_end < win_end:
        return _insufficient("La capture ne couvre pas toute la fenêtre de l'incident",
                             f"Une capture couvrant {window[0]}-{window[1]}")
    if not any(p["src"] == source_ip for p in in_window):
        return _insufficient(
            "Aucun trafic de la passerelle dans la capture : impossible de distinguer "
            "'rien n'est envoyé' d'une capture défaillante",
            "Une capture sur l'interface de sortie de la passerelle")
    if not timeout_events:
        return _insufficient("Aucun timeout à corréler dans la fenêtre",
                             "Les horodatages des timeouts de la passerelle")

    # 2. Filtrer le trafic passerelle <-> service
    outgoing = [p for p in in_window if p["src"] == source_ip and p["dst"] == target_ip
                and p["port"] == target_port and p["kind"] == "request"]
    replies = [p for p in in_window if p["src"] == target_ip and p["dst"] == source_ip]
    refusals = [p for p in replies if p["kind"] == "refusal"]

    # 3. Corréler chaque timeout avec un envoi réel (à ± tolérance près)
    matched = [t for t in timeout_events
               if any(abs((_ts(p["t"]) - _ts(t)).total_seconds()) <= tolerance_s
                      for p in outgoing)]

    # 4. Classer
    if not outgoing:
        verdict, supports, weakens = ("NO_REQUESTS_LEAVE", "problème interne à la passerelle",
                                      "problème après la passerelle")
    elif refusals:
        verdict, supports, weakens = ("REJECTED", "rejet actif (filtrage, certificat)",
                                      "perte silencieuse sur le chemin")
    elif not replies:
        verdict, supports, weakens = ("NO_RESPONSE", "problème après la passerelle",
                                      "problème interne à la passerelle")
    else:
        verdict, supports, weakens = ("INCONCLUSIVE", "aucune (réponses normales observées)",
                                      "aucune")

    return {
        "verdict": verdict,
        "evidence": {
            "outgoing": len(outgoing),
            "replies": len(replies),
            "refusals": len(refusals),
            "timeouts_matched": f"{len(matched)}/{len(timeout_events)}",
            "first_outgoing": outgoing[0]["t"] if outgoing else None,
        },
        "supports": supports,
        "weakens": weakens,
        "limitations": "Ne localise pas où, après la passerelle, les paquets sont perdus.",
    }
