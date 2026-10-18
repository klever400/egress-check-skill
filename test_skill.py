"""Cas de test du skill check_egress_to_service (données simulées)."""

from skill import check_egress_to_service

GW1, AUTH1, OTHER, PORT = "10.0.1.1", "10.0.9.9", "10.0.5.5", 3868
CAPTURE = ("10:00:00", "10:20:00")
WINDOW = ("10:03:00", "10:15:00")


def request(t):
    return {"t": t, "src": GW1, "dst": AUTH1, "port": PORT, "kind": "request"}


def other_traffic(t):
    # Trafic de GW-1 vers un autre équipement : prouve que la capture fonctionne
    return {"t": t, "src": GW1, "dst": OTHER, "port": 443, "kind": "other"}


def test_cas_probant_les_demandes_sortent_sans_reponse():
    """Cas 1 : GW-1 envoie ses demandes, AUTH-1 ne répond jamais."""
    times = [f"10:{m:02d}:{s:02d}" for m in range(3, 13) for s in (5, 20, 35, 50)]  # 40 envois
    packets = [request(t) for t in times] + [other_traffic("10:04:00")]
    timeouts = times[:38] + ["10:14:58", "10:14:59"]  # 38 corrélés, 2 sans envoi proche

    result = check_egress_to_service(packets, CAPTURE, WINDOW, GW1, AUTH1, PORT, timeouts)

    assert result["verdict"] == "NO_RESPONSE"
    assert result["evidence"]["outgoing"] == 40
    assert result["evidence"]["replies"] == 0
    assert result["evidence"]["timeouts_matched"] == "38/40"
    assert result["supports"] == "problème après la passerelle"


def test_cas_donnees_insuffisantes_capture_sans_trafic_gw1():
    """Cas 2 : capture prise sur la mauvaise interface, aucun paquet de GW-1."""
    packets = [{"t": "10:05:00", "src": OTHER, "dst": AUTH1, "port": PORT, "kind": "request"}]
    timeouts = ["10:03:05", "10:03:20"]

    result = check_egress_to_service(packets, CAPTURE, WINDOW, GW1, AUTH1, PORT, timeouts)

    # Il ne doit PAS conclure NO_REQUESTS_LEAVE : absence de données != absence d'envoi
    assert result["verdict"] == "INSUFFICIENT_DATA"
    assert "Aucun trafic de la passerelle" in result["reason"]


def test_bonus_trafic_gw1_present_mais_rien_vers_auth1():
    """Cas bonus : la capture fonctionne, mais aucune demande ne part vers AUTH-1."""
    packets = [other_traffic("10:04:00"), other_traffic("10:08:00")]
    timeouts = ["10:03:05", "10:03:20"]

    result = check_egress_to_service(packets, CAPTURE, WINDOW, GW1, AUTH1, PORT, timeouts)

    assert result["verdict"] == "NO_REQUESTS_LEAVE"
    assert result["supports"] == "problème interne à la passerelle"
