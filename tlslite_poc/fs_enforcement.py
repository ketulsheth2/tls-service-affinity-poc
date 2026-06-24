"""Prove the server enforces forward secrecy (psk_dhe_ke) on relocation.

The draft requires psk_dhe_ke and forbids psk_ke (PSK-only, no (EC)DHE), so a
compromised ticket key cannot expose post-relocation data. Here the server sets
psk_modes=["psk_dhe_ke"]; a client offering only psk_ke is refused resumption
(falls back to a full handshake), while a psk_dhe_ke client resumes.
"""
import socket
import threading
import time

from tlslite import TLSConnection, HandshakeSettings

import common


def _serve_conn(c, chain, key, s):
    try:
        conn = TLSConnection(c)
        conn.handshakeServer(certChain=chain, privateKey=key, settings=s)
        conn.send(b"ok")
        conn.close()
    except Exception:
        pass


def server(port, ready):
    chain, key = common.load_cert_key()
    s = HandshakeSettings()
    s.minVersion = s.maxVersion = (3, 4)
    s.ticketKeys = [common.SHARED_TICKET_KEY]
    s.ticket_count = 2
    s.psk_modes = ["psk_dhe_ke"]  # enforce forward secrecy
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(5)
    ready.set()
    while True:
        c, _ = ls.accept()
        # per-connection thread so a blocking peer can't stall accept()
        threading.Thread(target=_serve_conn, args=(c, chain, key, s), daemon=True).start()


def client(port, psk_modes, session=None):
    s = HandshakeSettings()
    s.minVersion = s.maxVersion = (3, 4)
    s.psk_modes = psk_modes
    raw = socket.create_connection(("127.0.0.1", port))
    raw.settimeout(5.0)
    conn = TLSConnection(raw)
    try:
        conn.handshakeClientCert(settings=s, session=session, serverName=common.SERVICE_NAME)
        conn.read(max=16)
    except Exception:
        return conn, False
    return conn, conn.resumed


def main():
    common.ensure_cert()
    ready = threading.Event()
    port = 7900
    threading.Thread(target=server, args=(port, ready), daemon=True).start()
    ready.wait()
    time.sleep(0.2)

    c1, _ = client(port, ["psk_dhe_ke", "psk_ke"])
    session = c1.session
    c1.close()

    _, resumed_dhe = client(port, ["psk_dhe_ke"], session=session)
    print(f"resume psk_dhe_ke : resumed={resumed_dhe}   <-- expect True (forward secrecy)", flush=True)

    _, resumed_pskke = client(port, ["psk_ke"], session=session)
    print(f"resume psk_ke-only: resumed={resumed_pskke}   <-- expect False (FS-less resumption refused)", flush=True)

    ok = resumed_dhe and not resumed_pskke
    print("FS-ENFORCEMENT:", "PASS" if ok else "FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
