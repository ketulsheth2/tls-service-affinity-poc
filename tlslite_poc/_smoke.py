"""Smoke test: does tlslite-ng do real cross-instance TLS 1.3 ticket resumption?

Starts two in-domain instances (A, B) that share a ticket key, and one foreign
instance (F) with a different key. A client handshakes A, then resumes on B
(expected resumed=True) and tries F (expected resumed=False -> fail-closed).
"""
import socket
import threading
import time

from tlslite import TLSConnection, HandshakeSettings

import common


def server_settings(ticket_key):
    s = HandshakeSettings()
    s.minVersion = (3, 4)
    s.maxVersion = (3, 4)
    s.ticketKeys = [ticket_key]
    s.ticket_count = 2
    return s


def client_settings():
    s = HandshakeSettings()
    s.minVersion = (3, 4)
    s.maxVersion = (3, 4)
    return s


def run_instance(name, port, ticket_key, ready):
    chain, key = common.load_cert_key()
    settings = server_settings(ticket_key)
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", port))
    lsock.listen(5)
    ready.set()
    while True:
        csock, _ = lsock.accept()
        try:
            conn = TLSConnection(csock)
            conn.handshakeServer(certChain=chain, privateKey=key, settings=settings)
            conn.send(b"hello-from-" + name.encode())
            try:
                conn.read(max=64)
            except Exception:
                pass
            conn.close()
        except Exception as e:
            print(f"[{name}] server error: {e}")


def connect(port, session=None):
    s = socket.create_connection(("127.0.0.1", port))
    conn = TLSConnection(s)
    conn.handshakeClientCert(settings=client_settings(), session=session,
                             serverName=common.SERVICE_NAME)
    # Read once so the post-handshake NewSessionTicket is processed and stored
    # in conn.session.tickets.
    data = conn.read(max=64)
    return conn, data


def main():
    common.ensure_cert()
    ports = {"A": 7101, "B": 7102, "F": 7201}
    for name, port in ports.items():
        key = common.FOREIGN_TICKET_KEY if name == "F" else common.SHARED_TICKET_KEY
        ev = threading.Event()
        threading.Thread(target=run_instance, args=(name, port, key, ev), daemon=True).start()
        ev.wait()
    time.sleep(0.3)

    # Phase 1: full handshake with A
    connA, dataA = connect(ports["A"])
    print(f"A: resumed={connA.resumed} got={bytes(dataA)!r} tickets={len(connA.session.tickets or [])}")
    session = connA.session
    connA.close()

    # Phase 3a: resume on B (shared key) -> expect resumed=True
    connB, dataB = connect(ports["B"], session=session)
    print(f"B: resumed={connB.resumed} got={bytes(dataB)!r}  <-- expect resumed=True")
    connB.close()

    # Phase 3b: try foreign F (different key) -> expect resumed=False
    connF, dataF = connect(ports["F"], session=session)
    print(f"F: resumed={connF.resumed} got={bytes(dataF)!r}  <-- expect resumed=False (fail-closed)")
    connF.close()

    ok = connB.resumed and not connF.resumed
    print("SMOKE:", "PASS" if ok else "FAIL")


if __name__ == "__main__":
    main()
