"""Prove migrate_request is wired as a REAL post-handshake TLS message.

The server, after the handshake completes, sends migrate_request as a
ContentType.handshake record (type 0xFD), encrypted under the application
traffic keys. The client reads it straight off the record layer, processes any
NewSessionTickets first (so resumption still works), and parses the target.

This is no longer carried over the application stream.
"""
import socket
import threading
import time

from tlslite import TLSConnection, HandshakeSettings

import common
import wire


def server(port, ready):
    chain, key = common.load_cert_key()
    s = HandshakeSettings()
    s.minVersion = s.maxVersion = (3, 4)
    s.ticketKeys = [common.SHARED_TICKET_KEY]
    s.ticket_count = 2
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(1)
    ready.set()
    c, _ = ls.accept()
    conn = TLSConnection(c)
    conn.handshakeServer(certChain=chain, privateKey=key, settings=s)
    # Real post-handshake handshake message, NOT application data.
    wire.send_migrate_request(conn, b"tok-B")
    print("[server] sent migrate_request as ContentType.handshake (type 0xFD)", flush=True)
    time.sleep(0.3)
    conn.close()


def main():
    common.ensure_cert()
    wire.install()

    ready = threading.Event()
    port = 7800
    threading.Thread(target=server, args=(port, ready), daemon=True).start()
    ready.wait()
    time.sleep(0.2)

    raw = socket.create_connection(("127.0.0.1", port))
    conn = TLSConnection(raw)
    conn.handshakeClientCert(settings=_client_settings(), serverName=common.SERVICE_NAME)
    print(f"[client] handshake OK (tls={conn.version})", flush=True)

    target = wire.recv_migrate_request(conn)
    tickets = len(conn.tickets or [])
    print(f"[client] received migrate_request from the wire: target={target!r}", flush=True)
    print(f"[client] NewSessionTickets captured alongside it: {tickets} (resumption preserved)", flush=True)

    ok = (target == b"tok-B") and tickets >= 1
    print("RESULT:", "PASS" if ok else "FAIL", flush=True)
    conn.close()
    raise SystemExit(0 if ok else 1)


def _client_settings():
    s = HandshakeSettings()
    s.minVersion = s.maxVersion = (3, 4)
    return s


if __name__ == "__main__":
    main()
