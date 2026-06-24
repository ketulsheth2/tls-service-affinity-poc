"""tlslite-ng server for cross-stack interop.

Used in direction 1: a picotls client (./cli -M) connects and emits the
migration_support extension; this server parses it and logs the extension-type
list, proving an independent C stack's extension is understood by Python.
"""
import socket
import sys
import time

from tlslite import TLSConnection, HandshakeSettings

import common
import wire


def main():
    common.ensure_cert()
    wire.install()
    wire.set_allow(True)  # issue NewSessionTickets carrying migration_allowed (0xFE4E)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7500
    chain, key = common.load_cert_key()
    s = HandshakeSettings()
    s.minVersion = s.maxVersion = (3, 4)
    s.ticketKeys = [common.SHARED_TICKET_KEY]
    s.ticket_count = 2
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(5)
    print(f"[tlslite-server] listening on 127.0.0.1:{port}", flush=True)
    while True:
        c, _ = ls.accept()
        try:
            conn = TLSConnection(c)
            conn.handshakeServer(certChain=chain, privateKey=key, settings=s)
            exts = [hex(t) for t in (wire.observed_ext_types() or [])]
            seen = "0xfe4d" in exts
            print(f"[tlslite-server] handshake OK; parsed CH ext types={exts}", flush=True)
            print(f"[tlslite-server] migration_support(0xFE4D) from peer = {seen}", flush=True)
            try:
                # Send a real migrate_request post-handshake message so a picotls
                # client can receive/parse it (cross-stack, Py -> C).
                wire.send_migrate_request(conn, b"tok-B")
                print("[tlslite-server] sent migrate_request (post-handshake msg, type 0xFD) target=tok-B", flush=True)
                time.sleep(0.3)
            except Exception:
                pass
            conn.close()
        except Exception as e:
            # A bare TCP liveness probe (no TLS) shows up as an abrupt close;
            # ignore it so the interop output stays clean.
            if "AbruptClose" not in type(e).__name__:
                print(f"[tlslite-server] err: {e}", flush=True)


if __name__ == "__main__":
    main()
