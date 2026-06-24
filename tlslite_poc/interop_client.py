"""tlslite-ng client for cross-stack interop.

Used in direction 2: connects to a picotls server (./cli -M -c cert -k key) and
emits the migration_support extension; the picotls server's on_extension hook
logs that it observed 0xFE4D, proving Python's extension is understood by C.
"""
import socket
import sys

from tlslite import TLSConnection, HandshakeSettings

import common
import wire


def main():
    common.ensure_cert()
    wire.install()
    wire.set_inject(True)
    host = "127.0.0.1"
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7600
    s = HandshakeSettings()
    s.minVersion = s.maxVersion = (3, 4)
    raw = socket.create_connection((host, port))
    tee = wire.TeeSocket(raw)
    conn = TLSConnection(tee)
    conn.handshakeClientCert(settings=s, serverName=common.SERVICE_NAME)
    on_wire = b"\xfe\x4d" in bytes(tee.sent)
    print(f"[tlslite-client] handshake OK with peer; tls={conn.version}", flush=True)
    print(f"[tlslite-client] migration_support(0xFE4D) emitted on the wire = {on_wire}", flush=True)
    # Read picotls' post-handshake messages: NewSessionTicket(s) (carrying
    # migration_allowed) and the migrate_request message.
    target = wire.recv_migrate_request(conn, timeout=2.0)
    allowed = wire.ticket_has_migration_allowed(conn)
    print(f"[tlslite-client] migration_allowed(0xFE4E) observed in picotls NST = {allowed}", flush=True)
    print(f"[tlslite-client] migrate_request received from picotls: target={target!r}", flush=True)
    conn.close()


if __name__ == "__main__":
    main()
