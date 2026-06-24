"""Produce verifiable byte-level capture artifacts under ../captures/.

  clienthello.bin      a real ClientHello containing migration_support (0xFE4D)
  newsessionticket.bin a real NewSessionTicket containing migration_allowed (0xFE4E)
  migrate_request.bin  the migrate_request post-handshake message wire format

These are real TLS wire bytes (the first two captured from a live handshake),
decodable with decode.py or any TLS dissector.
"""
import os
import socket
import threading
import time

from tlslite import TLSConnection, HandshakeSettings

import common
import wire

OUT = os.path.join(os.path.dirname(__file__), "..", "captures")


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
    wire.set_allow(True)  # issuer marks tickets migration_allowed
    conn.handshakeServer(certChain=chain, privateKey=key, settings=s)
    try:
        conn.send(b"ok")
        conn.read(max=16)
    except Exception:
        pass
    conn.close()


def main():
    os.makedirs(OUT, exist_ok=True)
    common.ensure_cert()
    wire.install()
    wire.set_inject(True)

    ready = threading.Event()
    port = 7700
    threading.Thread(target=server, args=(port, ready), daemon=True).start()
    ready.wait()
    time.sleep(0.2)

    raw = socket.create_connection(("127.0.0.1", port))
    tee = wire.TeeSocket(raw)
    conn = TLSConnection(tee)
    conn.handshakeClientCert(settings=_client_settings(), serverName=common.SERVICE_NAME)
    conn.read(max=16)  # process post-handshake NewSessionTicket(s)

    # 1) ClientHello: first client->server TLS record (handshake, plaintext).
    sent = bytes(tee.sent)
    ch = _first_handshake_record(sent)
    _write("clienthello.bin", ch, OUT)

    # 2) NewSessionTicket: re-serialize the parsed ticket (plaintext incl. ext).
    nst = conn.tickets[-1].write() if conn.tickets else b""
    _write("newsessionticket.bin", bytes(nst), OUT)

    # 3) migrate_request wire format.
    _write("migrate_request.bin", wire.encode_migrate_request(b"tok-B"), OUT)
    conn.close()

    print("wrote artifacts to", os.path.normpath(OUT))


def _client_settings():
    s = HandshakeSettings()
    s.minVersion = s.maxVersion = (3, 4)
    return s


def _first_handshake_record(data):
    # TLS record: type(1)=0x16 handshake, version(2), length(2), fragment.
    if data and data[0] == 0x16:
        ln = int.from_bytes(data[3:5], "big")
        return data[: 5 + ln]
    return data


def _write(name, blob, out):
    with open(os.path.join(out, name), "wb") as f:
        f.write(blob)
    has4d = "fe4d" in blob.hex()
    has4e = "fe4e" in blob.hex()
    print(f"  {name}: {len(blob)} bytes  0xFE4D={has4d} 0xFE4E={has4e}")


if __name__ == "__main__":
    main()
