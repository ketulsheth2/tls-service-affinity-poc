"""Decode the capture artifacts to verify the real wire elements are present."""
import os
import sys

from tlslite.messages import ClientHello, NewSessionTicket
from tlslite.utils.codec import Parser

import wire

CAP = os.path.join(os.path.dirname(__file__), "..", "captures")


def _read(name):
    with open(os.path.join(CAP, name), "rb") as f:
        return f.read()


def decode_clienthello():
    data = _read("clienthello.bin")
    # strip 5-byte record header + 1-byte handshake type; parse() reads the
    # 3-byte length itself via startLengthCheck(3).
    body = data[6:]
    ch = ClientHello().parse(Parser(bytearray(body)))
    types = [hex(e.extType) for e in ch.extensions]
    print(f"ClientHello: {len(ch.extensions)} extensions {types}")
    print(f"  migration_support (0xFE4D) present: {0xFE4D in [e.extType for e in ch.extensions]}")


def decode_nst():
    data = _read("newsessionticket.bin")
    # strip the 1-byte handshake type; parse() reads the 3-byte length itself.
    nst = NewSessionTicket().parse(Parser(bytearray(data[1:])))
    types = [hex(e.extType) for e in nst.extensions]
    print(f"NewSessionTicket: lifetime={nst.ticket_lifetime} {len(nst.extensions)} extensions {types}")
    print(f"  migration_allowed (0xFE4E) present: {0xFE4E in [e.extType for e in nst.extensions]}")


def decode_migrate_request():
    data = _read("migrate_request.bin")
    target = wire.decode_migrate_request(data)
    print(f"migrate_request: hstype=0x{data[0]:02x} target={target!r}  raw={data.hex()}")


def main():
    if not os.path.isdir(CAP):
        print("run captures.py first", file=sys.stderr)
        sys.exit(1)
    decode_clienthello()
    decode_nst()
    decode_migrate_request()


if __name__ == "__main__":
    main()
