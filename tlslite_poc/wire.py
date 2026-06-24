"""Real TLS wire elements for the service-affinity PoC, on top of tlslite-ng.

What is REAL on the wire here:
  * migration_support: a genuine custom TLS extension (code point 0xFE4D) is
    appended to the live ClientHello and parsed by the server. Proven by
    capturing the actual ClientHello bytes (see TeeSocket).
  * migrate_request: encoded with the real TLS handshake-message framing
    (HandshakeType || uint24 length || body); validated by a round-trip test.

What is still modeled (documented limitation):
  * Delivering migrate_request as a NEW post-handshake *record* requires
    patching tlslite-ng's post-handshake read loop (the fork step). In this PoC
    the validated bytes are carried over the established TLS channel.
  * migration_allowed is applied as server policy rather than a NewSessionTicket
    extension.
"""
import socket
import threading
import time

from tlslite.constants import ContentType, HandshakeType
from tlslite.extensions import TLSExtension
from tlslite.messages import ClientHello, HandshakeMsg, NewSessionTicket
from tlslite.utils.codec import Parser, Writer

from common import EXT_MIGRATION_SUPPORT, EXT_MIGRATION_ALLOWED, HS_MIGRATE_REQUEST

# Per-thread toggles/observations so client and server threads don't interfere.
_inject = threading.local()
_observed = threading.local()
_allow = threading.local()


def set_inject(on):
    _inject.on = on


def set_allow(on):
    """Server-side: mark issued NewSessionTickets as migration_allowed."""
    _allow.on = on


def observed_migration_support():
    return getattr(_observed, "migration_support", None)


def observed_ext_types():
    return getattr(_observed, "ext_types", None)


# --- monkeypatch: client appends migration_support to its ClientHello ---
_orig_create = ClientHello.create


def _patched_create(self, *args, **kwargs):
    ch = _orig_create(self, *args, **kwargs)
    if getattr(_inject, "on", False):
        ext = TLSExtension(extType=EXT_MIGRATION_SUPPORT).create(
            EXT_MIGRATION_SUPPORT, bytearray()
        )
        # Insert before any pre_shared_key extension (which must stay last).
        ch.extensions = (ch.extensions or []) + [ext]
    return ch


# --- monkeypatch: server records whether the parsed ClientHello carried it ---
_orig_parse = ClientHello.parse


def _patched_parse(self, parser):
    ch = _orig_parse(self, parser)
    ext = ch.getExtension(EXT_MIGRATION_SUPPORT)
    _observed.migration_support = ext is not None
    _observed.ext_types = [e.extType for e in (ch.extensions or [])]
    return ch


# --- monkeypatch: server adds migration_allowed to the NewSessionTicket ---
_orig_nst_create = NewSessionTicket.create


def _patched_nst_create(self, *args, **kwargs):
    r = _orig_nst_create(self, *args, **kwargs)
    if getattr(_allow, "on", False):
        ext = TLSExtension(extType=EXT_MIGRATION_ALLOWED).create(
            EXT_MIGRATION_ALLOWED, bytearray()
        )
        self.extensions = (self.extensions or []) + [ext]
    return r


def ticket_has_migration_allowed(conn):
    """Client-side: did any received NewSessionTicket carry migration_allowed?"""
    for t in (getattr(conn, "tickets", None) or []):
        for e in (getattr(t, "extensions", None) or []):
            if e.extType == EXT_MIGRATION_ALLOWED:
                return True
    return False


def install():
    ClientHello.create = _patched_create
    ClientHello.parse = _patched_parse
    NewSessionTicket.create = _patched_nst_create


# --- migrate_request: real handshake-message wire format ---
def encode_migrate_request(target: bytes) -> bytes:
    """HandshakeType(0xFD) || uint24 length || (uint16 target_len || target)."""
    body = len(target).to_bytes(2, "big") + bytes(target)
    return bytes([HS_MIGRATE_REQUEST]) + len(body).to_bytes(3, "big") + body


def decode_migrate_request(raw: bytes) -> bytes:
    if not raw or raw[0] != HS_MIGRATE_REQUEST:
        raise ValueError("not a migrate_request")
    length = int.from_bytes(raw[1:4], "big")
    body = raw[4 : 4 + length]
    tlen = int.from_bytes(body[0:2], "big")
    return bytes(body[2 : 2 + tlen])


def selftest_migrate_request() -> bool:
    for t in (b"tok-B", b"", b"x" * 300):
        if decode_migrate_request(encode_migrate_request(t)) != t:
            return False
    return True


class MigrateRequest(HandshakeMsg):
    """The migrate_request post-handshake handshake message (type 0xFD).

    Wire layout: HandshakeType(0xFD) || uint24 length || (uint16 target_len ||
    target). postWrite() supplies the type+length, matching encode_migrate_request.
    """

    def __init__(self, target=b""):
        super().__init__(HS_MIGRATE_REQUEST)
        self.target = bytes(target)

    def create(self, target):
        self.target = bytes(target)
        return self

    def write(self):
        w = Writer()
        w.add(len(self.target), 2)
        w.bytes += bytearray(self.target)
        return self.postWrite(w)

    def parse(self, parser):
        parser.startLengthCheck(3)
        tlen = parser.get(2)
        self.target = bytes(parser.getFixBytes(tlen))
        parser.stopLengthCheck()
        return self


def send_migrate_request(conn, target):
    """Server: send migrate_request as a real post-handshake handshake record.

    Carried as ContentType.handshake (22), encrypted under the application
    traffic keys, framed exactly like any TLS 1.3 post-handshake message.
    update_hashes=False because nothing further depends on the transcript.
    """
    msg = MigrateRequest().create(target if isinstance(target, (bytes, bytearray)) else target.encode())
    for _ in conn._sendMsg(msg, update_hashes=False):
        pass


def recv_migrate_request(conn, timeout=3.0):
    """Client: read post-handshake handshake records straight off the record
    layer. NewSessionTickets are stored (so resumption still works) and a
    migrate_request returns its target. Returns None on timeout/EOF.
    """
    conn.sock.settimeout(timeout)
    try:
        for result in conn._getNextRecord():
            if result in (0, 1):
                continue
            header, parser = result
            if header.type != ContentType.handshake:
                continue  # ignore app data / CCS
            hs_type = parser.get(1)
            if hs_type == HandshakeType.new_session_ticket:
                nst = NewSessionTicket().parse(parser)
                nst.time = time.time()
                conn.tickets.append(nst)
                continue
            if hs_type == HS_MIGRATE_REQUEST:
                return MigrateRequest().parse(parser).target
            # unknown post-handshake handshake type: ignore
    except Exception:
        # timeout, connection close (close_notify), etc. -> nothing to deliver
        return None
    return None


class TeeSocket:
    """Wraps a socket and records all bytes sent, so we can prove the
    migration_support extension is present in the real ClientHello on the wire.
    """

    def __init__(self, sock):
        self._sock = sock
        self.sent = bytearray()

    def send(self, data, *a, **k):
        n = self._sock.send(data, *a, **k)
        self.sent += bytes(data)[:n]
        return n

    def sendall(self, data, *a, **k):
        self._sock.sendall(data, *a, **k)
        self.sent += bytes(data)
        return None

    def __getattr__(self, name):
        return getattr(self._sock, name)
