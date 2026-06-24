"""End-to-end service-affinity PoC on tlslite-ng (real TLS 1.3).

Scenarios: success | foreign | unaware | outofscope

Demonstrates, with real TLS on an independent stack:
  * migration_support as a genuine TLS extension on the wire (captured bytes),
  * cross-instance ticket resumption via a shared ticket key (conn.resumed),
  * fail-closed when redirected to a foreign instance (no shared key),
  * scope enforcement, and application-level idempotency on relocation,
  * migrate_request delivered as a real post-handshake message (type 0xFD).
"""
import json
import socket
import sys
import threading
import time

from tlslite import TLSConnection, HandshakeSettings

import common
import wire

_ledger = {}
_ledger_lock = threading.Lock()
LAST_CH_HEX = None  # evidence: hex slice of a real ClientHello around 0xFE4D


def apply_payment(idem):
    with _ledger_lock:
        if idem in _ledger:
            return "deduped"
        _ledger[idem] = True
        return "applied"


def server_settings(ticket_key):
    s = HandshakeSettings()
    s.minVersion = s.maxVersion = (3, 4)
    s.ticketKeys = [ticket_key]
    s.ticket_count = 2
    s.psk_modes = ["psk_dhe_ke"]  # enforce forward secrecy: refuse psk_ke
    return s


def client_settings():
    s = HandshakeSettings()
    s.minVersion = s.maxVersion = (3, 4)
    return s


class Channel:
    def __init__(self, conn):
        self.conn = conn
        self.buf = bytearray()

    def send(self, obj):
        self.conn.send((json.dumps(obj) + "\n").encode())

    def recv(self, timeout=2.0):
        self.conn.sock.settimeout(timeout)
        while b"\n" not in self.buf:
            data = self.conn.read(max=4096)
            if not data:
                raise EOFError
            self.buf += data
        line, _, rest = self.buf.partition(b"\n")
        self.buf = bytearray(rest)
        return json.loads(line.decode())


def run_instance(name, port, ticket_key, issue_migrate, accept_scopes,
                 migrate_target, log):
    chain, key = common.load_cert_key()
    settings = server_settings(ticket_key)
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", port))
    lsock.listen(5)
    while True:
        csock, _ = lsock.accept()
        try:
            conn = TLSConnection(csock)
            # The issuing instance marks its tickets migration_allowed (0xFE4E),
            # a real NewSessionTicket extension on the wire.
            wire.set_allow(issue_migrate)
            conn.handshakeServer(certChain=chain, privateKey=key, settings=settings)
            saw_support = wire.observed_migration_support()
            ch = Channel(conn)
            hello = ch.recv()
            if hello.get("migrated"):
                # tlslite-ng does not surface server-side `resumed` for TLS 1.3,
                # so resumption is enforced client-side (fail-closed) and by TLS
                # itself: a foreign instance cannot complete the resumption, so a
                # migrated hello only ever arrives on a genuinely resumed conn.
                if hello.get("scope") not in accept_scopes:
                    ch.send({"type": "error", "reason": "out_of_scope"})
                    log(f"[{name}] REJECT relocated: scope {hello.get('scope')!r} not in {accept_scopes}")
                    conn.close(); continue
                log(f"[{name}] ACCEPT relocated (resumed={conn.resumed} scope={hello.get('scope')!r})")
            pay = ch.recv()
            status = apply_payment(pay["idem"])
            ch.send({"type": "result", "status": status, "instance": name})
            ext_types = wire.observed_ext_types() or []
            log(f"[{name}] parsed CH ext types={[hex(t) for t in ext_types]} migration_support_seen={saw_support}")
            log(f"[{name}] payment idem={pay['idem']} -> {status}")
            if issue_migrate and saw_support and not hello.get("migrated"):
                # Real post-handshake handshake message (ContentType.handshake,
                # type 0xFD) -- NOT application data.
                wire.send_migrate_request(conn, migrate_target)
                log(f"[{name}] -> migrate_request (post-handshake msg, type 0xFD) target={migrate_target}")
            conn.close()
        except Exception as e:  # keep the instance alive across probes
            log(f"[{name}] conn error: {e}")


def connect(port, session, scope, migrated, idem, log, want_support=True):
    raw = socket.create_connection(("127.0.0.1", port))
    tee = wire.TeeSocket(raw)
    conn = TLSConnection(tee)
    conn.handshakeClientCert(settings=client_settings(), session=session,
                             serverName=common.SERVICE_NAME)
    on_wire = b"\xfe\x4d" in bytes(tee.sent)
    if on_wire:
        global LAST_CH_HEX
        data = bytes(tee.sent)
        i = data.find(b"\xfe\x4d")
        LAST_CH_HEX = data[max(0, i - 6):i + 8].hex()
    # Fail-closed: a relocation MUST be a genuine resumption. If the target
    # could not resume (e.g. a foreign instance lacking the shared key), abort
    # before sending any application data.
    if migrated and not conn.resumed:
        return conn, on_wire, None, None, conn.session
    ch = Channel(conn)
    ch.send({"type": "hello", "migrated": migrated, "scope": scope})
    ch.send({"type": "payment", "idem": idem, "amount": 100})
    res = ch.recv()
    mig = None
    if not migrated:
        # Read migrate_request as a real post-handshake handshake message off
        # the record layer (NewSessionTickets are already processed by the
        # conn.read above, so resumption is preserved).
        target = wire.recv_migrate_request(conn, timeout=2.0)
        if target is not None:
            mig = target.decode()
    session_out = conn.session
    return conn, on_wire, res, mig, session_out


def run_scenario(scenario, base):
    print("=" * 66)
    print(f" scenario: {scenario}   (tlslite-ng {__import__('tlslite').__version__}, real TLS 1.3)")
    print("=" * 66)
    logs = []
    log = lambda m: logs.append(m)

    pA, pB, pF = base, base + 1, base + 2
    b_scope = "svc.example/green" if scenario == "outofscope" else "svc.example/blue"
    a_target = "tok-F" if scenario == "foreign" else "tok-B"
    targets = {"tok-B": (pB, "B"), "tok-F": (pF, "F")}

    threading.Thread(target=run_instance, args=("A", pA, common.SHARED_TICKET_KEY, True, {"svc.example/blue"}, a_target, log), daemon=True).start()
    threading.Thread(target=run_instance, args=("B", pB, common.SHARED_TICKET_KEY, False, {b_scope}, "", log), daemon=True).start()
    threading.Thread(target=run_instance, args=("F", pF, common.FOREIGN_TICKET_KEY, False, {"svc.example/blue"}, "", log), daemon=True).start()
    time.sleep(0.4)

    with _ledger_lock:
        _ledger.clear()
    idem = f"pay-{scenario}"
    wire.set_inject(scenario != "unaware")

    # Phase 1: connect to A
    connA, on_wire_A, resA, mig, sessionA = connect(pA, None, "", False, idem, log)
    allowed_A = wire.ticket_has_migration_allowed(connA)
    print(f"[client] A: tls=resumed?{connA.resumed} migration_support_on_wire={on_wire_A} "
          f"migration_allowed_in_ticket={allowed_A} payment={resA.get('status')}")
    connA.close()

    if scenario == "unaware":
        ok = (mig is None) and (on_wire_A is False)
        print(f"[client] unaware: no migrate_request received={mig is None}; stays on A")
        _dump(logs); _verdict(ok); return ok

    print(f"[client] <- migrate_request target={mig}")
    port, inst = targets[mig]

    # Phase 3: resume on target
    connT, on_wire_T, resT, _, _ = connect(port, sessionA, "svc.example/blue", True, idem, log)
    print(f"[client] {inst}: resumed={connT.resumed} migration_support_on_wire={on_wire_T} reply={resT}")
    connT.close()

    if scenario == "foreign":
        ok = (connT.resumed is False)
        print(f"[client] FAIL-CLOSED expected: resumed={connT.resumed} (no shared key) -> {'OK' if ok else 'NOT OK'}")
    elif scenario == "outofscope":
        ok = (connT.resumed is True) and (resT.get("reason") == "out_of_scope")
        print(f"[client] resumed but rejected out_of_scope -> {'OK' if ok else 'NOT OK'}")
    else:  # success
        ok = (connT.resumed is True) and (resT.get("status") == "deduped") and on_wire_A and on_wire_T and allowed_A
        print(f"[client] PASS criteria: resumed={connT.resumed} replay={resT.get('status')} "
              f"migration_support_on_wire(A,B)=({on_wire_A},{on_wire_T}) migration_allowed_in_ticket={allowed_A}")
        print(f"[client] EVIDENCE: real ClientHello bytes around migration_support (0xFE4D): ...{LAST_CH_HEX}...")

    _dump(logs); _verdict(ok); return ok


def _dump(logs):
    print("  --- instance logs ---")
    for m in logs:
        print("  " + m)


def _verdict(ok):
    print("RESULT:", "PASS" if ok else "FAIL")
    print()


def main():
    common.ensure_cert()
    wire.install()
    assert wire.selftest_migrate_request(), "migrate_request codec round-trip failed"
    print(f"[wire] migrate_request codec round-trip: PASS  (sample hex={wire.encode_migrate_request(b'tok-B').hex()})\n")

    scenarios = sys.argv[1:] or ["success", "foreign", "unaware", "outofscope"]
    results = {}
    base = 7300
    for i, sc in enumerate(scenarios):
        results[sc] = run_scenario(sc, base + i * 10)
    print("=" * 66)
    print(" SUMMARY")
    for sc, ok in results.items():
        print(f"   {sc:12s} {'PASS' if ok else 'FAIL'}")
    sys.exit(0 if all(results.values()) else 1)


if __name__ == "__main__":
    main()
