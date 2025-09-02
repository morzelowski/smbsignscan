#!/usr/bin/env python3
import argparse
import ipaddress
import random
import time
import socket
import struct
import sys
import uuid


def build_smb2_negotiate_request(client_security_mode: int = 0x0000):
    """
    Craft a minimal SMB2 NEGOTIATE request (SMB 2.0.2 – 3.0.2 dialects only)
    to avoid 3.1.1 negotiate contexts and keep traffic small.

    Returns: bytes of NetBIOS Session + SMB2 Header + NEGOTIATE body
    """

    # SMB2 Header (64 bytes)
    protocol_id = b"\xfeSMB"  # 0xFE 'S' 'M' 'B'
    structure_size = 64
    credit_charge = 0
    status = 0
    command = 0  # NEGOTIATE
    credit_request = 1
    flags = 0
    next_command = 0
    message_id = 0
    reserved = 0  # for requests (SMB 2.0.2/2.1)
    tree_id = 0
    session_id = 0
    signature = b"\x00" * 16

    smb2_header = (
        protocol_id
        + struct.pack(
            "<H H I H H I I Q I I Q",
            structure_size,
            credit_charge,
            status,
            command,
            credit_request,
            flags,
            next_command,
            message_id,
            reserved,
            tree_id,
            session_id,
        )
        + signature
    )

    # SMB2 NEGOTIATE Request body (StructureSize = 36)
    # Using SMB 2.0.2 style body to avoid 3.1.1 contexts.
    neg_structure_size = 36

    # Offer common dialects up to 3.0.2 to ensure broad compatibility
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    dialect_count = len(dialects)

    # Client security mode is a parameter so we can optionally request signing
    # (0x0002) in a second probe to detect policy.
    reserved2 = 0
    capabilities = 0x00000000
    client_guid = uuid.uuid4().bytes
    client_start_time = 0  # 8 bytes

    negotiate_body_fixed = struct.pack(
        "<H H H H I 16s Q",
        neg_structure_size,
        dialect_count,
        client_security_mode,
        reserved2,
        capabilities,
        client_guid,
        client_start_time,
    )

    negotiate_dialects = b"".join(struct.pack("<H", d) for d in dialects)

    smb2_message = smb2_header + negotiate_body_fixed + negotiate_dialects

    # NetBIOS Session Service header: 0x00 + length (3 bytes, big-endian)
    length = len(smb2_message)
    if length > 0xFFFFFF:
        raise ValueError("SMB2 message too large for NetBIOS header")
    netbios = b"\x00" + struct.pack(
        ">I", length
    )[1:]  # take last 3 bytes of big-endian length

    return netbios + smb2_message


def parse_smb2_negotiate_response(data):
    """
    Parse SMB2 NEGOTIATE response and return (signing_enabled, signing_required).
    Raises ValueError on parse errors.
    """
    if len(data) < 4:
        raise ValueError("Response too short (no NetBIOS header)")
    if data[0] != 0x00:
        raise ValueError("Unexpected NetBIOS header type")
    msg_len = int.from_bytes(b"\x00" + data[1:4], "big")
    payload = data[4:4 + msg_len]
    if len(payload) < 64 + 4:  # header + start of negotiate body
        raise ValueError("SMB2 payload too short")
    if payload[:4] != b"\xfeSMB":
        raise ValueError("Not an SMB2/3 response")

    # SMB2 Header: read Status and Command
    # Command is at offset 12 (after ProtocolId[4], StructureSize[2], CreditCharge[2], Status[4])
    status = struct.unpack_from("<I", payload, 8)[0]
    command = struct.unpack_from("<H", payload, 12)[0]
    if command != 0:
        # Not a NEGOTIATE response; bail
        raise ValueError("Unexpected SMB2 command in response")

    # NEGOTIATE Response body begins immediately after 64-byte header
    body = payload[64:]
    if len(body) < 4:
        raise ValueError("NEGOTIATE body too short")

    # StructureSize (2), SecurityMode (2)
    _, security_mode = struct.unpack_from("<H H", body, 0)

    signing_enabled = bool(security_mode & 0x0001)
    signing_required = bool(security_mode & 0x0002)
    return status, signing_enabled, signing_required


def smb2_negotiate(host: str, port: int, timeout: float, client_security_mode: int):
    req = build_smb2_negotiate_request(client_security_mode)
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(req)
        nb = s.recv(4)
        if not nb or len(nb) < 4:
            raise RuntimeError("No response or incomplete NetBIOS header")
        if nb[0] != 0x00:
            raise RuntimeError("Unexpected NetBIOS message type (not SMB over TCP)")
        msg_len = int.from_bytes(b"\x00" + nb[1:4], "big")
        remaining = msg_len
        chunks = []
        while remaining > 0:
            chunk = s.recv(min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        resp = nb + b"".join(chunks)
        return parse_smb2_negotiate_response(resp)


def check_smb_signing(host: str, port: int = 445, timeout: float = 3.0):
    # First, neutral negotiate (client does not require signing)
    status0, enabled0, required0 = smb2_negotiate(host, port, timeout, client_security_mode=0x0000)
    # If server does not require signing, probe policy by demanding signing
    policy_refuses = False
    status2 = 0
    enabled2 = None
    required2 = None
    if not required0:
        try:
            status2, enabled2, required2 = smb2_negotiate(host, port, timeout, client_security_mode=0x0002)
            # If server returns an error status when client requires signing, infer policy refusal
            if status2 != 0:
                policy_refuses = True
        except Exception:
            # Any error on the second negotiate is treated as refusal to sign when required
            policy_refuses = True

    return {
        "neutral": {"status": status0, "enabled": enabled0, "required": required0},
        "require_probe": {"status": status2, "enabled": enabled2, "required": required2, "refuses": policy_refuses},
    }


def check_smb_service(host: str, port: int = 445, timeout: float = 2.0):
    """Quickly check if TCP 445 is reachable and looks like SMB2/3.
    Returns tuple (service_state, details):
      service_state in {"unreachable", "open-non-smb", "smb2-3"}
      details: optional exception message for diagnostics
    """
    try:
        req = build_smb2_negotiate_request(0x0000)
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req)
            nb = s.recv(4)
            if not nb or len(nb) < 4:
                return "open-non-smb", "no NBSS header"
            if nb[0] != 0x00:
                return "open-non-smb", "NBSS type!=0"
            msg_len = int.from_bytes(b"\x00" + nb[1:4], "big")
            payload = b""
            remaining = msg_len
            while remaining > 0:
                chunk = s.recv(min(remaining, 8192))
                if not chunk:
                    break
                payload += chunk
                remaining -= len(chunk)
            if len(payload) < 4:
                return "open-non-smb", "short payload"
            if payload[:4] == b"\xfeSMB":
                return "smb2-3", None
            if payload[:4] == b"\xffSMB":
                return "smb1", None
            return "open-non-smb", "no SMB signature"
        return "smb2-3", None
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        return "unreachable", str(e)


def smb1_negotiate_request():
    # SMB1 Negotiate Protocol Request with single dialect "NT LM 0.12"
    smb1_header = bytearray()
    smb1_header += b"\xffSMB"          # Protocol
    smb1_header += b"\x72"              # Command: NEGOTIATE
    smb1_header += b"\x00\x00\x00\x00"  # Status
    smb1_header += b"\x18"              # Flags
    smb1_header += b"\x01\x28"          # Flags2 (little-endian). Minimal set
    smb1_header += b"\x00\x00"          # PIDHigh
    smb1_header += b"\x00" * 8          # Signature
    smb1_header += b"\x00\x00"          # TID
    smb1_header += b"\x2F\x4B"          # PID (random-ish)
    smb1_header += b"\x00\x00"          # UID
    smb1_header += b"\x00\x00"          # MID

    dialect = b"NT LM 0.12\x00"
    payload = b"\x00"  # WordCount = 0
    payload += struct.pack("<H", 1 + 1 + len(dialect))  # ByteCount
    payload += b"\x02" + dialect  # Dialect format 0x02 + string

    nb_len = len(smb1_header) + len(payload)
    netbios = b"\x00" + struct.pack(">I", nb_len)[1:]
    return netbios + smb1_header + payload


def check_smb1_signing(host: str, port: int = 445, timeout: float = 3.0):
    req = smb1_negotiate_request()
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(req)
        nb = s.recv(4)
        if not nb or len(nb) < 4 or nb[0] != 0x00:
            raise RuntimeError("Invalid SMB1 NBSS header")
        msg_len = int.from_bytes(b"\x00" + nb[1:4], "big")
        data = b""
        remaining = msg_len
        while remaining > 0:
            chunk = s.recv(min(remaining, 8192))
            if not chunk:
                break
            data += chunk
            remaining -= len(chunk)
        if len(data) < 32 or data[:4] != b"\xffSMB":
            raise RuntimeError("Not an SMB1 response")
        # SMB1 header is 32 bytes; parameters follow
        if len(data) < 33:
            raise RuntimeError("SMB1 response too short")
        # Byte at offset 32 is WordCount (number of parameter words)
        wc = data[32]
        params_len = wc * 2
        if len(data) < 33 + params_len:
            raise RuntimeError("SMB1 params truncated")
        params = data[33:33 + params_len]
        if wc < 2:
            raise RuntimeError("Unexpected SMB1 NEGOTIATE WordCount")
        # For NT LM 0.12 negotiate response, SecurityMode is a byte at param[2]
        # Layout: DialectIndex (2), SecurityMode (1), then other words...
        dialect_index = struct.unpack_from("<H", params, 0)[0]
        sec_mode = params[2]
        enabled = bool(sec_mode & 0x01)
        required = bool(sec_mode & 0x02)
        return enabled, required


# -----------------
# Minimal DNS client
# -----------------

def _dns_encode_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.strip('.').split('.'):
        if not label:
            continue
        if len(label) > 63:
            raise ValueError("DNS label too long")
        out.append(len(label))
        out += label.encode('utf-8')
    out.append(0)
    return bytes(out)


def _dns_read_name(data: bytes, offset: int):
    labels = []
    jumped = False
    orig_offset = offset
    limit = 0
    while True:
        if offset >= len(data):
            raise ValueError("DNS name out of bounds")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("DNS pointer truncated")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if limit > 10:
                raise ValueError("DNS pointer loop")
            limit += 1
            offset = ptr
            if not jumped:
                # Only advance original offset once; compressed name ends here
                orig_offset += 2
                jumped = True
            continue
        else:
            offset += 1
            if offset + length > len(data):
                raise ValueError("DNS label truncated")
            labels.append(data[offset:offset + length].decode('utf-8', 'ignore'))
            offset += length
    return '.'.join(labels), (orig_offset if jumped else offset)


def dns_resolve_a(name: str, server: str, port: int = 53, timeout: float = 2.0, max_chain: int = 3) -> str:
    # Build query
    tid = random.getrandbits(16)
    flags = 0x0100  # RD=1
    qdcount = 1
    header = struct.pack('>HHHHHH', tid, flags, qdcount, 0, 0, 0)
    qname = _dns_encode_qname(name)
    question = qname + struct.pack('>HH', 1, 1)  # QTYPE=A, QCLASS=IN
    query = header + question

    target = name
    for _ in range(max_chain + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, (server, port))
            data, _ = s.recvfrom(2048)

        if len(data) < 12:
            raise RuntimeError("DNS response too short")
        r_tid, r_flags, qdc, anc, nsc, arc = struct.unpack('>HHHHHH', data[:12])
        if r_tid != tid:
            # Ignore mismatch; treat as failure
            raise RuntimeError("DNS transaction ID mismatch")
        rcode = r_flags & 0x000F
        if rcode != 0:
            raise RuntimeError(f"DNS error rcode={rcode}")

        # Walk question section
        off = 12
        for _q in range(qdc):
            _, off = _dns_read_name(data, off)
            off += 4  # QTYPE,QCLASS

        cname_target = None
        # Walk answers
        for _a in range(anc):
            _, off = _dns_read_name(data, off)
            if off + 10 > len(data):
                raise RuntimeError("DNS RR header truncated")
            atype, aclass, _ttl, rdlen = struct.unpack('>HHIH', data[off:off + 10])
            off += 10
            if off + rdlen > len(data):
                raise RuntimeError("DNS RDATA truncated")
            rdata = data[off:off + rdlen]
            off += rdlen
            if aclass != 1:
                continue
            if atype == 1 and rdlen == 4:
                return socket.inet_ntoa(rdata)
            if atype == 5:  # CNAME
                cname, _ = _dns_read_name(data, off - rdlen)
                cname_target = cname

        if cname_target:
            # Follow CNAME: rebuild query with new qname
            target = cname_target
            tid = random.getrandbits(16)
            header = struct.pack('>HHHHHH', tid, flags, qdcount, 0, 0, 0)
            qname = _dns_encode_qname(target)
            query = header + qname + struct.pack('>HH', 1, 1)
            continue

        raise RuntimeError("DNS: no A record found")


def _expand_target_token(token: str):
    token = token.strip()
    if not token:
        return []
    if '/' in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                return [str(ip) for ip in net.hosts()]
        except ValueError:
            pass
    return [token]


def _collect_targets(host_arg: str | None, file_path: str | None, max_hosts: int = 65536):
    seen = set()
    ordered = []
    def add_one(h):
        if h and h not in seen:
            seen.add(h)
            ordered.append(h)

    if host_arg:
        for part in host_arg.split(','):
            for h in _expand_target_token(part):
                add_one(h)

    if file_path:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                for part in line.split(','):
                    for h in _expand_target_token(part):
                        add_one(h)

    if len(ordered) > max_hosts:
        raise RuntimeError(f"Target list too large ({len(ordered)} > {max_hosts}). Reduce scope or raise --max-hosts.")
    return ordered


def main():
    print("""
▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌
▐░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▌
▐░█▀▀░█▄█░█▀▄░█▀▀░▀█▀░█▀▀░█▀█░█▀▀░█▀▀░█▀█░█▀█░▌
▐░▀▀█░█░█░█▀▄░▀▀█░░█░░█░█░█░█░▀▀█░█░░░█▀█░█░█░▌
▐░▀▀▀░▀░▀░▀▀░░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀░▀░▀░▀░▌
▐░By░M0U░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▌
▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌
    """)

    ap = argparse.ArgumentParser(description="Minimal SMB signing check via SMB2 NEGOTIATE")
    ap.add_argument("host", nargs='?', help="Target(s): host/IP, comma list, or CIDR (e.g., 192.168.0.1,192.168.0.2 or 192.168.0.0/24)")
    ap.add_argument("-p", "--port", type=int, default=445, help="SMB port (default 445)")
    ap.add_argument("-t", "--timeout", type=float, default=3.0, help="Socket timeout seconds (default 3.0)")
    ap.add_argument("--show-service", action="store_true", help="Also print SMB service presence/version hints")
    ap.add_argument("--probe-policy", action="store_true", help="Probe if server rejects client-required signing")
    ap.add_argument("--dns", metavar="IP", help="Use this DNS server (e.g., DC IP) to resolve host if not an IP")
    ap.add_argument("--dns-port", type=int, default=53, help="DNS server port (default 53)")
    # DNS timeout removed; DNS uses the global --timeout
    ap.add_argument("-f", "--file", help="File with hosts (one per line; supports comma-separated and CIDR)")
    ap.add_argument("--max-hosts", type=int, default=65536, help="Safety cap for expanded targets (default 65536)")
    ap.add_argument("--sleep", type=float, default=0.0, help="Seconds to sleep between targets (multi-target runs)")
    ap.add_argument("--force-smb1", action="store_true", help="Force SMBv1 signing probe (skip SMBv2/3)")
    args = ap.parse_args()

    try:
        targets = _collect_targets(args.host, args.file, max_hosts=args.max_hosts)
        if not targets:
            print("Error: no targets provided (positional host/CIDR or --file)")
            sys.exit(2)
        if len(targets) > 1:
            any_ok = False
            for idx, src in enumerate(targets):
                # Resolve via specified DNS if provided and src is not an IP
                resolved = src
                try:
                    ipaddress.ip_address(resolved)
                except ValueError:
                    if args.dns:
                        try:
                            resolved = dns_resolve_a(src, args.dns, port=args.dns_port, timeout=args.timeout)
                        except Exception as e:
                            print(f"Target: {src}")
                            print(f"Error: DNS resolution via {args.dns} failed: {e}")
                # Header line
                if src == resolved:
                    print(f"Target: {src}")
                else:
                    print(f"Target: {src} -> {resolved}")

                # Force SMB1 signing probe path
                if args.force_smb1:
                    try:
                        en1, req1 = check_smb1_signing(resolved, args.port, args.timeout)
                        any_ok = True
                        if req1:
                            print("SMB signing: REQUIRED (SMB1)")
                        elif en1:
                            print("SMB signing: SUPPORTED but NOT required (SMB1)")
                        else:
                            print("SMB signing: DISABLED (SMB1)")
                    except Exception as e:
                        print(f"Error: SMB1 probe failed: {e}")
                    if idx != len(targets) - 1:
                        print()
                        if args.sleep > 0:
                            time.sleep(args.sleep)
                    continue

                # Optional service probe (adds one extra request if used)
                if args.show_service:
                    state, details = check_smb_service(resolved, args.port, timeout=min(args.timeout, 2.0))
                    if state == "smb2-3":
                        print("Service: SMBv2/3 detected on TCP/445")
                    elif state == "smb1":
                        print("Service: SMBv1 detected on TCP/445")
                    elif state == "open-non-smb":
                        print("Service: TCP/445 open but not SMB (non-SMB service)")
                    else:
                        print("Service: SMB unreachable (closed/filtered)")

                    if state == "unreachable":
                        if idx != len(targets) - 1:
                            print()
                            if args.sleep > 0:
                                time.sleep(args.sleep)
                        continue

                    if state == "smb1":
                        try:
                            en1, req1 = check_smb1_signing(resolved, args.port, args.timeout)
                            any_ok = True
                            if req1:
                                print("SMB signing: REQUIRED (SMB1)")
                            elif en1:
                                print("SMB signing: SUPPORTED but NOT required (SMB1)")
                            else:
                                print("SMB signing: DISABLED (SMB1)")
                        except Exception as e:
                            print(f"Error: SMB1 probe failed: {e}")
                        if idx != len(targets) - 1:
                            print()
                            if args.sleep > 0:
                                time.sleep(args.sleep)
                        continue

                # SMB2/3 path
                try:
                    res = check_smb_signing(resolved, args.port, args.timeout)
                    any_ok = True
                    enabled = res["neutral"]["enabled"]
                    required = res["neutral"]["required"]
                    refuses = res["require_probe"]["refuses"] if args.probe_policy else False

                    if required:
                        print("SMB signing: REQUIRED (server enforces signing)")
                    elif refuses:
                        print("SMB signing: DISABLED/REFUSED (server rejects client-required signing at negotiate)")
                    elif enabled:
                        print("SMB signing: SUPPORTED but NOT required")
                    else:
                        print("SMB signing: DISABLED (not supported)")

                    if args.probe_policy:
                        pr = res["require_probe"]
                        st = pr.get("status", 0)
                        e2 = pr.get("enabled")
                        r2 = pr.get("required")
                        if pr.get("refuses"):
                            print(f"Probe (client requires signing): refused, status=0x{st:08x}")
                        else:
                            if e2 is None and r2 is None and (res["neutral"]["required"] is True):
                                print("Probe (client requires signing): skipped (server already requires)")
                            else:
                                flags = []
                                if e2 is True:
                                    flags.append("ENABLED")
                                if r2 is True:
                                    flags.append("REQUIRED")
                                flag_str = ",".join(flags) if flags else "none"
                                print(f"Probe (client requires signing): accepted, status=0x{st:08x}, server flags={flag_str}")
                except Exception as e:
                    print(f"Error: {e}")

                if idx != len(targets) - 1:
                    print()
                    if args.sleep > 0:
                        time.sleep(args.sleep)

            sys.exit(0 if any_ok else 2)
        # Resolve host via specified DNS if provided and host is not an IP
        target = targets[0]
        try:
            ipaddress.ip_address(target)
        except ValueError:
            if args.dns:
                target = dns_resolve_a(target, args.dns, port=args.dns_port, timeout=args.timeout)

        # If forcing SMB1, do only SMB1 signing probe and exit
        if args.force_smb1:
            try:
                en1, req1 = check_smb1_signing(target, args.port, args.timeout)
                if req1:
                    print("SMB signing: REQUIRED (SMB1)")
                elif en1:
                    print("SMB signing: SUPPORTED but NOT required (SMB1)")
                else:
                    print("SMB signing: DISABLED (SMB1)")
                sys.exit(0)
            except Exception as e:
                print(f"Error: SMB1 probe failed: {e}")
                sys.exit(2)

        # Optional service probe
        if args.show_service:
            state, details = check_smb_service(target, args.port, timeout=min(args.timeout, 2.0))
            if state == "smb2-3":
                print("Service: SMBv2/3 detected on TCP/445")
            elif state == "smb1":
                print("Service: SMBv1 detected on TCP/445")
            elif state == "open-non-smb":
                print("Service: TCP/445 open but not SMB (non-SMB service)")
            else:
                print("Service: SMB unreachable (closed/filtered)")

            if state == "unreachable":
                sys.exit(2)
            if state == "smb1":
                try:
                    en1, req1 = check_smb1_signing(target, args.port, args.timeout)
                    if req1:
                        print("SMB signing: REQUIRED (SMB1)")
                    elif en1:
                        print("SMB signing: SUPPORTED but NOT required (SMB1)")
                    else:
                        print("SMB signing: DISABLED (SMB1)")
                    sys.exit(0)
                except Exception as e:
                    print(f"Error: SMB1 probe failed: {e}")
                    sys.exit(2)

        # SMB2/3 path
        res = check_smb_signing(target, args.port, args.timeout)
        enabled = res["neutral"]["enabled"]
        required = res["neutral"]["required"]
        refuses = res["require_probe"]["refuses"] if args.probe_policy else False

        if required:
            print("SMB signing: REQUIRED (server enforces signing)")
        elif refuses:
            print("SMB signing: DISABLED/REFUSED (server rejects client-required signing at negotiate)")
        elif enabled:
            print("SMB signing: SUPPORTED but NOT required")
        else:
            print("SMB signing: DISABLED (not supported)")

        # If user asked for policy probe, report its outcome explicitly
        if args.probe_policy:
            pr = res["require_probe"]
            st = pr.get("status", 0)
            e2 = pr.get("enabled")
            r2 = pr.get("required")
            if pr.get("refuses"):
                print(f"Probe (client requires signing): refused, status=0x{st:08x}")
            else:
                # If we didn't perform the second negotiate (because server already required),
                # status will remain 0 and enabled/required None. Clarify that.
                if e2 is None and r2 is None and (res["neutral"]["required"] is True):
                    print("Probe (client requires signing): skipped (server already requires)")
                else:
                    flags = []
                    if e2 is True:
                        flags.append("ENABLED")
                    if r2 is True:
                        flags.append("REQUIRED")
                    flag_str = ",".join(flags) if flags else "none"
                    print(f"Probe (client requires signing): accepted, status=0x{st:08x}, server flags={flag_str}")
        sys.exit(0)
    except (socket.timeout, ConnectionRefusedError):
        print("Error: Connection failed or timed out.")
    except Exception as e:
        print(f"Error: {e}")
    sys.exit(2)


if __name__ == "__main__":
    main()
