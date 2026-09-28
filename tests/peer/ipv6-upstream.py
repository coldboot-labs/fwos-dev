#!/usr/bin/env python3
"""External IPv6 upstream for one isolated peer segment.

Sends Router Advertisements for one on-link /64 and answers DHCPv6 for one
address (IA_NA) and, when configured, one delegated prefix (IA_PD). A
configured DNS recursive name server is named both in DHCPv6 (option 23) and
in the Router Advertisements (RDNSS). Like an ISP router, it routes a
delegated prefix to the client's link-local address. Each binding is reported
as one JSON line on stdout.

usage: ipv6-upstream.py <device> <ra-prefix> <delegated-prefix|none> [dns-server]
"""
import ipaddress
import json
import select
import socket
import struct
import subprocess
import sys
import time

DEVICE, RA_PREFIX, DELEGATE = sys.argv[1], sys.argv[2], sys.argv[3]
ifindex = socket.if_nametoindex(DEVICE)
ra_network = ipaddress.IPv6Network(RA_PREFIX + "/64")
delegated = None if DELEGATE == "none" else ipaddress.IPv6Network(DELEGATE)
dns_server = ipaddress.IPv6Address(sys.argv[4]) if len(sys.argv) > 4 else None
mac = bytes.fromhex(open(f"/sys/class/net/{DEVICE}/address").read().strip().replace(":", ""))
server_duid = struct.pack("!HH", 3, 1) + mac
addresses = {}


def report(**event):
    print(json.dumps(event), flush=True)


def option(code, data):
    return struct.pack("!HH", code, len(data)) + data


def options(data):
    while len(data) >= 4:
        code, length = struct.unpack("!HH", data[:4])
        yield code, data[4 : 4 + length]
        data = data[4 + length :]


def router_advertisement():
    packet = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, 1800, 0, 0)
    packet += struct.pack("!BB", 1, 1) + mac
    packet += struct.pack("!BBBBIII", 3, 4, 64, 0xC0, 3600, 1800, 0)
    packet += ra_network.network_address.packed
    if dns_server is not None:
        packet += struct.pack("!BBHI", 25, 3, 0, 600) + dns_server.packed
    return packet


def bindings(client, message, source, commit):
    reply = b""
    for code, body in options(message):
        if code == 3 and len(body) >= 12:
            iaid = body[:4]
            address = addresses.setdefault(client, ra_network.network_address + 0x1000 + len(addresses))
            inner = option(5, address.packed + struct.pack("!II", 600, 900))
            reply += option(3, iaid + struct.pack("!II", 300, 480) + inner)
            if commit:
                report(event="address", address=str(address))
        elif code == 25 and len(body) >= 12:
            iaid = body[:4]
            if delegated is None:
                inner = option(13, struct.pack("!H", 6) + b"no prefix available")
            else:
                inner = option(
                    26,
                    struct.pack("!IIB", 600, 900, delegated.prefixlen)
                    + delegated.network_address.packed,
                )
                if commit:
                    subprocess.run(
                        ["ip", "-6", "route", "replace", str(delegated), "via", source, "dev", DEVICE],
                        check=True,
                    )
                    report(event="delegated", prefix=str(delegated), via=source)
            reply += option(25, iaid + struct.pack("!II", 300, 480) + inner)
    return reply


icmp = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
icmp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
icmp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
dhcp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
dhcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
dhcp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, DEVICE.encode())
dhcp.bind(("::", 547))
group = socket.inet_pton(socket.AF_INET6, "ff02::1:2") + struct.pack("@I", ifindex)
dhcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group)
report(event="ready")

next_ra = 0.0
while True:
    now = time.monotonic()
    if now >= next_ra:
        icmp.sendto(router_advertisement(), ("ff02::1", 0, 0, ifindex))
        next_ra = now + 3
    ready, _, _ = select.select([dhcp], [], [], max(0.0, next_ra - now))
    if not ready:
        continue
    message, (source, port, _, scope) = dhcp.recvfrom(2048)
    if len(message) < 4:
        continue
    kind, transaction = message[0], message[1:4]
    fields = dict(options(message[4:]))
    client = fields.get(1)
    if client is None or kind not in (1, 3, 5, 6, 8):
        continue
    answer = 2 if kind == 1 else 7
    body = option(1, client) + option(2, server_duid)
    if kind == 8:
        body += option(13, struct.pack("!H", 0) + b"released")
    else:
        body += bindings(client, message[4:], source.split("%")[0], kind != 1)
        if dns_server is not None:
            body += option(23, dns_server.packed)
    dhcp.sendto(bytes([answer]) + transaction + body, (source, port, 0, scope or ifindex))
