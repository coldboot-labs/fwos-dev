"""Resolve one IN name through a DNS server and report a positive answer."""

import socket
import sys


def encode(name):
    body = b""
    for label in name.strip(".").split("."):
        if not label:
            continue
        raw = label.encode()
        body += bytes([len(raw)]) + raw
    return body + b"\0"


server, name = sys.argv[1], sys.argv[2]
source = sys.argv[3] if len(sys.argv) > 3 else ""
packet = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
packet += encode(name) + (1).to_bytes(2, "big") + (1).to_bytes(2, "big")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if source:
    sock.bind((source, 0))
sock.settimeout(3)
try:
    sock.sendto(packet, (server, 53))
    data, _ = sock.recvfrom(512)
except (TimeoutError, socket.timeout, OSError):
    print("timeout")
    raise SystemExit(1)
rcode = data[3] & 0x0F if len(data) >= 12 else 15
answers = int.from_bytes(data[6:8], "big") if len(data) >= 12 else 0
resolved = data[:2] == b"\x12\x34" and data[2] & 0x80 and rcode == 0 and answers > 0
print("resolved" if resolved else "no")
raise SystemExit(0 if resolved else 1)
