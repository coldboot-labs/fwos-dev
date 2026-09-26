"""Complete a real DHCPv4 lease on an isolated external LAN peer."""

import fcntl
import json
import os
import select
import socket
import struct
import sys
import time


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def options_of(packet):
    found = {}
    if len(packet) < 244 or packet[236:240] != bytes([99, 130, 83, 99]):
        return found
    index = 240
    while index < len(packet):
        kind = packet[index]
        index += 1
        if kind == 255:
            break
        if kind == 0:
            continue
        if index >= len(packet):
            break
        length = packet[index]
        index += 1
        if index + length > len(packet):
            break
        found[kind] = packet[index:index + length]
        index += length
    return found


def frame_for(mac, xid, client_id, extra_options):
    bootp = bytearray(300)
    bootp[0:3] = bytes([1, 1, 6])
    bootp[4:8] = xid
    bootp[10:12] = struct.pack("!H", 0x8000)
    bootp[28:34] = mac
    options = bytes([99, 130, 83, 99]) + extra_options + bytes([61, 7, 1]) + client_id + bytes([255])
    bootp[236:236 + len(options)] = options
    udp = struct.pack("!HHHH", 68, 67, 8 + len(bootp), 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp) + len(bootp),
        int.from_bytes(os.urandom(2)), 0, 64, 17, 0,
        b"\0" * 4, b"\xff" * 4,
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return b"\xff" * 6 + mac + struct.pack("!H", 0x0800) + ip + udp + bootp


def wait_message(receiver, sender, frame, xid, message_type, deadline):
    next_send = 0
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_send:
            sender.send(frame)
            next_send = now + 1
        ready, _, _ = select.select(
            [receiver], [], [], max(0, min(deadline, next_send) - time.monotonic())
        )
        if not ready:
            continue
        packet, _ = receiver.recvfrom(2048)
        if len(packet) < 244 or packet[0] != 2 or packet[4:8] != xid:
            continue
        parsed = options_of(packet)
        if parsed.get(53) == bytes([message_type]):
            return packet, parsed
    return None, {}


receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver.bind(("0.0.0.0", 68))
sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
device = sys.argv[1] if len(sys.argv) > 1 else "eth0"
sender.bind((device, 0))
mac = fcntl.ioctl(receiver.fileno(), 0x8927, struct.pack("256s", device.encode()))[18:24]
xid = os.urandom(4)
client_id = bytearray(os.urandom(6))
client_id[0] = (client_id[0] | 2) & 0xFE
discover = frame_for(mac, xid, client_id, bytes([53, 1, 1, 55, 2, 1, 3]))
deadline = time.monotonic() + 6
offer, offer_options = wait_message(receiver, sender, discover, xid, 2, deadline)
leased = None
if offer is not None and len(offer_options.get(54, b"")) == 4:
    requested = offer[16:20]
    request = frame_for(
        mac, xid, client_id,
        bytes([53, 1, 3, 50, 4]) + requested + bytes([54, 4]) + offer_options[54],
    )
    ack, _ = wait_message(receiver, sender, request, xid, 5, deadline)
    if ack is not None:
        leased = ".".join(str(octet) for octet in ack[16:20])
print(json.dumps({"address": leased}))
