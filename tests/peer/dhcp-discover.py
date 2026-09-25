"""Send a real first-contact DHCPDISCOVER on an isolated external LAN peer."""

import fcntl
import json
import os
import select
import socket
import struct
import time


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver.bind(("0.0.0.0", 68))
sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sender.bind(("eth0", 0))
mac = fcntl.ioctl(receiver.fileno(), 0x8927, struct.pack("256s", b"eth0"))[18:24]
xid = os.urandom(4)
bootp = bytearray(300)
bootp[0:3] = bytes([1, 1, 6])
bootp[4:8] = xid
bootp[10:12] = struct.pack("!H", 0x8000)
bootp[28:34] = mac
bootp[236:248] = bytes([99, 130, 83, 99, 53, 1, 1, 55, 2, 1, 3, 255])
udp = struct.pack("!HHHH", 68, 67, 8 + len(bootp), 0)
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp) + len(bootp),
                 int.from_bytes(os.urandom(2)), 0, 64, 17, 0,
                 b"\0" * 4, b"\xff" * 4)
ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
frame = b"\xff" * 6 + mac + struct.pack("!H", 0x0800) + ip + udp + bootp

offer = False
deadline = time.monotonic() + 4
next_send = 0
while time.monotonic() < deadline and not offer:
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
    if len(packet) >= 244 and packet[0] == 2 and packet[4:8] == xid:
        if packet[236:240] == bytes([99, 130, 83, 99]):
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
                if kind == 53 and length == 1 and packet[index] == 2:
                    offer = True
                index += length
print(json.dumps({"offer": offer}))
