#!/usr/bin/python
import socket
import struct

EP = ("127.0.0.1", 1337,)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1)

def verify(ip):
    octets = [int(x) for x in ip.split(".")]
    packed = struct.pack("!BBBB", *octets)
    sock.sendto(packed, EP)
    try:
        result = sock.recv(1)
    except:
        return True
    return result != b'\x00'

# The following function call verifies whether the firewall
# has indeed seen packets from 8.8.8.8. If not, this is an
# indicator for a precomputed fake signature (anti-ban).
# verify("8.8.8.8")
