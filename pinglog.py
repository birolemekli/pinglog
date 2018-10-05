import os
import sys
import socket
import struct
from ctypes import *
import time

zmn = time.strftime("%d/%m/%Y  %H:%M:%S")

class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer=None):

        self.protocol_map = {
            1: "ICMP"
        }
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)
        self.ip_src = socket.inet_ntoa(struct.pack("<L", self.src))
        self.ip_dst = socket.inet_ntoa(struct.pack("<L", self.dst))
data = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
data.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)


try:
    while True:
        zmn = time.strftime("%d/%m/%Y  %H:%M:%S")
        buffer = data.recvfrom(65565)[0]
        ip_buffer = buffer[0:20]
        ip_header = IP(ip_buffer)
        dosya=open("log","a")
        dosya.write(ip_header.protocol+"  Target="+ip_header.ip_src+"  Source="+ip_header.ip_dst+"  Time="+zmn+"\n")
        print({ip_header.protocol},  {ip_header.ip_src},"-->", {ip_header.ip_dst})
except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
sys.exit(0)
