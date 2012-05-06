#!/usr/bin/python
# Intersect Framework (c) 2012
# Core module for basic stuff

import os, sys
import string
import random
import logging

fwpath = os.getcwd()
sys.path.append(fwpath+"src")

ActivityLog = ("Logs/ActivityLog")
DownloadDir = ("Storage/")
ModulesDir = ("src/Modules/remote/")
logging.basicConfig(filename=ActivityLog, level=logging.INFO, format='%(asctime)s %(message)s')

Modules = []
for mods in os.listdir(ModulesDir):
    Modules.append(mods)
    
    
def signalHandler(signal, frame):
    print("[!] Ctrl-C caught, Shutting down now!");
    Shutdown()


def Shutdown():
    if active_session is True:
        shutdown_session()
    sys.exit()


def banner():

    target = random.randrange(1,3)

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


def shell_help(): # help menu displayed for all shells
    print("\n")
    print("          :mods  =>  show available modules")
    print("    :info module => display module information")
    print("  :download file => download file from remote host")
    print("    :upload file => upload file to remote host")
    print("    :exec module => execute module on remote host")
    print("          :files => display stored files for session")
    print("         :killme => shuts down server completely")
    print("           :exit => closes shell connection\n") 
    

def valid_ip(ip):
    parts = ip.split('.')
    return (
        len(parts) == 4
        and all(part.isdigit() for part in parts)
        and all(0 <= int(part) <= 255 for part in parts)
        )
        
        
def get_choice(string):
    try:
        choice = string.split(" ")
        choice = choice[1]
        return choice
    except IndexError:
        choice = ""
        return choice
    
    
def check_options(host, port, type, key, name):
    if valid_ip(host):
        if port.isdigit():
            if name != "":
                if type != "":
                    if type == "xor" and key != "":
                        return True
                    elif type != "xor":
                        return True
                    else:
                        print("[!] invalid private key!")
                else:
                    print("[!] invalid shell type!")
            else:
                print("[!] invalid session name!")
        else:
            print("[!] invalid port number!")
    else:
        print("[!] invalid ipv4 address!")
        
    return False


def module_info(module):
    if os.path.exists(ModulesDir+module):
        info = open(ModulesDir+modname)
        for line in info:
            if "@description" in line:
                des = line.split(":")
                des = des[1]
                print("\nDescription: %s" % des)
            if "@author" in line:
                author = line.split(":")
                author = author[1]
                print("Author: %s" % author)
            else:
                pass
    else:
        print("[!] module not found!")
    
