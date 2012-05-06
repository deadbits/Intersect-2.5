#!/usr/bin/python
# Intersect Framework (c) 2012
# Core module for framework wide stuff

import os, sys
import string
import random
import logging

fwpath = os.getcwd()
sys.path.append(fwpath+"src")

# Location for logs, modules and storage
ActivityLog = ("Logs/ActivityLog")
DownloadDir = ("Storage/")
ModulesDir = ("src/Modules/")
Config = ("Config/core.conf")

# Define the logging messages
logging.basicConfig(filename=ActivityLog, level=logging.INFO, format='%(asctime)s %(message)s')

# Build list of modules
Modules = []
for mods in os.listdir(ModulesDir):
    Modules.append(mods)
    

# catch for ctrl+c so we can exit smoothly
def signalHandler(signal, frame):
    print("[!] Ctrl-C caught, Shutting down now!");
    logging.info("[!] Ctrl+C signal caught. Shutting down Intersect!")


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


# help menu displayed for all of the shells
def shell_help():
    print("\n")
    print("          :mods  =>  show available modules")
    print("    :info module => display module information")
    print("  :download file => download file from remote host")
    print("    :upload file => upload file to remote host")
    print("    :exec module => execute module on remote host")
    print("          :files => display stored files for session")
    print("         :killme => shuts down server completely")
    print("           :exit => closes shell connection\n") 
    

# verify that ipv4 addresses are in the correct format
# only performs basic checks so things like 1.1.4 won't get through
def valid_ip(ip):
    parts = ip.split('.')
    return (
        len(parts) == 4
        and all(part.isdigit() for part in parts)
        and all(0 <= int(part) <= 255 for part in parts)
        )
        

# attempt to parse option from console commands
def get_choice(string):
    try:
        choice = string.split(" ")
        choice = choice[1]
        return choice
    except IndexError:
        choice = ""
        return choice
    

# verifies that shell options are correct
# before we try to make a connection
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


# parses author and description from individual modules
# when users call the :info command
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


# define some common error messages
# i got tired of typing these out every time. derp.
def downloaderr(filename, session):
    print("[!] Error saving file: %s" % filename)
    logging.info("[%s] File '%s' download failed." % (session, filename)) 


def uploaderr(filename, session):
    print("[!] Error uploading file: %s" % filename)
    logging.info("[%s] File '%s' upload failed." % (session, filename))

    
def inputerr():
    print("[!] must specify an option!")

    
def socketerr(session):
    print("[!] connection error!")
    logging.info("[%s] connection error occured!" % session)