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
ShellTemps = ("src/Templates/Shells/")
PayloadTemps = ("src/Templates/Payloads/")
Scripts = ("Scripts/")
Payloads = ("Scripts/Payloads/")
Config = ("Config/core.conf")


# Define the logging messages
logging.basicConfig(filename=ActivityLog, level=logging.INFO, format='%(asctime)s %(message)s')

# Build list of modules
Modules = []
for mods in os.listdir(ModulesDir):
    Modules.append(mods)
    
    
# Pretty colors
reset = '\x1b[0m'    # reset all colors to white on black
bold = '\x1b[1m'     # enable bold text
uline = '\x1b[4m'    # enable underlined text
nobold = '\x1b[22m'  # disable bold text
nouline = '\x1b[24m' # disable underlined text
red = '\x1b[31m'     # red text
green = '\x1b[32m'   # green text
blue = '\x1b[34m'    # blue text
cyan = '\x1b[36m'    # cyan text
white = '\x1b[37m'   # white text (use reset unless it's only temporary)

warning = "%s[!]%s" % (red, reset)
info = "%s[*]%s" % (green, reset)


def warning(msg):
    print("%s%s[%s!%s]%s %s " % (bold, red, white, red, reset, msg))
          

def status(msg):
    print("%s[~]%s %s " % (bold, reset, msg))


def title(msg):
    print("%s %s %s" % (uline, msg, reset))
    

def info(msg):
    print("%s[*]%s %s " % (bold, reset, msg))
    

def mkdir_session(name):
    if os.path.exists(DownloadDir+name) is False:
        sessiondir = DownloadDir+name
        os.mkdir(sessiondir)
        return sessiondir
    else:
        from time import gmtime, strftime
        now = stfrtime("%Y-%m-%d", gmtime())
        sessiondir = DownloadDir+name+"-"+now
        os.mkdir(sessiondir)
        return sessiondir
    
    
def xor(string, key):
    data = ''
    for char in string:
        for ch in key:
            char = chr(ord(char) ^ ord(ch))
        data += char
    return data
        

# catch for ctrl+c so we can exit smoothly
def signalHandler(signal, frame):
    warning("Ctrl-C caught, Shutting down now!")
    logging.info("[!] Ctrl+C signal caught. Shutting down Intersect!")


def banner():

    target = random.randrange(1,3)

    if target == 1:
        print """%s%s                         
              ___         __                                     __   
             |   |.-----.|  |_ .-----..----..-----..-----..----.|  |_ 
             |.  ||     ||   _||  -__||   _||__ --||  -__||  __||   _|
             |.  ||__|__||____||_____||__|  |_____||_____||____||____|
             |:  | %spost-exploitation framework%s                                                    
             |::.|                                                   
             `---'  %s                                                  
""" % (bold, blue, white, blue, reset)

    elif target == 2:
        print """%s%s
             _______         __                                __   
            |_     _|.-----.|  |_.-----.----.-----.-----.----.|  |_ 
             _|   |_ |     ||   _|  -__|   _|__ --|  -__|  __||   _|
            |_______||__|__||____|_____|__| |_____|_____|____||____|
                                        %sPost-Exploitation Framework
                                                    bindshell.it.cx%s                                     
""" % (bold, green, white, reset)

    elif target == 3:
        print """%s%s
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
             |_| |_|  \__,_|_| |_| |_|\___| \_/\_/ \___/|_|  |_|\_\%s

                                                            
""" % (bold, cyan, reset)


# help menu displayed for all of the shells
def shell_help():
    print("\n")
    title("intersect shell commands:")
    print("           :mods =>  show available modules")
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
def check_options(host, port, type, key):
    if valid_ip(host):
        if port.isdigit():
            if type != "":
                if type == "xor" and key != "":
                    return True
                elif type != "xor":
                    return True
                else:
                    warning("invalid private key!")
            else:
                warning("invalid shell type!")
        else:
            warning("invalid port number!")
    else:
        warning("invalid IPv4 address!")
        
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
                print("\n%sDescription:%s %s" % (bold, reset, des))
            if "@author" in line:
                author = line.split(":")
                author = author[1]
                print("%sAuthor:%s %s" % (bold, reset, author))
            else:
                pass
    else:
        warning("module not found!")


# define some common error messages
# i got tired of typing these out every time. derp.
def downloaderr(filename, session):
    warning("error saving file: %s" % filename)
    logging.info("[%s] File '%s' download failed." % (session, filename)) 


def uploaderr(filename, session):
    warning("error uploading file: %s" % filename)
    logging.info("[%s] File '%s' upload failed." % (session, filename))

    
def inputerr():
    warning("must specify an option!")

    
def socketerr(session):
    warning("connection error!")
    logging.info("[%s] connection error occured!" % session)