#!/usr/bin/python

import os, sys
import string
import random
import logging

fwpath = os.getcwd()
sys.path.append(fwpath+"src")

ActivityLog = ("Logs/ActivityLog")
DownloadDir = ("Storage/")
ModulesDir = ("src/Modules/remote/")

Modules = []
for mods in os.listdir(ModulesDir):
    Modules.append(mods)
    
logging.basicConfig(filename=ActivityLog, level=logging.INFO, format='%(asctime)s %(message)s')


def signalHandler(signal, frame):
    print("[!] Ctrl-C caught, Shutting down now!");
    Shutdown()


def Shutdown():
    sys.exit()


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


def shell_help(): # help menu displayed for all shells
    print(" Available Commands: ")
    print("---------------------------------")
    print("          :mods  =>  show available modules")
    print("   :info module  =>  display module information")
    print(" :download file  =>  download file from host")
    print("   :upload file  =>  upload file to host")
    print("   :exec module  =>  sends script to host and executes")
    print("         :files  =>  display contents of your files directory")
    print("        :killme  =>  shuts down server completely")
    print("          :quit  =>  closes shell connection\n")
    
    
