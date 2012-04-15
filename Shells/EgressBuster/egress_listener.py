#!/usr/bin/python

import threading
import time
import SocketServer
import sys

#
#
# This is the listener for the egress buster - works both on posix and windows
#
# Egress Buster Listener - Written by: Dave Kennedy (ReL1K)
#
#

# assign arg params
try:
        portrange = sys.argv[1]
        portrange = portrange.split("-")
        lowport = int(portrange[0])
        lowport = lowport - 1
        highport = int(portrange[1])

# if we didnt put anything in args
except IndexError:
        print """
Egress Buster v0.1 - Find open ports inside a network

Only use a 1000 at a time! Anything more will cause errors.

Quick Egress Buster Listener written by: Dave Kennedy (ReL1K)

Usage: python egress_listener.py <lowport-highport>
Example: python egress_listener.py 1-1000
        """
        sys.exit()

# base class handler for socket server
class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

	# handle the packet
    def handle(self):
        self.data = self.request.recv(1024).strip()
        print "%s connected on port: %s\n" % (self.client_address[0],self.data)
       # self.request.send(self.data.upper())

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

if __name__ == "__main__":

        while 1:

                lowport = lowport + 1
                try:
                        socketserver = ThreadedTCPServer(('', lowport), ThreadedTCPRequestHandler)
                        socketserver_thread = threading.Thread(target=socketserver.serve_forever)
                        socketserver_thread.setDaemon(True)
                        socketserver_thread.start()

                except Exception, e:
                        print e
                        pass

                if lowport == highport: break

        while 1:
                try:
                        time.sleep(1)
                except KeyboardInterrupt: 
                        break
