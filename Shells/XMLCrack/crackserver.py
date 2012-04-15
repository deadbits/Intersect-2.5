#! /usr/bin/python
# Copyright 2011 Stephen Haywood aka AverageSecurityGuy
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Crackserver uses the crack.py module to setup a XMLRPC server to handle
# password cracking requests.
#

import SimpleXMLRPCServer as sxml
import crack
import argparse

desc = """Crackserver uses the crack.py module to setup a XMLRPC server to
handle password cracking requests."""

parser = argparse.ArgumentParser(description=desc)
parser.add_argument('-l', action='store', default='127.0.0.1',
                    help='IP address to listen on. (default: 127.0.0.1)')
parser.add_argument('-p', action='store', default='8000',
                    help='Port to listen on. (default: 8000)')
parser.add_argument('-c', action='store', default='crack.cfg',
                    help='Configuration file. (default: crack.cfg)')

args = parser.parse_args()

# Create new CrackManager object to handle cracking process.
try:
    c = crack.CrackManager(args.c)
    print "CrackManager configured successfully"
except Exception, err:
    print "CrackManager configuration unsuccessful:\n"
    print str(err)
    exit()
    
try:
    server = sxml.SimpleXMLRPCServer((args.l, int(args.p)),
        requestHandler=sxml.SimpleXMLRPCRequestHandler)
    print "XMLRPC server configuration successful."
except Exception, err:
    print "XMLRPC server configuration unsuccessful:\n"
    print str(err)
    exit()
    
# Register CrackManager functions to be used with by XMLRPC client.
server.register_introspection_functions()
server.register_function(c.crack_passwords, 'crack')
server.register_function(c.get_progress, 'results')
server.serve_forever()

