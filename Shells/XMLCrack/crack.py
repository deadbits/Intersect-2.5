#!/usr/bin/python
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
# crack.py defines a CrackManager object and a CrackThread object, which
# are used to receive and process password cracking requests.
#

import subprocess
import shlex
import threading
import os
import time
import re
import traceback

#-----------------------------------------------------------------------------
# CrackThread Class
#-----------------------------------------------------------------------------
class CrackThread(threading.Thread):
    """Takes an id, hash type, a hash list, and a list of commands. The hash
    list should be in username:hash format except for pwdump and dcc hash
    lists, which are special cases. The hash list is processed to extract
    usernames and is then written to the disk to be used by each command. After
    each command is run the results are processed, added to the results array,
    and the cracked hashes are removed from the hash file."""
    
    def __init__(self, id, hash_type, hash_list, commands):
        threading.Thread.__init__(self)
        self.id = id
        self.hash_type = hash_type
        self.hash_list = hash_list
        self.commands = commands
        self.hash_file = id + '.hash'
        self.results = []
        self.hashes = {}
        self.complete = False
        
    def __del__(self):
        """Remove the temporary hash file"""
        os.remove(self.hash_file)
        
    def process_hash_list(self):
        """Process the file passed to us and extract the usernames, then write
        the file to disk for processing by the commands. Pwdump files and DCC
        files are special cases. The typical input should be username:hash"""
        
        if self.hash_type == 'pwdump':
            for line in self.hash_list:
                user, id, lm, ntlm, a, b, c = line.split(':')
                self.hashes[lm.lower()] = user
            
            self.write_file()
            
        elif self.hash_type == 'dcc':
            for line in self.hash_list:
                dcc, user = line.split(':')
                self.hashes[dcc.lower()] = user

            self.write_file()
            
        else:
            hashes = []
            for line in self.hash_list:
                user, hash = line.split(':')
                self.hashes[hash.lower()] = user
                hashes.append(hash.lower())
                
            self.write_file(hashes)

    def remove_found_hash(self, hash):
        """Remove the found hash from the hash list, which will be rewritten to
        the disk. This prevents us from cracking the same password twice."""
        
        del self.hashes[hash]
        for line in self.hash_list:
            if re.search(hash, line):
                self.hash_list.remove(line)
    
    def process_user(self, user, password):
        """Writes the username, hash and password to the results array. Finds
        the hash using the user. After the results are written, we remove
        the found hash from the hash file on disk."""
        
        if user in self.hashes.itervalues():
            for k, v in self.hashes.iteritems():
                if v == user:
                    self.results.append(user + ':' + k + ':' + password)
                    self.remove_found_hash(hash)
        
    def process_hash(self, hash, password):
        """Writes the username, hash and password to the results array. Finds
        the user using the hash. After results are written, we remove the found
        hash from the hash file on the disk."""
        
        if hash in self.hashes.iterkeys():
            self.results.append(self.hashes[hash] + ':' + hash + ':' + password)
            self.remove_found_hash(hash)

    def process_output(self, output):
        """Uses regular expressions to find hashes and passwords in results and
        passes them to either the process_hash or process_user function. Pwdump
        and DCC results are different than typical results for other hash types
        so I have separated them as special cases. I have REs for outputs from 
        common programs such as rcracki and hashcat. Other REs may need to be
        added for outputs from other programs."""

        if self.hash_type == 'pwdump':
            # All REs here should be for proccessing results of pwdump commands
            # RE for output from rcracki_mt
            for r in re.finditer("([A-Za-z0-9.]+)\s+(.?)\s+hex:.*", output):
                self.process_user(r.group(1), r.group(2))
                
        elif self.hash_type == 'dcc':
            #All REs here should be for processing results of dcc commands
            # RE for DCC output for hashcat family
            for r in re.finditer("([0-9a-f]{16,}):.*:(.*)", output):
                self.process_hash(r.group(1), r.group(2))
        else:
            # RE for standard output for hashcat family
            for r in re.finditer("([0-9a-f]{16,}):(.*)", output):
                self.process_hash(r.group(1), r.group(2))

    def write_file(self, hashes=None):
        """Write the hashes to a file for use by the cracking commands."""
        if hashes == None:
            hashes = self.hash_list
            
        f = open(self.hash_file, 'w')
        for line in hashes:
            f.write(line + '\n')
        f.close()

    def fix_cmd(self, cmd):
        for c in xrange(len(cmd)):
            if cmd[c] == '{file}': cmd[c] = self.hash_file
        return cmd 

    def run(self):
        """For each command, process the hash_list, modify the command to
        include the correct file name on disk, and run the command. Once the
        command is run, we process the output, which include updating the hash
        list to remove found hashes."""
        
        for cmd in self.commands:
            self.process_hash_list()
            cmd = self.fix_cmd(cmd)
            self.process_output(subprocess.check_output(cmd))
            
        self.complete = True


#------------------------------------------------------------------------------
# CrackManager Class
#------------------------------------------------------------------------------
class CrackManager():

    def __init__(self, config):
        self.config = {}
        self.load_cfg(config)
        self.processes = {}

    def load_cfg(self, config):
        """Load configuration file. Blank lines and comments are skipped.
        Confirms each command exists but does not confirm the arguments to the
        command."""
        try:
            cfgfile = open(config, 'r')
            for line in cfgfile:
                if re.match('^$', line): continue
                if re.match('^#.*$', line): continue
                h, c = line.split('|')
                cmd = shlex.split(c.rstrip('\r\n'))
                
                # Split off the command so we can verify it exists.
                if os.path.exists(cmd[0]):
                    if h in self.config.keys():
                        self.config[h].append(cmd)
                    else:
                        self.config[h] = []
                        self.config[h].append(cmd)
                else:
                    raise Exception("Command {0} does not exist.".format(cmd[0]))
    
        except Exception, err:
            raise Exception("Error loading configuration file: \n{0}\n{1}\n".format(str(err), traceback.print_exc()))
            
    def crack_passwords(self, hlist, htype):
        """Accepts an array and hash type from the xmlrpc client. Creates an id
        and a CrackThread object and passes the id, array, and hash type to it.
        Returns the id so that results can be obtained later.
        
        If a hash type is not supported by the server then it returns id 0."""

        id = 0
        message = ''
        if htype in self.config.iterkeys():
            id = str(int(time.time()))
            message = "Request accepted by server."
            self.processes[id] = CrackThread(id, htype, hlist, self.config[htype])
            self.processes[id].start()
        else:
            message = "Server does not support the hash type requested."

        return id, message

    def get_progress(self, id):
        """Accepts an id and provides the results for the CrackThread with that
        id. Gets a copy of the results and clears them to prevent duplicates.
        If the process is complete, it is removed from the process dictionary.
        Returns completion status and current results."""

        r = self.processes[id].results
        self.processes[id].results = []
        
        c = self.processes[id].complete
        if c:
            #If the thread is complete remove CrackThread from processes dict
            del(self.processes[id])
        
        return c, r
