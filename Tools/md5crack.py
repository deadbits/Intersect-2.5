#!/usr/bin/python
# This script uses a bruteforce method to crack MD5 hashes
# If the password length is longer than ~10 characters, it could take a considerable time to crack
# Also, this code can be very CPU intensive if you are running it for long periods of time
# or running several instances at once. Be kind to it, it just a proof of concept.
 
import itertools
import sys
import hashlib
import time
 
lower = 'abcdefghijklmnopqrstuvwxyz'
upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
lowup = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
numbers = '1234567890'
lownum = 'abcdefghijklmnopqrstuvwxyz1234567890'
upnum = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
all = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
 
def brutecrack():
        length = int(sys.argv[2]) + 1
 
        if sys.argv[1] == '-l':
                final = lower
        elif sys.argv[1] == '-U':
                final = upper
        elif sys.argv[1] == '-n':
                final = numbers
        elif sys.argv[1] == '-aA':
                final = lowup
        elif sys.argv[1] == '-ln':
                final = lownum
        elif sys.argv[1] == '-Un':
                final = upnum
        elif sys.argv[1] == '-all':
                final = all
 
        for i in range(1,length):
                for p in itertools.product(final, repeat=i):
                        crack = ''.join(p)
                        m = hashlib.md5()
                        m.update(crack)
                        if m.hexdigest() != sys.argv[3]:
                                print "[X] Failed attempt => ",crack
                                
                                
                        else:
                                print "[!] Success => ", crack
                                sys.exit()
 
def main():
        if len(sys.argv) <=1:
                print '''\nMD5-Crack :\n
python md5crack.py -all 10 5f4dcc3b5aa765d61d8327deb882cf99
-l   | Lowercase Only
-U   | Uppercase Only
-n   | Numbers Only
-ln  | Alphanumeric(lower)
-Un  | Alphanumeric(upper)
-all | All of Above\n'''
                sys.exit(1)
        else:
                brutecrack()
 
if __name__ == "__main__" :
        main()
