#!/usr/bin/python

import tabnanny
import sys, os

if len(sys.argv) <=1:
	print("Tabnanny Helper Script")
	print("What:\nThis script checks for the existence of tabs and indents within a specified Python script.")
	print("Why:\nPython is a crappy whitespace language and will throw errors if you mix spaces and tabs.")
	print("How:\nEnter the filename that you would like to check. Review it. Proceed to curse Python and then go write some Ruby.")	
	print("usage: ./tabnanny.py filename")
	sys.exit()	

filename = sys.argv[1]



file = open(filename)
for line in file.readlines():
	print repr(line)

