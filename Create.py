#!/usr/bin/python

# Intersect2 Payload Generation Utility
# copyright 2012 - ohdae
# bindshell labs - http://bindshell.it.cx

import sys, os, re
import shutil
import string, socket
import linecache
import random
import urllib, urllib2
import datetime


global ModulesDir
global CustomDir
global PayloadTemplate
global currentloc
global tab_complete
global BuildLog
global now


tab_complete = True
try:
    import readline
except ImportError:
    print "[!] Python readline is not installed. Tab completion in the Create menu will be disabled."
    tab_complete = False

if tab_complete == True:
    readline.parse_and_bind("tab: complete")

currentloc = os.getcwd()
ModulesDir = (currentloc+"/src/Modules/Standard/")
CustomDir = (currentloc+"/src/Modules/Custom/")
PayloadTemplate = (currentloc+"/src/Templates/stock-template")
BuildLog = (currentloc+"/Logs/build_log")

# Setup time format for build logs
now = datetime.datetime.now()
logtime = (str(now.month)+"-"+str(now.day)+"-"+str(now.year)+" @ "+str(now.hour)+":"+str(now.minute))
writelog = open(BuildLog, "a")

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

class Completer:
    def __init__(self):
        standard = os.listdir(ModulesDir)
        custom = os.listdir(CustomDir)
        modcom = standard + custom
        cmds = ["create", "help", "active", "rem", "modules", "quit", "info", "clear"]
        if menu_option == "build":
            self.words = cmds + modcom
            self.prefix = ":"
	
    def complete(self, prefix, index):
        if prefix != self.prefix:
            self.matching_words = [w for w in self.words if w.startswith(prefix)]
            self.prefix = prefix
        else:
            pass
        try:
            return self.matching_words[index]
            return self.match_mods[index]
        except IndexError:
            return None

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
            global menu_option
            menu_option = "build"
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
      print("2 => Download and import from URL")
      print("3 => List currently loaded custom modules")
      print("4 => Return to Main Menu")

      choice = raw_input("%s " % (self.header))

      if choice == '1':
          print("Enter the current location of your custom module: ")
          modloc = raw_input("%s " % (self.header))

          if os.path.exists(modloc) is True:
              shutil.copy2(modloc, CustomDir)
              writelog.write("\n\n[ New Module Imported ]")
              writelog.write("\n"+logtime+" %s imported successfully." % modloc)
              print("[+] Module successfully loaded into the custom modules directory!")
              self.loadfunc()

          else:
              print("[!] Custom module could not be loaded.")
              writelog.write("\n"+logtime+" [Error] Module import failed.")

      elif choice == '2':
          print("Enter the URL where the file is location: ")
          print("example: http://example.com/mymodule")
          modloc = raw_input("%s " % (self.header))

          filename = modloc.split('/')[-1]
        
          try:
              urllib.urlretrieve(modloc, filename=CustomDir+filename)
          except Exception, e:
              print("\n[!] Error downloading %s: %s" % (modloc, e))
              self.loadfunc()

          if os.path.exists(CustomDir+filename) is True:
              print("\n[+] Module successfully downloaded and imported!\n")
              writelog.write("\n\n[ New Module Imported ]")
              writelog.write("\n"+logtime+" %s downloaded and imported successfully." % modloc)
              self.loadfunc()
          else:
              print("\n[!] Something went wrong! Download and import not completed!\n")
              writelog.write("\n"+logtime+" [Error] Download and import of %s failed." % modloc)
              self.loadfunc()

      elif choice == '3':
          print("Currently available custom modules: ")
          os.system("ls %s" % CustomDir)
          self.loadfunc()

      elif choice == '4':
          os.system("clear")
          banner()
          self.core()

  def create(self):
      menu_option = "build"
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
      writelog.write("\n\n[ New Build Process Started ]\n")

      while 1:
          if tab_complete == True:
              completer = Completer()
              readline.set_completer(completer.complete)

          modulesInput = raw_input("%s " % (self.header))

          if os.path.exists(ModulesDir+modulesInput) is True:
              desired_modules.append(modulesInput)
              writelog.write("\n"+logtime + " %s added to queue" % modulesInput)
              print ("%s added to queue.\n" % modulesInput)

          elif os.path.exists(CustomDir+modulesInput) is True:
              desired_modules.append(modulesInput)
              writelog.write("\n"+logtime + " %s added to queue" % modulesInput)
              print ("%s added to queue.\n" % modulesInput)
              
          elif modulesInput == ":modules":
              os.system("ls %s" % ModulesDir)
              os.system("ls %s" % CustomDir)

          elif modulesInput == ":create":
              createcustom.chooseName()
              payloadgen.globalconfig(desired_modules)
              writelog.write("\n"+logtime + " Building Script with: ")
              writelog.write("\n%s" % desired_modules)
              for mod in desired_modules:
                  print mod
              createcustom.CombineFeatures(desired_modules)

          elif modulesInput.startswith(":info"):
              getname = modulesInput.split(' ')
              modname = getname[1]

              if os.path.exists(CustomDir+modname) is True:
                  info = open(CustomDir+modname)
                  for line in info:
                      if "@description" in line:
                          split = line.split(":")
                          des = split[1]
                          print("\nDescription: %s " % des)
                      if "@author" in line:
                          split = line.split(":")
                          author = split[1]
                          print("Author: %s " % author)

              elif os.path.exists(ModulesDir+modname) is True:
                  info = open(ModulesDir+modname)
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
                  print("No description given for %s module " % modname)


          elif modulesInput.startswith(":rem"):
              getname = modulesInput.split(' ')
              modname = getname[1]
              desired_modules.remove(modname)
              writelog.write("\n"+logtime + "%s removed from queue" % moduleInput)
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
      writeglobals = (currentloc+"/Junk/globals")
      globalstemp = open(writeglobals, "a")

      globalstemp.write("\ndef globalvars():")
      globalstemp.write("\n    global PORT")
      globalstemp.write("\n    global RHOST")
      globalstemp.write("\n    global RPORT")
      globalstemp.write("\n    global PPORT")
      globalstemp.write("\n    global PKEY")
      globalstemp.write("\n    global modList")
      globalstemp.write("\n    global Temp_Dir")
      globalstemp.write("\n    global Logging")

      globalstemp.write("\n\n    modList = %s" % modules)

      print("\nSpecify the directory on the target system where the gathered files and information will be saved to.")
      print("*Important* This should be a NEW directory. When exiting Intersect, this directory will be deleted if it contains no files.")
      print("If you skip this option, the default (/tmp/lift+$randomstring) will be used.")

      tempdir = raw_input("temp directory %s " % (self.header))
      if tempdir == "":
          globalstemp.write("\n    Rand_Dir = ''.join(random.choice(string.letters) for i in xrange(12))")
          globalstemp.write("\n    Temp_Dir = '/tmp/lift-'+'%s' % Rand_Dir")
      else:
          globalstemp.write("\n    Temp_Dir = '%s'" % tempdir)

      logopt = raw_input("enable logging %s " % (self.header))
      if logopt == "":
          writelog.write("\n"+logtime+" Task logging DISABLED")
          globalstemp.write("\n    Logging = 'no'")
      elif logopt == "yes" or logopt.startswith("y"):
          writelog.write("\n"+logtime+" Task logging ENABLED")
          globalstemp.write("\n    Logging = 'yes'")
      else:
          globalstemp.write("\n    Logging = 'no'")
          writelog.write("\n"+logtime+" Task logging DISABLED")


      bport = raw_input("bind port %s " % (self.header))
      if bport == "":
          globalstemp.write("\n    PORT = 8888")
          writelog.write("\n"+logtime + " PORT: 8888")
      elif bport.isdigit() is True:
          globalstemp.write("\n    PORT = %s" % bport)
          writelog.write("\n"+logtime + " PORT: %s" % bport)
          print("[+] bind port saved.")
      else:
          print("[!] invalid port!")
          os.system("rm %s" % writeglobals)
          self.globalconfig()

      rhost = raw_input("remote host %s " % (self.header))
      if rhost == "":
          globalstemp.write("\n    RHOST = ''")
          writelog.write("\n"+logtime + " RHOST: ''")
      elif self.valid_ip(rhost) is True:
          globalstemp.write("\n    RHOST = '%s'" % rhost)
          writelog.write("\n"+logtime + " RHOST: %s" % rhost)
          print("[+] remote host saved.")
      else:
          print("[!] invalid ipv4 address!")
          os.system("rm %s" % writeglobals)
          self.globalconfig()

      rport = raw_input("remote port %s " % (self.header))
      if rport == "":
          globalstemp.write("\n    RPORT = 8888")
          writelog.write("\n"+logtime + " RPORT: 8888")
      elif rport.isdigit() is True:
          globalstemp.write("\n    RPORT = %s" % rport)
          writelog.write("\n"+logtime + " RPORT: %s" % rport)
          print("[+] remote port saved.")
      else:
          print("[!] invalid port!")
          os.system("rm %s" % writeglobals)
          self.globalconfig()

      pport = raw_input("proxy port %s " % (self.header))
      if pport == "":
          globalstemp.write("\n    PPORT = 8080")
          writelog.write("\n"+logtime + " PPORT: 8080")
      elif pport.isdigit() is True:
          globalstemp.write("\n    PPORT = %s" % pport)
          writelog.write("\n"+logtime + " PPORT: %s" % pport)
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

      print("\n[ Set Options ]\nIf any of these options don't apply to you, press [enter] to skip.")

      if os.path.exists(PayloadTemplate) is True:
          print("Enter a name for your Intersect script. The finished script will be placed in the Scripts directory. Do not include Python file extension.")
          name = raw_input("%s " % (self.header))
          script = (currentloc+"/Scripts/%s.py" % name)

          if name == "":
              script = (currentloc+"/Scripts/Intersect.py")
              shutil.copy2(PayloadTemplate, script)
              newpayload = open(script, "a")
              writelog.write("\n"+logtime+ " Script named: Intersect.py")

          else:

              if os.path.exists(script) is True:
                  print("[!] The filename you entered all ready exists. Enter a new filename")
                  writelog.write("\n"+logtime+" [Error] User selected invalid script name.")
                  self.chooseName()
              else: 
                  shutil.copy2(PayloadTemplate, script)
                  newpayload = open(script, "a")
                  print("Script will be saved as %s" % script)
                  writelog.write("\n"+logtime + " Script named: %s " % script)

      else:
          print("[!] Payload template cannot be found!")
          writelog.write("\n"+logtime+" [Error] Cannot find the base Intersect template.")
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
      writelog.write("\n"+logtime + " Script saved to: %s \n" % script)
      sys.exit(0)

      
  def MakeUsage(self, moduleList):  # Clean up this function
      usage = (currentloc+"/Junk/usage")
      descriptions = []

      for module in moduleList:
          if os.path.exists(ModulesDir+module) is True:
              info = open(ModulesDir+module)
              for line in info:
                  if "@short" in line:
                      split = line.split(":")
                      des = split[1]
                      des = des.rstrip("\n")
                      short = module[0]
                      descriptions.append("    -%s    --%s       %s" % (short, module, des))


          elif os.path.exists(CustomDir+module) is True:
              info = open(CustomDir+module)
              for line in info:
                  if "@short" in line:
                      split = line.split(":")
                      des = split[1]
                      des = des.rstrip("\n")
                      short = module[0]
                      descriptions.append("    -%s    --%s       %s" % (short, module, des))

          else:
              descriptions.append("    -%s    --%s" % (short, module))

      writeusage = open(usage, "a")

      writeusage.write("\n\ndef usage():")
      writeusage.write("\n    print('============================================')")
      writeusage.write("\n    print('   intersect 2.5 | custom version     ')")
      writeusage.write("\n    print('      http://bindshell.it.cx | ohdae')")
      writeusage.write("\n    print(' Modules:')")

      for item in descriptions:
          writeusage.write("\n    print('%s')" % (str(item)))

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

