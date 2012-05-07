#!/usr/bin/python




# Pretty colors
reset = '\x1b[0m'    # reset all colors to white on black
bold = '\x1b[1m'     # enable bold text
uline = '\x1b[4m'    # enable underlined text
nobold = '\x1b[22m'  # disable bold text
nouline = '\x1b[24m' # disable underlined text
red = '\x1b[31m'     # red text
green = '\x1b[32m'   # green text
blue = '\x1b[34m'    # blue text
cyan = '\x1b[36m'    # cyan text
white = '\x1b[37m'   # white text (use reset unless it's only temporary)

def warning(msg):
    print("%s%s[%s!%s]%s %s " % (bold, red, white, red, reset, msg))
          

def status(msg):
    print("%s%s[%s~%s]%s %s " % (bold, white, blue, white, reset, msg))


def title(msg):
    print("%s %s %s" % (uline, msg, reset))
    

def info(msg):
    print("%s[*]%s %s" % (bold, reset, msg))

title("Title Information:\n\n")

status("Status Message\n\n")

info("Info Update\n\n")

warning("Warning Message!")


