#!/usr/bin/python
#create valid ipv4 address


def valid_ip(ip):
    parts = ip.split('.')
    return (
        len(parts) == 4
        and all(part.isdigit() for part in parts)
        and all(0 <= int(part) <= 255 for part in parts)
        )

ip_address = raw_input("enter ip to check: ")
if valid_ip(ip_address) is True:
    print ("valid ip!")
else:
    print ("no!")


