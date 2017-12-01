#!/usr/bin/python3
# Need to run as root on 16.04 make sure you fill out all field
import os
import socket
import fcntl
import struct
import re
import subprocess

# INTERFACE
ifaces=os.listdir('/sys/class/net/')
for intf in ifaces:
    if intf[0]=='e':
        iface = intf
        break
# IP ADDRESS
address=socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                                     0x8915,struct.pack('256s', bytes(iface[:15], 'utf-8')))[20:24])
# IP NETMASK
netmask=socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                             35099,struct.pack('256s', bytes(iface[:15], 'utf-8')))[20:24])
# IP GATEWAY
gateway=""
with open("/proc/net/route") as fh:
    for line in fh:
        fields = line.strip().split()
        if fields[1] != '00000000' or not int(fields[3], 16) & 2:
            continue
        gateway = ( socket.inet_ntoa(struct.pack("<L", int(fields[2], 16))))
# HOSTNAME
hostname=open("/etc/hostname").read().strip()
# DOMAIN
dns_domain=socket.getfqdn().strip().split(".",1)
dns_domain.append("")
dns_domain = dns_domain[1].strip()
# DNS SERVERS
dns_server1 = ""
dns_server2 = ""
dnsf=open("/etc/resolv.conf")
dns_server1=""
dns_server2=""
for line in dnsf:
    curdns = re.subn(r"nameserver ([0-9]+(?:\.[0-9]+){3}).*", r"\1", line)
    if dns_server1 == "" and curdns[1]:
        dns_server1 = curdns[0].strip()
    elif dns_server2 == "" and curdns[1]:
        dns_server2 = curdns[0].strip()
    elif dns_server1 == "" or dns_server2 == "":
        continue
    else:
        break

s = input("Enter interface name ("+iface+") : ")
if s != "" : iface = s.strip()
s = input("Enter IP address ("+address+") : ")
if s != "" : address = s.strip()
s = input("Enter IP netmask ("+netmask+") : ")
if s != "" : netmask = s.strip()
s = input("Enter IP gateway ("+gateway+") : ")
if s != "" : gateway = s.strip()
s = input("Enter hostname ("+hostname+") : ")
if s != "" : hostname = s.strip()
s = input("Enter DNS domain ("+dns_domain+") : ")
if s != "" : dns_domain = s.strip()
s = input("Enter primary DNS ("+dns_server1+") : ")
if s != "" :
    dns_server1 = s.strip()
else:
    dns_server1 = "8.8.8.8"
s = input("Enter secondary DNS ("+dns_server2+") : ")
if s != "" : dns_server2 = s.strip()
dns_servers = (dns_server1 + " " + dns_server2).strip()

intfile = "auto lo\n"
intfile += "iface lo inet loopback\n\n"
intfile += "auto " + iface + "\n"
intfile += "iface " + iface + " inet static\n"
intfile += "address " + address + "\n"
intfile += "netmask " + netmask + "\n"
intfile += "gateway " + gateway + "\n"
intfile += "dns-nameservers " + dns_servers + "\n"
intfile += "dns-search " + dns_domain + "\n"

print(intfile)

hostsfile = address+"\t"+hostname+"."+dns_domain+"\t"+hostname+"\n"
hostsfile += "127.0.1.1\t"+hostname+"."+dns_domain+"\t"+hostname+"\n"
hostsfile +=  "127.0.0.1\tlocalhost\n"
hostsfile += "\n::1     localhost ip6-localhost ip6-loopback\n"
hostsfile += "ff02::1 ip6-allnodes\n"
hostsfile += "ff02::2 ip6-allrouters\n"

print(hostsfile)

open("/etc/hostname", 'w').write(hostname+"\n")
open("/etc/hosts", 'w').write(hostsfile)
open("/etc/network/interfaces", 'w').write(intfile)

subprocess.call(["ip","addr","flush",iface])
subprocess.call(["hostname",hostname])
subprocess.call(["systemctl","restart","networking.service"])
