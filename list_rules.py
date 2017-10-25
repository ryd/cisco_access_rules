#!/usr/bin/python
#
# Copyright by Jens (ryd) Muecke under GPLv3.

import sys
import glob
import socket
import struct

# model
class AccessRule:
    def __init__(self, proto, src, src_port, dest, dest_port, info="", hit=0, raw=None):
        self.proto = proto
        self.src = src
        self.src_port = src_port
        self.dest = dest
        self.dest_port = dest
        self.info = info
        self.hit = hit
        self.raw = raw
        
    def is_in_src(self, ip_number):
        return self.src[0] <= ip_number and self.src[1] >= ip_number
    
    def is_in_dest(self, ip_number):
        return self.dest[0] <= ip_number and self.dest[1] >= ip_number

# helper
def get_ip_number(ip):
    try:
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]
    except:
        return None

def get_number_ip(ip):
    return socket.inet_ntoa(struct.pack('!L', ip))

def get_min_max_ip(ip, mask=None):
    full = 4294967295
    n_ip = get_ip_number(ip)
    if n_ip == None:
        return None
    if mask == None:
        return (n_ip, n_ip)
    n_mask = get_ip_number(mask)
    n_min = n_ip & n_mask
    n_nmask = full - n_mask
    n_max = n_min + n_nmask
    return (n_min, n_max)

# logic
def process_line(s, d=0):
    debug = ""
    p = s.split(" ")
    pos = 1
    debug += "Access-List: %s ," % p[pos]
    pos += 1
    if p[pos] != "line":
        print("[E] cannot parse (line check - %s): %s" % (p[pos], s))
        return None
    pos += 1
    debug += "Rule line: %s ," % p[pos]
    pos += 1
    if p[pos] not in ["extended", "standard"] or p[pos+1] != "permit":
        print("[E] cannot parse (extended permit - %s %s): %s" % (p[pos], p[pos+1], s))
        return None
    if p[pos] == "standard":
        print("[W] ignore standard rule for now")
        return None
    pos += 2
    if p[pos] not in ["tcp", "udp", "icmp", "ip", "gre"]:
        print("[E] cannot parse (protocol - %s): %s" % (p[pos], s))
        return None
    proto = p[pos]
    pos += 1
    debug += "Protocol: %s ," % proto
    
    ## source
    ip_from = (0, 4294967295)
    src_port = (1, 65535)
    ip_to = (0, 4294967295)
    dest_port = (1, 65535)
    if proto in ["tcp", "udp", "icmp", "ip", "gre"] and p[pos] == "host":
        ip_from = get_min_max_ip(p[8])
        if ip_from == None:
            print("[E] cannot parse (ip from): %s" %s)
            return None
        pos += 2
        if proto in ["tcp", "udp"] and p[pos] == "eq":
            src_port = (p[pos+1], p[pos+1])
            pos += 2
        if proto in ["tcp", "udp"] and p[pos] == "range":
            src_port = (p[pos+1], p[pos+2])
            pos += 3
    elif proto in ["tcp", "udp", "icmp", "ip"] and p[pos] == "any":
        pos += 1
        if proto in ["tcp", "udp"] and p[pos] == "eq":
            src_port = (p[pos+1], p[pos+1])
            pos += 2
        if proto in ["tcp", "udp"] and p[pos] == "range":
            src_port = (p[pos+1], p[pos+2])
            pos += 3
    elif proto in ["ip", "tcp", "udp"] and get_min_max_ip(p[pos], p[pos+1]) != None:
        ip_from = get_min_max_ip(p[pos], p[pos+1])
        pos += 2
        if proto in ["tcp", "udp"] and p[pos] == "eq":
            src_port = (p[pos+1], p[pos+1])
            pos += 2
        if proto in ["tcp", "udp"] and p[pos] == "range":
            src_port = (p[pos+1], p[pos+2])
            pos += 3
    else:
        print("[E] cannot parse (source - %s %s): %s" % (proto, p[pos], s))
        return None
    
    ## destination
    if proto in ["tcp", "udp", "icmp", "ip", "gre"] and p[pos] == "host":
        ip_to = get_min_max_ip(p[pos+1])
        if ip_to == None:
            print("[E] cannot parse (ip to): %s" %s)
            return None
        pos += 2
        if proto in ["tcp", "udp"] and p[pos] == "eq":
            dest_port = (p[pos+1], p[pos+1])
            pos += 2
        if proto in ["tcp", "udp"] and p[pos] == "range":
            dest_port = (p[pos+1], p[pos+2])
            pos += 3
        if proto in ["icmp"] and p[pos] in ["echo-reply", "echo"]:
            dest_port = (1, 1)
            pos += 1
            if p[pos] == "0":
                # ignore
                pos += 1
    elif proto in ["tcp", "udp", "icmp", "ip"] and p[pos] == "any":
        pos += 1
        if proto in ["tcp", "udp"] and p[pos] == "eq":
            dest_port = (p[pos+1], p[pos+1])
            pos += 2
        if proto in ["tcp", "udp"] and p[pos] == "range":
            dest_port = (p[pos+1], p[pos+2])
            pos += 3
        if proto in ["icmp"] and p[pos] in ["echo-reply", "echo"]:
            dest_port = (1, 1)
            pos += 1
            if p[pos] == "0":
                # ignore
                pos += 1
    elif proto in ["ip", "tcp", "udp", "icmp"] and get_min_max_ip(p[pos], p[pos+1]) != None:
        ip_to = get_min_max_ip(p[pos], p[pos+1])
        pos += 2
        if proto in ["tcp", "udp"] and p[pos] == "eq":
            dest_port = (p[pos+1], p[pos+1])
            pos += 2
        if proto in ["tcp", "udp"] and p[pos] == "range":
            dest_port = (p[pos+1], p[pos+2])
            pos += 3
        if proto in ["icmp"] and p[pos] in ["echo-reply", "echo"]:
            dest_port = (1, 1)
            pos += 1
            if p[pos] == "0":
                # ignore
                pos += 1
    elif proto in ["ip"] and p[pos] == "any4":
        pos += 1
    else:
        print("[E] cannot parse (destination): %s" %s)
        return None
    
    if not p[pos].startswith("(hitcnt="):
        print("[E] cannot parse (not hitcount - %d %s): %s" % (pos, p[pos], s))
        return None
    hitcount = int(p[pos].split("=")[1][:-1])
    debug += "hitcount: %d" % hitcount
    
    if d:
        print(debug)
    return AccessRule(proto, ip_from, src_port, ip_to, dest_port, debug, hitcount, s)

def parse_config(rule_files):
	counter = 0
	err_counter = 0
	rules = []
	for filename in rule_files:
	    print("[*] processing %s" % filename)
	    f = open(filename, 'r')
	    lines = f.readlines()
	    f.close()
	    for line in lines:
	        # pre filter
	        l = line.strip()
	        if len(l) < 10:
	            continue
	        if not l.startswith("access-list"):
	            continue
	        if "permit" not in l:
	            continue
	        counter += 1
	        rule = process_line(l)
	        if rule == None:
	            err_counter += 1
	        else:
	            rules.append(rule)
	print("[*] %d rules processed." % counter)
	print("[*] %d rules failed." % err_counter)

	return rules


# programm functions
def help():
	banner()
	print("")
	print("This tool parse access list in text format and filter")
	print("all rules affected by this rule.")
	print("")
	print("This tool is written for auditors reviewing and monitoring")
	print("access rules in CISCO environments.")
	print("")
	print("Copyright by Jens (ryd) Muecke under GPLv3.")
	print("")
	print("Example:")
	print("        %s <IP> <list of text files>" % sys.argv[0])
	print("        %s 10.0.0.1 *.log" % sys.argv[0])
	print("")
	print("Feedback:")
	print("			j.muecke@kryptonsecurity.com")
	print("")

def banner():
	print("CISCO Access List parser and filter")


# filter one
def print_src(ip, rules):
	print("[*] Systems to reach from %s" % get_number_ip(ip))
	for r in rules:
		if r.is_in_src(ip):
			print(r.raw)

# filter two
def print_dest(ip, rules):
	print("[*] %s can be reach by" % get_number_ip(ip))
	for r in rules:
		if r.is_in_dest(ip):
			print(r.raw)

def main():
	ip = get_ip_number(sys.argv[1])
	files = sys.argv[2:]

	rule_files = []
	for i in files:
	    ls = glob.glob(i)
	    for j in ls:
	        rule_files += glob.glob(j)

	rules = parse_config(rule_files)

	print_dest(ip, rules)
	print_src(ip, rules)

if __name__ == "__main__":
	if len(sys.argv) < 3:
		help()
	else:
		main()


