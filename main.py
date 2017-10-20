#!/usr/bin/env python3
#import threading
import argparse
import time
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


parser = argparse.ArgumentParser()

parser.add_argument("-i", "--iface", required=True, help="interface", default=None)
#parser.add_argument("-t", "--timeout", required=False, help="timeout", default=3)
parser.add_argument("-c", "--count", required=False, help="pkt count", default=1000)
parser.add_argument("-f", "--infinity", required=False, help="infinite loop", action="store_true")

args = parser.parse_args()

i = 0
skip = 0
used_ip = []
begin = time.time()
while (args.infinity or i < int(args.count)):
    now = time.time()
    src = str(RandIP())
    if src in used_ip:
        skip += 1
        continue

    used_ip.append(src)

    frame = Ether(dst=str(RandMAC()),src=str(RandMAC()))/IP(src=src,dst=str(RandIP()))/UDP(sport=random.randint(1,0xffff),dport=random.randint(1,0xffff))
    sendp(frame,iface=args.iface,verbose=False)

    sys.stdout.write("\r {}".format(i))
    sys.stdout.write("." * skip)
    sys.stdout.write(" ")
    sys.stdout.write(str(now - begin))
    i += 1
    skip = 0
    begin = now
