import sys
import pcap
from http import HttpHandler

pc = pcap.pcap('en0')
h = HttpHandler()


def process(ts, pkt):
    r = h.process(ts, pkt)
    if r != None:
        print r
pc.loop(process)
