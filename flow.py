#!/usr/bin/env python
from optparse import OptionParser
import pcap
from http import HttpHandler

parser = OptionParser()
parser.add_option("-i", "--interface", dest="interface",
    help="Interface to listen.", default=None)
parser.add_option("-f", "--filter", dest="filter",
    help="BPF filter")
(options, args) = parser.parse_args()

pc = pcap.pcap(options.interface)
if options.filter:
    pc.filter = options.filter

h = HttpHandler()


def process(ts, pkt):
    r = h.process(ts, pkt)
    if r != None:
        print r

pc.loop(process)
