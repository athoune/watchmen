#!/usr/bin/env python
from optparse import OptionParser
import pcap
from http import HttpHandler

parser = OptionParser()
parser.add_option("-i", "--interface", dest="interface",
    help="Interface to listen.", default=None)
parser.add_option("-p", "--port", dest="port", default=80, help="Port")
parser.add_option("-H", "--host", dest="host", help="Host")
parser.add_option("-f", "--filter", dest="filter", help="BPF filter")

(options, args) = parser.parse_args()

pc = pcap.pcap(options.interface)
filter = "tcp "
filters = []
if options.port:
    filters.append("dst port %i or src port %i" % (options.port, options.port))
if options.host:
    filters.append("dst host %s or src host %s" % (options.host, options.host))
filter += " and ".join(filters)
if options.filter:
    filter += " %s" % options.filter

print "BPF filter:", filter
pc.setfilter(filter)

h = HttpHandler()


def process(ts, pkt):
    r = h.process(ts, pkt)
    if r is not None:
        print r

pc.loop(process)
