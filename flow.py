#!/usr/bin/env python
from optparse import OptionParser
import gzip
from cStringIO import StringIO
import json
import pcap
from http import HttpHandler

parser = OptionParser()
parser.add_option("-i", "--interface", dest="interface",
        help="Interface to listen.", default=None)
parser.add_option("-p", "--port", dest="port", default=80, type="int",
        help="Port")
parser.add_option("-H", "--host", dest="host", help="Host")
parser.add_option("-f", "--filter", dest="filter", help="BPF filter")
parser.add_option("-s", "--slow", dest="slow", type="int",
        help="filter call slower than")
parser.add_option("-P", "--pretty", dest="pretty", action="append", help="Pretty print")

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

h = HttpHandler(options)

mimes = {
    "json": "application/json"
        }


def process(ts, pkt):
    r = h.process(ts, pkt)
    if r is not None:
        if options.slow and r.delta < options.slow:
            return
        print r
        if r.response.headers.get('content-encoding') == 'gzip':
            body = gzip.GzipFile(fileobj=StringIO(r.response.body)).read()
        else:
            body = r.response.body
        if r.response.headers.get('content-type') == mimes['json']:
            #print r.response.headers
            try:
                print json.dumps(json.loads(body), indent=2, sort_keys=True)
            except Exception as e:
                print e
                print body

pc.loop(process)
