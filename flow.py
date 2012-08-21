#!/usr/bin/env python
from optparse import OptionParser
import gzip
from cStringIO import StringIO
import json

from http import HttpHandler
from csv import CSVFile

parser = OptionParser()
parser.add_option("-F", "--file", dest="file",
                  help="Open a wireshark dump file", default=None)
parser.add_option("-i", "--interface", dest="interface",
                  help="Interface to listen.", default=None)
parser.add_option("-p", "--port", dest="port", default=80, type="int",
                  help="Port")
parser.add_option("-H", "--host", dest="host", help="Host")
parser.add_option("-f", "--filter", dest="filter", help="BPF filter")
parser.add_option("-s", "--slow", dest="slow", type="int",
                  help="filter call slower than")
parser.add_option("-P", "--pretty", dest="pretty", action="append",
                  help="Pretty print")
parser.add_option("-c", "--csv", dest="csv", help="Write data to a csv file")

(options, args) = parser.parse_args()

h = HttpHandler(options)

mimes = {
    "json": "application/json",
    "txt": "text/plain"}

if options.csv:
    writer = CSVFile(open(options.csv, 'a'))


def process(ts, pkt):
    r = h.process(ts, pkt)
    if r is not None:
        if options.slow and r.delta < options.slow:
            return
        print r
        if options.csv:
            writer.add_line(
                r.start,
                r.request.method,
                r.request.headers['host'],
                r.request.uri,
                str(len(r.request)),
                str(len(r.response)),
                r.response.status,
                r.response.headers.get('content-type', 'unknown').split(';')[0]
                )
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
        if r.response.headers.get('content-type') == mimes['txt']:
            print body

if options.file is None:
    import pcap
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
    pc.loop(process)
else:
    import dpkt
    f = open(options.file, 'r')
    src = dpkt.pcap.Reader(f)
    for ts, pkt in src:
        process(ts, pkt)
