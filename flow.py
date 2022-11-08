#!/usr/bin/env python
from optparse import OptionParser
import gzip
from io import StringIO

from http import HttpHandler
from csv import CSVFile

parser = OptionParser()
parser.add_option(
    "-F", "--file", dest="file", help="Open a wireshark dump file", default=None
)
parser.add_option(
    "-i", "--interface", dest="interface", help="Interface to listen.", default=None
)
parser.add_option("-p", "--port", dest="port", default=80, type="int", help="Port")
parser.add_option("-H", "--host", dest="host", help="Host")
parser.add_option("-f", "--filter", dest="filter", help="BPF filter")
parser.add_option(
    "-s", "--slow", dest="slow", type="int", help="filter call slower than"
)
parser.add_option("-S", "--status", dest="status", help="Status code")
parser.add_option("--fast", dest="fast", help="Filter call faster than", type="int")
parser.add_option(
    "-P", "--pretty", dest="pretty", action="store_true", help="Pretty print"
)
parser.add_option("-c", "--csv", dest="csv", help="Write data to a csv file")
parser.add_option(
    "-m", "--mime", dest="mimes", help="Filter on mime type", action="append"
)

(options, args) = parser.parse_args()

h = HttpHandler(options)

mimes = {"json": "application/json", "txt": "text/plain", "html": "text/html"}

types = {}
for k in mimes:
    types[mimes[k]] = k

if options.csv:
    writer = CSVFile(open(options.csv, "a"))
    writer.add_line(
        "start",
        "time",
        "method",
        "host",
        "uri",
        "request_size",
        "response_size",
        "status",
        "content_type",
    )


def beautifier(format, txt):
    if format == "json":
        from beautifier.json import parse
    if format == "html":
        from beautifier.html import parse
    if format == "xml":
        from beautifier.xml import parse
    if format == "txt":
        from beautifier.txt import parse
    return parse(txt)


def process(ts, pkt):
    r = h.process(ts, pkt)
    if r is not None:
        if options.slow and r.delta < options.slow:
            return
        if options.fast and r.delta > options.fast:
            return
        content_type = r.response.headers.get("content-type", "").split(";")[0]
        if options.mimes is not None and content_type not in options.mimes:
            return
        if options.status:
            if options.status[0] == "-" and r.response.status == options.status[1:]:
                return
            if r.response.status != options.status:
                return
        print(r)
        if options.csv:
            writer.add_line(
                r.start,
                r.delta,
                r.request.method,
                r.request.headers["host"],
                r.request.uri,
                str(len(r.request)),
                str(len(r.response)),
                r.response.status,
                r.response.headers.get("content-type", "unknown").split(";")[0],
            )
        if r.response.headers.get("content-encoding") == "gzip":
            body = gzip.GzipFile(fileobj=StringIO(r.response.body)).read()
        else:
            body = r.response.body
        if content_type in list(mimes.values()):
            try:
                print(beautifier(types[content_type], body))
            except Exception as e:
                print("error", e)
                print(body)


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

    print("BPF filter:", filter)
    pc.setfilter(filter)
    pc.loop(process)
else:
    import dpkt

    f = open(options.file, "rb")
    src = dpkt.pcap.Reader(f)
    for ts, pkt in src:
        process(ts, pkt)
