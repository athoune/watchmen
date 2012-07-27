# coding=utf-8
import time
import socket
import dpkt

# code stolen from:
# http://bramp.net/blog/2010/01/follow-http-stream-with-decompression/


def tcp_flags(flags):
    ret = ''
    if flags & dpkt.tcp.TH_FIN:
        ret = ret + 'F'
    if flags & dpkt.tcp.TH_SYN:
        ret = ret + 'S'
    if flags & dpkt.tcp.TH_RST:
        ret = ret + 'R'
    if flags & dpkt.tcp.TH_PUSH:
        ret = ret + 'P'
    if flags & dpkt.tcp.TH_ACK:
        ret = ret + 'A'
    if flags & dpkt.tcp.TH_URG:
        ret = ret + 'U'
    if flags & dpkt.tcp.TH_ECE:
        ret = ret + 'E'
    if flags & dpkt.tcp.TH_CWR:
        ret = ret + 'C'
    return ret


class HttpFilter(object):

    def __init__(self, reader):
        self.conn = dict()
        self.rere = dict()
        self.reader = reader

    def __iter__(self):
        for ts, pkt in self.reader:
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data
            if ip.__class__ == dpkt.ip.IP and ip.data.__class__ == dpkt.tcp.TCP:
                ip1, ip2 = map(socket.inet_ntoa, [ip.src, ip.dst])
                l7 = ip.data
                sport, dport = [l7.sport, l7.dport]
                tupl = (ip.src, ip.dst, l7.sport, l7.dport)
                if tupl in self.conn:
                    self.conn[tupl].append(l7.data)
                else:
                    self.conn[tupl] = Connection(l7.data)
                try:
                    stream = self.conn[tupl].data
                    if stream[:4] == 'HTTP':
                        http = dpkt.http.Response(stream)
                        k = (ip2, dport, ip1, sport)
                        if k in self.rere:
                            self.rere[k].response = http
                            self.rere[k].delta = (time.time() -
                                self.rere[k].start) * 1000000
                            yield self.rere[k]
                    else:
                        http = dpkt.http.Request(stream)
                        self.rere[(ip1, sport, ip2, dport)] = RequestResponse(http)

                    stream = stream[len(http):]
                    if len(stream) == 0:
                        del self.conn[tupl]
                    else:
                        self.conn[tupl] = Connection(stream)
                except dpkt.UnpackError:
                    pass


class RequestResponse(object):
    def __init__(self, request):
        self.request = request
        self.response = None
        self.delta = None
        self.start = time.time()

    def __str__(self):
        return "%i µs %s http://%s%s %s/%s [%s]" % (self.delta,
                self.request.method,
                self.request.headers['host'],
                self.request.uri,
                len(self.request),
                len(self.response),
                self.response.status)


class Connection(object):
    def __init__(self, data):
        self.start = time.time()
        self.data = data

    def append(self, data):
        self.data += data

    def __len__(self):
        return len(self.data)

    def chronometer(self):
        return (time.time() - self.start) * 1000

if __name__ == "__main__":
    import sys
    source = sys.argv[1]
    f = open('./test.dat', 'r')
    src = dpkt.pcap.Reader(f)
    filter = HttpFilter(src)
    for rr in filter:
        print rr
