Watchmen
========

Watch HTTP traffic.

You can use it postmortem with tcpdump data, and later,
you will be able to use it with live data.

Install
-------

This project use two python's libraries, dpkt for reading ethernet packets,
and pcap to spy the ethernet flow on your computer. This libraries are painful
to install, pip doesn't works, and with a Mac, it's worst (it works with 10.8,
not with 10.6). But, there is nice packages for Debian and Ubuntu.

    sudo aptitude install python-dpkt python-pcap

Test samples
------------

    sudo tcpdump -n -w test.dat -i en0 "tcp port 80"

Test application
----------------

You need test.dat samples data.

    python http.py

Licence
-------

[The BSD 2 Clauses Licence](http://opensource.org/licenses/bsd-license.php)
