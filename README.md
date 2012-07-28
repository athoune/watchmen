Watchmen
========

Watch HTTP traffic.

You can use it postmortem with tcpdump data, and later,
you will be able to use it with live data.

Install
-------

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
