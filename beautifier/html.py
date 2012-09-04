from lxml import etree
from cStringIO import StringIO


def parse(txt):
    parser = etree.HTMLParser()
    tree = etree.parse(StringIO(txt), parser)
    return etree.tostring(tree.getroot(), pretty_print=True, method="html")
