from lxml import etree
from io import StringIO


def parse(txt):
    parser = etree.XMLParser(ns_clean=True)
    tree = etree.parse(StringIO(txt), parser)
    return etree.tostring(tree.getroot())
