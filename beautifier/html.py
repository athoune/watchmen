from lxml import etree
from cStringIO import StringIO
from pygments import highlight
from pygments.lexers import HtmlLexer
from pygments.formatters import Terminal256Formatter


def parse(txt):
    parser = etree.HTMLParser()
    tree = etree.parse(StringIO(txt), parser)
    indent = etree.tostring(tree.getroot(), pretty_print=True, method="html")  # FIXME
    return highlight(indent, HtmlLexer(), Terminal256Formatter())
