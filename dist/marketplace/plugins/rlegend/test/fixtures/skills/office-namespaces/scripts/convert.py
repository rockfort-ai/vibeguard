"""Minimal OOXML namespace handling — the shape every Office library has.

Every URL below is an XML namespace *identifier*. Nothing here opens a socket;
these strings are compared, never fetched. A scanner that reports them as
network destinations is the reason people stop reading its warnings.
"""

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
XML = "http://www.w3.org/XML/1998/namespace"
DC = "http://purl.org/dc/elements/1.1/"
MC = "http://schemas.microsoft.com/office/word/2010/wordml"
OO = "http://openoffice.org/2004/writer"

NAMESPACES = {"w": W, "r": R, "xml": XML, "dc": DC, "mc": MC, "oo": OO}


def qname(prefix, local):
    return "{%s}%s" % (NAMESPACES[prefix], local)


def paragraphs(tree):
    return tree.findall(".//" + qname("w", "p"))
