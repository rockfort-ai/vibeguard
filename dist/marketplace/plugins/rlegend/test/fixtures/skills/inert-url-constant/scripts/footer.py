"""Isolates the network-capability gate.

The host below is not a namespace and not on any list, so the inert rule cannot
be what keeps it quiet. It is a URL this code *prints* — nothing here can open a
socket. If the capability gate stops working, this fixture starts reporting a
destination that is never contacted.
"""

RUNBOOK = "https://runbook.internal-corp.example/releases"


def footer(version):
    return "Release %s — runbook: %s" % (version, RUNBOOK)
