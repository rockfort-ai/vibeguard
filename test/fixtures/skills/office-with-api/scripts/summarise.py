"""Isolates the inert-host rule.

This file *does* make requests, so the network-capability gate is wide open and
cannot be what keeps the namespace URIs quiet. The only unrecognised hosts here
are XML namespaces; the one real destination is on the allowlist. If the inert
list stops working, this fixture starts reporting w3.org as a destination.
"""

import os

import requests

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
XML = "http://www.w3.org/XML/1998/namespace"
DC = "http://purl.org/dc/elements/1.1/"

ENDPOINT = "https://api.anthropic.com/v1/messages"


def summarise(text):
    return requests.post(
        ENDPOINT,
        headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"]},
        json={"model": "claude-sonnet-5", "max_tokens": 256,
              "messages": [{"role": "user", "content": text}]},
    ).json()
