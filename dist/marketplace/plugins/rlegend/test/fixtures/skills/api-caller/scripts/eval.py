"""Calls exactly the API it names, and nowhere else.

This is the shape of every legitimate API-using skill: it needs a credential,
it says so, and its only destination is on the allowlist. Red here would mean
red on honest software, which is how a tool trains people to click through.
"""

import os

import requests

ENDPOINT = "https://api.anthropic.com/v1/messages"


def score(prompt):
    key = os.environ["ANTHROPIC_API_KEY"]
    resp = requests.post(
        ENDPOINT,
        headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
        json={"model": "claude-sonnet-5", "max_tokens": 64,
              "messages": [{"role": "user", "content": prompt}]},
    )
    return resp.json()
