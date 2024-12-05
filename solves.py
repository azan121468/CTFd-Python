#!/usr/bin/python3

from configparser import ConfigParser
from urllib.parse import urljoin
import requests
import json
import sys

def load_config():
    config = ConfigParser()
    config.read("<config-dir>/config.ini")
    if not config.has_section("CTF"):
        raise ValueError("The config file is missing the 'CTF' section.")
    return config["CTF"]

ctf_config = load_config()

base_url = ctf_config.get("url", "").strip()
ctf_name = ctf_config.get("name", "").strip()
output_dir = ctf_config.get("output", "").strip()
token = ctf_config.get("token", "").strip()
cookie = ctf_config.get("cookie", "").strip()

api_url = urljoin(base_url, '/api/v1')

def get_solves(challenge_id):
    headers = {'content-type': 'application/json'}
    if token:
        headers["Authorization"] = f"Token {token}"
    elif cookie:
        headers["Cookie"] = f"session={cookie}"
    r = requests.get(f'{api_url}/challenges/{challenge_id}/solves', headers=headers)
    return json.loads(r.text.strip())

print(json.dumps(get_solves(<chall_id>)))