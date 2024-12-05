#!/usr/bin/python3

from configparser import ConfigParser
from urllib.parse import urljoin
from pwn import *
import requests
import json
import sys

pf = log.success #replace with print if you don't have pwntools installed. pf = print function. we will only use this while printing hint

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

def get_hint_ids(challenge_id):
    headers = {'content-type': 'application/json'}
    if token:
        headers["Authorization"] = f"Token {token}"
    elif cookie:
        headers["Cookie"] = f"session={cookie}"
    r = requests.get(f'{api_url}/challenges/{challenge_id}', headers=headers)
    return json.loads(r.text.strip())

def get_hint(hint_id):
    headers = {'content-type': 'application/json'}
    if token:
        headers["Authorization"] = f"Token {token}"
    elif cookie:
        headers["Cookie"] = f"session={cookie}"
    r = requests.get(f'{api_url}/hints/{hint_id}', headers=headers)
    return json.loads(r.text.strip())

hints = get_hint_ids(<chall_id>)['data']['hints']

if not hints:
    print("No hints released yet. Come back later.")
    exit()

print(f"{len(hints)} hints have released.")
for hint in hints:
    if hint['cost'] == 0:
        hint_content = get_hint(hint['id'])['data']['content']
        pf(f'Hint: {hint_content}')
    if hint['cost'] > 0:
        print(f"[!] Paid hint is availiable for {hint['cost']} points.")
