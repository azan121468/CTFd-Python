#!/usr/bin/python3

from configparser import ConfigParser
from urllib.parse import urljoin
import requests
import json
import sys
import os

def load_config():
    config = ConfigParser()
    config_file = os.path.join(r"<config-dir>", "config.ini")
    config.read(config_file)
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


def submit_flag(api_url, chall_id, flag):
    # headers = {"Content-Type": "application/json"}
    headers = {}
    if token:
        headers["Authorization"] = f"Token {token}"
    elif cookie:
        headers["Cookie"] = f"session={cookie}"
    data = {
        'challenge_id': chall_id,
        'submission': flag
    }

    r = requests.post(f'{api_url}/challenges/attempt', headers=headers, json=data)
    return json.loads(r.text)

if len(sys.argv) < 2:
    flag_submission = input('Enter the flag: ')
else:
    flag_submission = sys.argv[1]

out = submit_flag(api_url, <chall_id>, flag_submission)
print(out)

if 'Success' in json.dumps(out) or 'Correct' in json.dumps(out):
    if os.path.isfile('instance.py'):
        print("Stopping container")
        os.system("./instance.py kill")