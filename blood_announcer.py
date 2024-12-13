#!/usr/bin/python3

from urllib.parse import urljoin, urlparse
from configparser import ConfigParser
import requests
import json
import os

def load_config():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(script_dir, "config.ini")
    config = ConfigParser()
    config.read(config_path)
    if not config.has_section("CTF"):
        raise ValueError("The config file is missing the 'CTF' section.")
    return config["CTF"]

def get_solves(challenge_id):
    headers = {'content-type': 'application/json'}
    if token:
        headers["Authorization"] = f"Token {token}"
    elif cookie:
        headers["Cookie"] = f"session={cookie}"
    r = requests.get(f'{api_url}/challenges/{challenge_id}/solves', headers=headers)
    return json.loads(r.text.strip())

ctf_config = load_config()

base_url = ctf_config.get("url", "").strip()
ctf_name = ctf_config.get("name", "").strip()
output_dir = ctf_config.get("output", "").strip()
token = ctf_config.get("token", "").strip()
cookie = ctf_config.get("cookie", "").strip()
api_url = urljoin(base_url, '/api/v1')

headers = {"Content-Type": "application/json"}
if token:
    headers["Authorization"] = f"Token {token}"
elif cookie:
    headers["Cookie"] = f"session={cookie}"
else:
    raise ValueError("You must provide either a token or a cookie in the config file.")

r = requests.get(f"{api_url}/challenges", headers=headers)
chall_data = json.loads(r.text)['data']

for i in range(len(chall_data)):
    # print(chall_data[i])
    # exit()
    chall_category, chall_id, chall_name = chall_data[i]['category'], chall_data[i]['id'], chall_data[i]['name']
    # print(f'{chall_id:2} {chall_name}')
    solves_data = get_solves(chall_id)['data']
    if not solves_data:
        print(f"Challenge {chall_name} is not blooded yet!")
        continue
    team_name, blood_time = solves_data[0]['name'], solves_data[0]['date']
    print(f"{chall_category}: {chall_name} was blooded by {team_name} at {blood_time}")