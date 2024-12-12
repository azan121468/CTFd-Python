#!/usr/bin/python3

from configparser import ConfigParser
from urllib.parse import urljoin
import requests
import json
import sys
import os

def load_config():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(script_dir, "config.ini")
    config = ConfigParser()
    config.read(config_path)
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

def get_team_id(team_name):
    headers = {}
    if token:
        headers["Authorization"] = f"Token {token}"
    elif cookie:
        headers["Cookie"] = f"session={cookie}"
    r = requests.get(f'{api_url}/scoreboard', headers=headers)
    data = json.loads(r.text)['data']
    for i in data:
        if team_name == i['name']:
            return int(i['account_id'])


def get_solves(team_id):
    # headers = {"Content-Type": "application/json"}
    headers = {}
    if token:
        headers["Authorization"] = f"Token {token}"
    elif cookie:
        headers["Cookie"] = f"session={cookie}"

    r = requests.get(f'{api_url}/teams/{team_id}/solves', headers=headers)
    data = json.loads(r.text)
    return data

team_name = sys.argv[1]
team_id = get_team_id(team_name)
out = get_solves(team_id)

for i in range(len(out['data'])):
    x = out['data'][i]

    chall_name = x['challenge']['name']
    chall_category = x['challenge']['category']

    team_name = x['team']['name']
    user_name = x['user']['name']

    print(f'{user_name} @ {team_name:30} {chall_category:30} {chall_name:30}')