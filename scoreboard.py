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

def get_score_board(api_url):
    headers = {}
    if token:
        headers["Authorization"] = f"Token {token}"
    elif cookie:
        headers["Cookie"] = f"session={cookie}"
    r = requests.get(f'{api_url}/scoreboard', headers=headers)
    data = r.text
    with open('scoreboard.txt', 'w') as f:
        f.write(data)
    return json.loads(data)['data']

def print_team_data(data):
    try:
        limit = int(sys.argv[1])
    except:
        limit = len(data)
    max_name_len = max(len(team["name"]) for team in data)
    if limit > 0:
        if limit > len(data):
            limit = len(data)
        for i in range(limit):
            print(f'{data[i]["pos"]:>2} {data[i]["name"]:<{max_name_len}} {data[i]["score"]:>4}')
    elif limit < 0:
        if abs(limit) > len(data):
            limit = -len(data)
        for i in range(limit, 0):
            print(f'{data[i]["pos"]:>2} {data[i]["name"]:<{max_name_len}} {data[i]["score"]:>4}')
    else:
        for record in data:
            print(f'{record["pos"]:>2} {record["name"]:<{max_name_len}} {record["score"]:>4}')

sc = get_score_board(api_url)
print_team_data(sc)
