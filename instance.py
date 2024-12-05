#!/usr/bin/python3

from configparser import ConfigParser
from urllib.parse import urljoin
from pwn import args
import requests
import json
import sys
import os

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
csrf_token = ctf_config.get("csrf_token", "").strip()

api_url = urljoin(base_url, '/api/v1')

def start_instance(challenge_id):
    headers = {'content-type': 'application/json'}
    if token:
        headers["Authorization"] = f"Token {token}"
    elif cookie:
        headers["Cookie"] = f"session={cookie}"
    headers["Csrf-Token"] = csrf_token
    data = {'chal_id': challenge_id}
    r = requests.post(f'{base_url}/containers/api/request', headers=headers, json=data)
    return json.loads(r.text.strip())

def stop_instance(challenge_id):
    headers = {'content-type': 'application/json'}
    if token:
        headers["Authorization"] = f"Token {token}"
    elif cookie:
        headers["Cookie"] = f"session={cookie}"
    headers["Csrf-Token"] = csrf_token
    data = {'chal_id': challenge_id}
    r = requests.post(f'{base_url}/containers/api/stop', headers=headers, json=data)
    return json.loads(r.text.strip())

if sys.argv[-1].lower() == 'stop' or sys.argv[-1].lower() == 'kill' or \
    args.STOP or args.KILL:
    stop_state = stop_instance(<instance-id>)
    print(json.dumps(stop_state))
    exit()

instance_data = start_instance(<instance-id>)
# print(json.dumps(instance_data))

if 'error' in instance_data.keys():
    print(f'error: {instance_data["error"]}')
    exit()
elif instance_data['status'] == 'already_running':
    print("Instance is already running")
elif instance_data['status'] == 'created':
    print("Instance is created")

if 'connect' in instance_data.keys():
    if instance_data['connect'] == 'tcp':
        print(f"nc {instance_data['hostname']} {instance_data['port']}")
    elif instance_data['connect'] == 'web':
        print(f"http://{instance_data['hostname']}:{instance_data['port']}/")
        print(f"https://{instance_data['hostname']}:{instance_data['port']}/")
    else:
        print("Unkown connect type")
        print(json.dumps(instance_data))