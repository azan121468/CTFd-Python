#!/usr/bin/python3

from urllib.parse import urljoin
from configparser import ConfigParser
import requests
import json
import os
from multiprocessing import Pool, cpu_count

def load_config():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(script_dir, "config.ini")
    config = ConfigParser()
    config.read(config_path)
    if not config.has_section("CTF"):
        raise ValueError("The config file is missing the 'CTF' section.")
    return config["CTF"]

def get_solves(args):
    challenge_id, api_url, headers = args
    try:
        r = requests.get(f'{api_url}/challenges/{challenge_id}/solves', headers=headers)
        r.raise_for_status()
        return json.loads(r.text.strip())
    except Exception as e:
        return {"error": str(e), "challenge_id": challenge_id}

def process_challenge(challenge):
    chall_category, chall_id, chall_name = challenge['category'], challenge['id'], challenge['name']
    solves_data = get_solves((chall_id, api_url, headers)).get('data', [])

    if not solves_data:
        return f"Challenge {chall_name} is not blooded yet!"

    team_name, blood_time = solves_data[0]['name'], solves_data[0]['date']
    return f"{chall_category}: {chall_name} was blooded by {team_name} at {blood_time}"

if __name__ == "__main__":
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
    r.raise_for_status()
    chall_data = json.loads(r.text)['data']

    # Use multiprocessing to process challenges
    with Pool(cpu_count()) as pool:
        results = pool.map(process_challenge, chall_data)

    for result in results:
        print(result)