#!/usr/bin/python3

import os
import re
import sys
import json
import shutil
import logging
import requests
import argparse
import unicodedata
from tqdm import tqdm
from configparser import ConfigParser
from urllib.parse import urljoin, urlparse

logging.basicConfig()
logging.root.setLevel(logging.INFO)

def load_config():
    config = ConfigParser()
    config.read("config.ini")
    if not config.has_section("CTF"):
        raise ValueError("The config file is missing the 'CTF' section.")
    return config["CTF"]

ctf_config = load_config()

base_url = ctf_config.get("url", "").strip()
ctf_name = ctf_config.get("name", "").strip()
output_dir = ctf_config.get("output", "").strip()
token = ctf_config.get("token", "").strip()
cookie = ctf_config.get("cookie", "").strip()
try:
    file_size_limit = int(ctf_config.get("fs_limit").strip())
except:
    print("Can't convert file size limit to integer. Ignoring!")

if not base_url or not ctf_name or not output_dir:
    raise ValueError("Missing required configuration: url, name, or output.")


def slugify(text):
    text = re.sub(r"[\/:*?\"<>|]", "_", text)  # Replace invalid filename characters with "_"
    text = re.sub(r"[\s]+", "-", text.strip())  # Replace spaces with dashes
    text = re.sub(r"[-]{2,}", "-", text)  # Remove consecutive dashes
    text = re.sub(r"^-|-$", "", text)  # Trim dashes from start/end
    return text  # Retain Unicode characters


def remove_already_downloaded_challs(challenges_data):
    downloaded_chall_ids = []
    for i, challenge in enumerate(challenges_data):
        path = os.path.join('.', challenge['category'], slugify(challenge['name']))
        if os.path.exists(path):
            print(f"Challenge already downloaded : {challenge['category']} @ {challenge['name']} ")
            downloaded_chall_ids.append(challenge['id'])
    
    # Remove already downloaded challenges from challenges_data
    challenges_data = [chall for chall in challenges_data if chall['id'] not in downloaded_chall_ids]

    return challenges_data


def fetch_challenges(api_url, headers):
    logging.info(f"Connecting to API: {api_url}")
    response = requests.get(f"{api_url}/challenges", headers=headers)
    return json.loads(response.text)


def fetch_challenge_details(session, api_url, challenge_id, headers):
    response = session.get(f"{api_url}/challenges/{challenge_id}", headers=headers)
    return json.loads(response.text)["data"]


def requires_instance(challenge):
    if challenge['type'] in ['dynamic_docker', 'container']:
        return True
    else:
        return False


def write_challenge_readme(challenge_dir, challenge):
    readme_path = os.path.join(challenge_dir, f"README_{os.urandom(3).hex()}.md")
    logging.info(f"Creating challenge readme: {challenge['name']} @ {challenge['category']}")
    with open(readme_path, "w", encoding="utf-8") as chall_readme:
        chall_readme.write(f"# {challenge['name']}\n\n")
        # chall_readme.write(f"## Challenge ID\n\n{challenge.get('id', 'N/A')}\n\n")
        chall_readme.write(f"## Description\n\n{challenge.get('description', 'N/A')}\n\n")
        chall_readme.write(f"## Points\n\n{challenge.get('value', 'N/A')}\n\n")
        
        chall_readme.write(f"## Requires Instance\n\n{'Yes' if requires_instance(challenge) else 'No'}\n\n")
        
        # Add files
        if challenge.get("files"):
            chall_readme.write("## Files\n\n")
            for file in challenge["files"]:
                file_name = urlparse(file).path.split("/")[-1]
                chall_readme.write(f"- {file_name}\n")
    return readme_path


limit_failed = {}
def download_file(session, challenge, challenge_dir, url, output_path, desc):
    try:
        global limit_failed
        response = session.get(url, stream=True)
        total_size_in_bytes = int(response.headers.get('content-length', 0))
        size_in_mb = total_size_in_bytes / (1024**2)
        if file_size_limit and size_in_mb > file_size_limit:
            print(f"File size limit exceeds. not Downloading. Size: {size_in_mb:.2f} MB")
            limit_failed[challenge['name']] = size_in_mb
            return
        progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True, desc=desc)

        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    progress_bar.update(len(chunk))
                    f.write(chunk)
        progress_bar.close()
    except KeyboardInterrupt:
        print("CTRL-C detected while downloading files. Exiting!")
        shutil.rmtree(challenge_dir)
        exit(-1)


def handle_challenge_files(session, challenge, challenge_dir, base_url):
    challenge_files = challenge.get("files", [])
    if challenge_files: # If challenge has files, we will put them in the challenge directory which we have created
        files_dir = challenge_dir
        '''Uncomment the lines given below, If you want to put downloaded files into the "files" folder instead of main folder'''
        # files_dir = os.path.join(challenge_dir, "files")
        os.makedirs(files_dir, exist_ok=True)

        for file in challenge.get("files", []):
            file_url = urljoin(base_url, file)
            file_name = urlparse(file_url).path.split("/")[-1]
            local_path = os.path.join(files_dir, file_name)
            download_file(session, challenge, challenge_dir, file_url, local_path, file_name)


def download_challenge(challenge):
    category = challenge['category']
    
    challenge_dir = os.path.join(output_dir, category, slugify(challenge["name"]))
    
    if os.path.exists(challenge_dir):
        print(f"Challenge already downloaded : {challenge['name']}")
        return
    
    os.makedirs(challenge_dir, exist_ok=True)

    write_challenge_readme(challenge_dir, challenge)
    handle_challenge_files(session, challenge, challenge_dir, base_url)

    if challenge['name'] in limit_failed.keys():
        shutil.rmtree(challenge_dir)
        return

    helper_folder = os.path.join(challenge_dir, f"helper_{os.urandom(3).hex()}")
    os.mkdir(helper_folder)

    write_submitter(helper_folder, challenge)
    write_solves(helper_folder, challenge)
    write_hints(helper_folder, challenge)

    if requires_instance(challenge):
        write_instancer(helper_folder, challenge)


def write_ctf_readme(output_dir, ctf_name, categories):
    readme_path = os.path.join(output_dir, "README.md")
    logging.info("Writing main CTF readme...")
    with open(readme_path, "w", encoding="utf-8") as ctf_readme:
        ctf_readme.write(f"# {ctf_name}\n\n")
        ctf_readme.write("## Challenges\n\n")
        
        first_category = True
        for category, challenges in categories.items():
            ctf_readme.write(f"### {category}\n")
            for chall in challenges:
                chall_path = f"challenges/{chall['category']}/{slugify(chall['name'])}/"
                ctf_readme.write(f"* [{chall['name']}](<{chall_path}>)\n")
            ctf_readme.write("\n")
    return readme_path


def write_submitter(helper_folder, chall_data):
    submitter = os.path.join(helper_folder, 'submit.py')
    with open('submit.py', encoding="utf-8") as f:
        data = f.read()
    data = data.replace('<config-dir>', os.getcwd()).replace('<chall_id>', str(chall_data['id']))
    with open(submitter, 'w', encoding="utf-8") as f:
        f.write(data)


def write_solves(helper_folder, chall_data):
    submitter = os.path.join(helper_folder, 'solves.py')
    with open('solves.py', encoding="utf-8") as f:
        data = f.read()
    data = data.replace('<config-dir>', os.getcwd()).replace('<chall_id>', str(chall_data['id']))
    with open(submitter, 'w', encoding="utf-8") as f:
        f.write(data)


def write_instancer(helper_folder, chall_data):
    instancer = os.path.join(helper_folder, 'instance.py')
    with open('instance.py', encoding="utf-8") as f:
        data = f.read()
    data = data.replace('<config-dir>', os.getcwd()).replace('<instance-id>', str(chall_data['id']))
    with open(instancer, 'w', encoding="utf-8") as f:
        f.write(data)


def write_hints(helper_folder, chall_data):
    hints = os.path.join(helper_folder, 'hints.py')
    with open('hints.py', encoding="utf-8") as f:
        data = f.read()
    data = data.replace('<config-dir>', os.getcwd()).replace('<chall_id>', str(chall_data['id']))
    with open(hints, 'w', encoding="utf-8") as f:
        f.write(data)


def classify_by_categories(challenges_data):
    categories = {}
    
    for x in challenges_data:
        chall_category = x['category']

        if chall_category in categories.keys():
            categories[chall_category].append(x)
        else:
            categories[chall_category] = [x]

    return categories


# Main code starts here

# Argument Parsing
parser = argparse.ArgumentParser()
parser.add_argument("--list", help="List all challenges", action="store_true")
parser.add_argument("--download", type=int, metavar="<challenge-id>", help="Download a challenge by providing its ID.")

args = parser.parse_args()

# Setup up required headers for authentication
headers = {"Content-Type": "application/json"}
if token:
    headers["Authorization"] = f"Token {token}"
elif cookie:
    headers["Cookie"] = f"session={cookie}"
else:
    raise ValueError("You must provide either a token or a cookie in the config file.")

# Fetch challenges details
api_url = urljoin(base_url, '/api/v1')
session = requests.Session()
challenges = fetch_challenges(api_url, headers)
challenges_data = challenges['data']

# Handle authentication failure
if 'message' in challenges.keys() and challenges['message'].index('wrong credentials') > -1:
    print('Please provide correct token or session cookie in config file')
    exit(-1)

# Sort and classify by categories and points
challenges_data = sorted(challenges_data, key=lambda x: (x['category'], x['value']))
categories = classify_by_categories(challenges_data)

if args.list: # challenge list
    for category in categories.keys():
        print(f"{'='*5}{category}{'='*5}")
        for chall in categories[category]:
            path = os.path.join('.', chall['category'], slugify(chall['name']))
            print(f'{chall["id"]:<3} {chall["name"]:<50} {chall["value"]:<6} {path if os.path.exists(path) else None}')

if args.download: # challenge ID is supplied via download parameter
    file_size_limit = False  # No file size limit if user is downloading a specific challenge

    challenge_data = next((c for c in challenges_data if c['id'] == args.download), None)
    challenge = fetch_challenge_details(session, api_url, challenge_data['id'], headers)

    download_challenge(challenge)

if len(sys.argv) == 1: # If no arguments are supplied, download all the challenge files
    # Write CTF readme file
    write_ctf_readme(output_dir, ctf_name, categories)

    # Identify and remove already downloaded challenges
    challenges_data = remove_already_downloaded_challs(challenges_data)

    # Download all the challenges
    for chall in challenges_data:
        challenge = fetch_challenge_details(session, api_url, chall['id'], headers)
        download_challenge(challenge)

    if limit_failed:
        print("Following challenges were not downloaded due to file size limit")
        for name, size in limit_failed.items():
            print(f"{name}: {size:.3f} MB")

    logging.info("All done!")