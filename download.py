#!/usr/bin/python3

import requests
import json
import logging
import os
from urllib.parse import urljoin, urlparse
import re
import shutil
from tqdm import tqdm
from configparser import ConfigParser

logging.basicConfig()
logging.root.setLevel(logging.INFO)


def slugify(text):
    text = re.sub(r"[\s]+", "-", text.lower())
    text = re.sub(r"[-]{2,}", "-", text)
    text = re.sub(r"[^a-z0-9\-]", "", text)
    text = re.sub(r"^-|-$", "", text)
    return text


def initialize_directories(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    for d in ["challenges", "images"]:
        os.makedirs(os.path.join(output_dir, d), exist_ok=True)


def fetch_challenges(api_url, headers):
    logging.info(f"Connecting to API: {api_url}")
    response = requests.get(f"{api_url}/challenges", headers=headers)
    return json.loads(response.text)


def fetch_challenge_details(session, api_url, challenge_id, headers):
    response = session.get(f"{api_url}/challenges/{challenge_id}", headers=headers)
    return json.loads(response.text)["data"]

def requires_instance(challenge):
    if challenge['type'] == 'dynamic_docker':
        return True
    else:
        return False

def write_challenge_readme(challenge_dir, challenge):
    readme_path = os.path.join(challenge_dir, "README.md")
    logging.info(f"Creating challenge readme: {challenge['name']}")
    with open(readme_path, "w") as chall_readme:
        chall_readme.write(f"# {challenge['name']}\n\n")
        chall_readme.write(f"## Challenge ID\n\n{challenge['id']}\n\n")
        chall_readme.write(f"## Description\n\n{challenge['description']}\n\n")
        chall_readme.write(f"## Points\n\n{challenge.get('value', 'N/A')}\n\n")
        
        chall_readme.write(f"## Requires Instance\n\n{'Yes' if requires_instance(challenge) else 'No'}\n\n")
        
        # Add files
        if challenge.get("files"):
            chall_readme.write("## Files\n\n")
            for file in challenge["files"]:
                file_name = urlparse(file).path.split("/")[-1]
                chall_readme.write(f"- {file_name}\n")
    return readme_path



def download_file(session, url, output_path, desc):
    response = session.get(url, stream=True)
    total_size_in_bytes = int(response.headers.get('content-length', 0))
    progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True, desc=desc)

    with open(output_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                progress_bar.update(len(chunk))
                f.write(chunk)
    progress_bar.close()


def handle_challenge_files(session, challenge, challenge_dir, base_url):
    challenge_files = challenge.get("files", [])
    if challenge_files: # if challenge has files, only then create the files directory and put all the files there
        files_dir = os.path.join(challenge_dir, "files")
        os.makedirs(files_dir, exist_ok=True)

        for file in challenge.get("files", []):
            file_url = urljoin(base_url, file)
            file_name = urlparse(file_url).path.split("/")[-1]
            local_path = os.path.join(files_dir, file_name)
            download_file(session, file_url, local_path, file_name)


def write_ctf_readme(output_dir, ctf_name, categories):
    readme_path = os.path.join(output_dir, "README.md")
    logging.info("Writing main CTF readme...")
    with open(readme_path, "w") as ctf_readme:
        ctf_readme.write(f"# {ctf_name}\n\n")
        ctf_readme.write("## About\n\n[insert description here]\n\n")
        ctf_readme.write("## Challenges\n\n")
        
        first_category = True
        for category, challenges in categories.items():
            if not first_category:
                ctf_readme.write("\n")  # Add a space before new category
            first_category = False
            ctf_readme.write(f"### {category}\n\n")
            for chall in challenges:
                chall_path = f"challenges/{chall['category']}/{slugify(chall['name'])}/"
                ctf_readme.write(f"* [{chall['name']}](<{chall_path}>)\n")
    return readme_path

def write_submitter(challenge_dir, chall_data):
    submitter = os.path.join(challenge_dir, 'submit.py')
    with open('submit.py') as f:
        data = f.read()
    data = data.replace('<config-dir>', os.getcwd()).replace('<chall_id>', str(chall_data['id']))
    with open(submitter, 'w') as f:
        f.write(data)


def load_config():
    config = ConfigParser()
    config.read("config.ini")
    if not config.has_section("CTF"):
        raise ValueError("The config file is missing the 'CTF' section.")
    return config["CTF"]



def main():
    ctf_config = load_config()

    base_url = ctf_config.get("url", "").strip()
    ctf_name = ctf_config.get("name", "").strip()
    output_dir = ctf_config.get("output", "").strip()
    token = ctf_config.get("token", "").strip()
    cookie = ctf_config.get("cookie", "").strip()

    if not base_url or not ctf_name or not output_dir:
        raise ValueError("Missing required configuration: url, name, or output.")

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Token {token}"
    elif cookie:
        headers["Cookie"] = f"session={cookie}"
    else:
        raise ValueError("You must provide either a token or a cookie in the config file.")

    initialize_directories(output_dir)
    api_url = urljoin(base_url, '/api/v1')
    session = requests.Session()
    challenges_data = fetch_challenges(api_url, headers)

    categories = {}
    if 'message' in challenges_data.keys() and challenges_data['message'].index('wrong credentials') > -1:
        print('Please provide correct token or session cookie in config file')
        exit(-1)
    for chall in challenges_data['data']:
        challenge = fetch_challenge_details(session, api_url, chall['id'], headers)
        category = challenge["category"]
        categories.setdefault(category, []).append(challenge)

        challenge_dir = os.path.join(output_dir, "challenges", category, slugify(challenge["name"]))
        if os.path.exists(challenge_dir):
            print(f"Challenge already downloaded : {challenge['name']}")
            continue
        os.makedirs(challenge_dir, exist_ok=True)

        write_challenge_readme(challenge_dir, challenge)
        handle_challenge_files(session, challenge, challenge_dir, base_url)
        write_submitter(challenge_dir, chall)
        if requires_instance(challenge):
            shutil.copy('instance.py', challenge_dir)

    try:
        os.rmdir('images')
    except:
        pass # directory not removed as it has files in it.

    write_ctf_readme(os.path.join(output_dir, 'challenges'), ctf_name, categories)
    logging.info("All done!")


if __name__ == "__main__":
    main()