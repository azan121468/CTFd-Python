# CTF Automation Scripts

This repository contains various scripts to help automate tasks for managing and participating in Capture The Flag (CTF) competitions. Below is a detailed guide for each script and its usage.

## Files to Run from the Main Folder

### blood_announcer.py
**Usage:**
```bash
./blood_announcer.py        # Get blood status of all challenges
```
- Retrieves the blood status of all challenges.
- If a challenge is blooded, it reports the user and team who solved it.
- If a challenge is not blooded, it reports that the challenge is not blooded.

### cleanup.sh
**Function:**
Removes all the downloaded CTF data.
**Usage:**
```bash
./cleanup.sh
```

### config.ini
- Contains:
  - CTF Name
  - CTF Directory
  - CTF Token/Session-Cookie
  - File size limit
- Automation scripts will pick configuration details from this file.

### download.py
**Usage:**
```bash
./download.py                                # Download all the challenges from the remote server
./download.py --list                         # List all the active challenges
./download.py --download <challenge-id>      # Download specific challenge
```

- List all challenges
- Download specific challenges
    - File size limit doesn't apply while downloading a specific challenge
- Downloads all the challenges from the server.
- On new challenge releases, rerun the script to fetch only the new challenges.

### main_scoreboard.py
**Usage:**
```bash
./main_scoreboard.py            # Get full scoreboard
./main_scoreboard.py <limit>    # Get scoreboard with provided limits
```
- Displays the current scoreboard situation with team names and points.
- The `<limit>` parameter specifies the number of teams:
  - Positive numbers show the top teams (e.g., `3` for top 3).
  - Negative numbers show the bottom teams (e.g., `-3` for last 3).

**Examples:**
```bash
./main_scoreboard.py 3    # Shows the top 3 teams
./main_scoreboard.py -3   # Shows the last 3 teams
```

### team_solves.py
**Usage:**
```bash
./team_solves.py <team-name>   # Get solves of a specific team
```
- Displays all solves of the specified team, including:
  - Member name
  - Challenge name
  - Challenge category

## Files to Run from the Challenge Folder

### hints.py
**Usage:**
```bash
./hints.py            # Get hints of the challenge
```
- Retrieves and displays all released hints for the current challenge.

### instance.py
**Usage:**
```bash
./instance.py         # Get instance details
./instance.py KILL    # Kill running instance
```
- Starts the remote container for challenges requiring remote instances.
- Provides container info (IP, Port, or URL for web challenges).
- Stops the remote container.
Note: There is a limit on the number of containers you can spawn.

### solves.py
**Usage:**
```bash
./solves.py           # Get all solves of current challenge
```
- Retrieves all solves for the current challenge.

### fix_path.py
**Usage:**
```bash
./fix_path.py         # Fix config path in all helpers files when transfered in different folder/OS
```
- Change the hardcoded path in all helpers script according to the OS on which the script is running.
- This allows to switch between operating systems or directory without affecting the helper scripts.

# Credits
Credits go to https://github.com/jselliott/ctfd_download_python/blob/main/download.py.
I use this script as a baseline along with manual investigation of API calls from a CTF instance.
