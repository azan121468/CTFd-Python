# CTF Automation Scripts

This repository contains various scripts to help automate tasks for managing and participating in Capture The Flag (CTF) competitions. Below is a detailed guide for each script and its usage.

## Files to Run from the Main Folder

### blood_announcer.py
**Usage:**
```bash
./blood_announcer.py
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
  - CTF token
  - File size limit
- Automation scripts will pick variables from this file.

### download.py
**Usage:**
```bash
./download.py
```
- Downloads all the challenges from the server.
- On new challenge releases, rerun the script to fetch only the new challenges.

### main_scoreboard.py
**Usage:**
```bash
./main_scoreboard.py <limit>
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
./team_solves.py <team-name>
```
- Displays all solves of the specified team, including:
  - Member name
  - Challenge name
  - Challenge category

## Files to Run from the Challenge Folder

### hints.py
**Usage:**
```bash
./hints.py
```
- Retrieves and displays all released hints for the current challenge.

### instance.py
**Usage:**
```bash
./instance.py
```
- Starts the remote container for challenges requiring remote instances.
- Provides container info (IP, Port, or URL for web challenges).
- Use the following command to stop the container:
  ```bash
  ./instance.py kill
  ```
- Note: There is a limit on the number of containers you can spawn.

### solves.py
**Usage:**
```bash
./solves.py
```
- Retrieves all solves for the current challenge.

# Credits
Credits go to https://github.com/jselliott/ctfd_download_python/blob/main/download.py.
I use this script as a baseline along with manual investigation of API calls from a CTF instance.
