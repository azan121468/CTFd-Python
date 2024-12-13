files to be run from main folder:
	blood_announcer.py:
	usage: ./blood_announcer.py 
	this script will get blood status of all challenges. If challenge is blooded it will report which user from which team solves the challenge. If challenge is not blooded it will report chall is not blooded

	cleanup.sh:
	remove all the downloaded ctf data.
	
	config.ini:
	put CTF token and file size limit in this file. automation will pick variable from this file.

	download.py:
	usage: ./download.py
	download all the challenge from the server.
	When new challenges release, rerun. it will only fetch the new challenge
	
	main_scoreboard.py:
	usage: ./main_scoreboard.py <limit>
	get current scoreboard situation. will display team name and points.
	limit is used to get top and bottom team.
	for example:
	./main_scoreboard.py 3
	this will show top three teams.
	./main_scoreboard.py -3
	this will show last three team.
	
	team_solves.py
	usage: ./team_solves.py <team-name>
	This will get all solves of the target team with member name, challenge name and category.
	
file to be run from challenge folder:
	hints.py
	usage: ./hints.py
	this will get and display all the released hints of the current challenge
	
	instance.py
	usage: ./instance.py
	this file is only present in the challenges which required remote instance.
	this script is use to start the remote container of the challenge and gives its info(IP and Port, [URL for web challs]).
	use "./instance.py kill" to stop the container as there is a max containers spawn limit after which you will not be able to spawn the container.
	
	solves.py
	usage: ./solves.py
	get all solves of current challenge in json format. pipe to jq and parse manually.