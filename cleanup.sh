#!/bin/bash

echo "Are you sure you want to delete 'images', 'challenges', and 'README.md'? (y/n)"
read -r confirmation

if [[ "$confirmation" == "y" || "$confirmation" == "Y" ]]; then
    rm -rf images challenges README.md
    echo "Files and directories deleted."
else
    echo "Deletion canceled."
fi
