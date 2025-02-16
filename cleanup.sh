#!/bin/bash

echo "Are you sure you want to delete all challenges data? (y/n)"
read -r confirmation

if [[ "$confirmation" == "y" || "$confirmation" == "Y" ]]; then
    dirs=$(find . -maxdepth 1 -mindepth 1 -type d)
    for i in $dirs; do 
        echo "Deleting "$i
        rm -rf $i
    done
    if [ -f "README.md" ]; then
        echo "Deleting README.md"
        rm README.md
    fi
else
    echo "Deletion canceled."
fi
